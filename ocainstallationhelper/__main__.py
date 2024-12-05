# -*- coding: utf-8 -*-

# opsiclientd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2010-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsi-client-agent installation_helper
"""

import argparse
import asyncio
import ctypes
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import IO

from opsicommon.exceptions import BackendAuthenticationError
from opsicommon.logging import LEVEL_TO_OPSI_LEVEL, NAME_TO_LEVEL, logging_config
from opsicommon.system.subprocess import patch_popen

from ocainstallationhelper import CONFIG_CACHE_DIRS, Dialog, __version__, logger
from ocainstallationhelper.backend import Backend, InstallationUnsuccessful
from ocainstallationhelper.config import SETUP_SCRIPT_NAME, Config
from ocainstallationhelper.utils import (
	decode_password,
	encode_password,
	get_installed_oca_version,
	get_this_oca_version,
	make_executable,
	show_message,
)

patch_popen()


class InstallationHelper:
	def __init__(self, cmdline_args: argparse.Namespace) -> None:
		# macos does not use DISPLAY. gui does not work properly on macos right now.
		self.dialog: Dialog | None = None
		self.backend: Backend | None = None
		self.should_stop: bool = False
		self.opsi_script_logfile: Path | None = None
		self.tmp_dir: Path = Path(tempfile.gettempdir()) / "oca-installation-helper-tmp"
		self.config = Config(cmdline_args)
		self.base_dir: Path

	async def configure_from_zeroconf_default(self) -> None:
		logger.info("Filling empty config fields from zeroconf information.")
		if not self.config.service_address:
			await self.show_message("Searching for opsi config services")
			self.config.fill_config_from_zeroconf()
			for _sec in range(5):
				if self.config.service_address:
					break
				await asyncio.sleep(1)
			await self.show_message(f"opsi config services found: {len(self.config.zeroconf_addresses)}")
		if self.dialog:
			await self.dialog.update_values()
		logger.info("Filling empty config fields from default.")
		self.config.fill_config_from_default()
		logger.info(
			"Got config: service_address='%s', service_username='%s', client_id='%s'",
			self.config.service_address,
			self.config.service_username,
			self.config.client_id,
		)
		if self.dialog:
			await self.dialog.update_values()

	async def copy_installation_files(self) -> Path:
		if not self.backend:
			raise ValueError("No backend connection.")
		self.cleanup()
		await self.show_message(f"Copying installation files from depot to '{self.tmp_dir}'")
		self.tmp_dir.mkdir(parents=True, exist_ok=True)
		self.backend.get_from_depot(self.config.oca_package, self.tmp_dir)
		self.backend.get_from_depot("opsi-script", self.tmp_dir)
		await self.show_message(f"Installation files succesfully copied to '{self.tmp_dir}'", "success")
		self.config.opsi_script = self.tmp_dir / "opsi-script" / self.config.opsi_script_path
		try:
			shutil.copytree(self.tmp_dir / "opsi-script" / "common" / "skin", self.config.opsi_script.parent)
		except Exception:
			logger.warning("Failed to copy opsi-script skin files")
		make_executable(self.config.opsi_script)
		return self.tmp_dir / self.config.oca_package

	async def run_setup_script(self) -> None:
		if not self.backend:
			raise ValueError("No backend connection.")
		if not self.base_dir:
			raise ValueError("No base directory set.")
		assert self.config.service_address and self.config.client_id and self.config.client_key and self.config.finalize  # for mypy
		await self.show_message("Running setup script")

		opsi_script_log_dir = Path(r"c:\opsi.org\log") if platform.system().lower() == "windows" else Path("/var/log/opsi-script")
		if not opsi_script_log_dir.exists():
			try:
				opsi_script_log_dir.mkdir(parents=True)
			except Exception as exc:
				logger.error(
					"Could not create log directory %s due to %s\n still trying to continue",
					opsi_script_log_dir,
					exc,
					exc_info=True,
				)
		self.opsi_script_logfile = opsi_script_log_dir / "opsi-client-agent.log"
		param_char = "/" if platform.system().lower() == "windows" else "-"
		arg_list: list[str] = [
			str(self.base_dir / SETUP_SCRIPT_NAME),
			str(self.opsi_script_logfile),
			f"{param_char}servicebatch",
			f"{param_char}productid",
			self.config.oca_package,
			f"{param_char}opsiservice",
			self.config.service_address,
			f"{param_char}clientid",
			self.config.client_id,
			f"{param_char}username",
			self.config.client_id,
			f"{param_char}password",
			self.config.client_key,
			f"{param_char}parameter",
			self.config.finalize,
		]
		if platform.system().lower() == "windows":
			proc = await asyncio.create_subprocess_exec(
				"powershell", "-command", "$PSVersionTable", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
			)
			stdout, _ = await proc.communicate()
			if proc.returncode != 0:
				logger.error("Cannot execute powershell. Maybe missing in system PATH? Returncode: %s", proc.returncode)
				raise RuntimeError(f"Cannot execute powershell. Maybe missing in system PATH? Returncode: {proc.returncode}")
			logger.debug("Found powershell with following version information:\n%s", stdout)

			arg_string = ",".join([f"'\"{arg}\"'" for arg in arg_list])  # Enclosing by ' and " to be robust against spaces in params
			ps_script = f'Start-Process -Verb runas -FilePath "{self.config.opsi_script}" -ArgumentList {arg_string} -Wait'
			command = [
				"powershell",
				"-ExecutionPolicy",
				"bypass",
				"-WindowStyle",
				"hidden",
				"-command",
				ps_script,
			]
		else:
			command = [str(self.config.opsi_script)] + arg_list

		self.backend.set_poc_to_installing(self.config.oca_package, self.config.client_id)
		logger.info("Executing: %s\n", command)
		proc = await asyncio.create_subprocess_exec(
			*command,
			stderr=asyncio.subprocess.STDOUT,
			stdout=asyncio.subprocess.PIPE,
			stdin=asyncio.subprocess.PIPE,
		)
		out, _ = await proc.communicate()
		logger.info("Command exit code: %s", proc.returncode)
		logger.info("Command output: %s", out)

	async def install(self) -> bool:
		await self.show_message("Connecting to service...")
		password = self.config.service_password or ""
		if password.startswith("{crypt}"):
			password = decode_password(password)
		if self.config.service_address is None or self.config.service_username is None or password is None:
			raise ValueError("Incomplete data - cannot run service_setup.")
		self.backend = Backend(self.config.service_address, self.config.service_username, password)
		if not self.backend:
			raise ValueError("No backend connection.")
		await self.show_message("Connected", "success")
		if self.config.client_id and "." not in self.config.client_id:
			self.config.client_id = f"{self.config.client_id}.{self.backend.get_domain()}"
		self.base_dir = await self.copy_installation_files()
		self.config.fill_config_from_files(self.base_dir)  # using copy destination as base dir
		if self.dialog:
			await self.dialog.update_values()
		try:
			assert self.config.client_id  # for mypy
			logger.info("Starting installation")
			installed_oca_version = get_installed_oca_version()
			this_oca_version = get_this_oca_version()
			logger.debug(
				"opsi-client-agent versions: installed=%s, this=%s",
				installed_oca_version,
				this_oca_version,
			)
			if (self.config.install_condition == "notinstalled" and installed_oca_version) or (
				self.config.install_condition == "outdated" and installed_oca_version == this_oca_version
			):
				await self.show_message(f"Skipping installation as condition {self.config.install_condition} is not met.")
				return False
			self.cleanup_cache()
			await self.service_setup()
			self.config.check_values()
			await self.run_setup_script()
			await self.show_message("Evaluating script result")
			self.backend.evaluate_success(self.config.client_id)
			return True
		except Exception as err:
			logger.error(err, exc_info=True)
			raise

	async def service_setup(self) -> None:
		if not self.backend:
			raise ValueError("No backend connection.")

		assert self.config.client_id  # for mypy

		if self.dialog:
			await self.dialog.set_button_enabled("install", False)

		await self.show_message("Obtaining Client object")
		client = self.backend.get_or_create_client(
			self.config.client_id,
			force_create=self.config.force_recreate_client,
			set_mac_address=self.config.set_mac_address,
		)
		self.config.client_key = client["opsiHostKey"]
		self.config.client_id = str(client["id"])
		await self.show_message("Client exists", "success")

		if self.config.setup_after_install:
			self.backend.set_product_property(
				client_id=self.config.client_id, property_id="setup_after_install", value=self.config.setup_after_install
			)

		if self.config.depot:
			if self.config.client_id == self.config.service_username:
				raise PermissionError(
					"Authorization error: Need opsi admin privileges to assign to depot",
					"error",
				)
			self.backend.assign_client_to_depot(self.config.client_id, self.config.depot)

		if self.config.group:
			if self.config.client_id == self.config.service_username:
				raise PermissionError(
					"Authorization error: Need opsi admin privileges to add to hostgroup",
					"error",
				)
			self.backend.put_client_into_group(self.config.client_id, self.config.group)

		if self.dialog:
			await self.dialog.update_values()

	async def show_message(self, message: str, severity: str | None = None) -> None:
		if message:
			log = logger.info
			exc_info = False
			if severity == "error":
				log = logger.error
				exc_info = True
			log(message, exc_info=exc_info)

		if self.dialog:
			await self.dialog.show_message(message, severity)

	async def show_logpath(self, logpath: Path | str | None) -> None:
		logger.info("See logs at: %s", logpath)
		if self.dialog:
			await self.dialog.show_logpath(logpath)

	async def on_cancel_button(self) -> None:
		await self.show_message("Canceled")
		sys.exit(1)

	async def on_install_button(self) -> None:
		if not self.dialog:
			raise ValueError("How did we end up here?")
		await self.dialog.set_button_enabled("install", False)
		try:
			# install returns True if installation successfull, False if skipped and throws Exception on error
			if await self.install():
				await self.show_message("Installation completed (closing in 5 Seconds)", "success")
			if self.dialog:
				# if using a dialog, wait for 5 Seconds before closing
				for _num in range(5):
					await asyncio.sleep(1)
				self.dialog.close()
		except BackendAuthenticationError:
			await self.show_message("Authentication error, wrong username or password", "error")
			await self.show_logpath(self.config.log_file)
		except InstallationUnsuccessful as err:
			await self.show_message(f"Installation Unsuccessful: {err}", "error")
			await self.show_logpath(self.opsi_script_logfile or "Undefined logfile.")
		except Exception as err:
			await self.show_message(str(err), "error")
			await self.show_logpath(self.config.log_file)
		await self.dialog.set_button_enabled("install", True)

	async def on_zeroconf_button(self) -> None:
		self.config.service_address = None
		if self.dialog:
			await self.dialog.update_values()
		await self.show_message("Searching for opsi config services")
		self.config.fill_config_from_zeroconf()
		for _sec in range(5):
			if self.config.service_address:
				break
			await asyncio.sleep(1)
		await self.show_message(f"opsi config services found: {len(self.config.zeroconf_addresses)}")
		if self.dialog:
			await self.dialog.update_values()

	def cleanup(self) -> None:
		if self.tmp_dir.is_dir():
			logger.debug("Delete temp dir '%s'", self.tmp_dir)
			shutil.rmtree(str(self.tmp_dir))

	def ensure_admin(self) -> None:
		if platform.system().lower() != "windows":
			if os.geteuid() != 0:
				# not root
				if self.config.use_gui and platform.system().lower() == "linux":
					try:
						subprocess.call(["xhost", "+si:localuser:root"])
					except subprocess.SubprocessError as err:
						logger.error(err)
				print(f"{Path(sys.argv[0]).name} has to be run as root")
				os.execvp("sudo", ["sudo"] + sys.argv)
		else:
			if ctypes.windll.shell32.IsUserAnAdmin() == 0:  # type: ignore
				# not elevated
				arg_string = "-ArgumentList " + ",".join([f'"{arg}"' for arg in sys.argv[1:]]) if sys.argv[1:] else ""
				ps_script = f'Start-Process -Verb runas -FilePath "{sys.argv[0]}" {arg_string} -Wait'
				command = [
					"powershell",
					"-ExecutionPolicy",
					"bypass",
					"-WindowStyle",
					"hidden",
					"-command",
					ps_script,
				]
				logger.info(
					"Not running elevated. Rerunning oca-installation-helper as admin: %s\n",
					command,
				)
				os.execvp("powershell", command)
			logger.info("Running elevated. Continuing execution.")

	def cleanup_cache(self) -> None:
		cache_dir = CONFIG_CACHE_DIRS.get(platform.system().lower())
		try:
			if cache_dir and cache_dir.exists():
				logger.info("Deleting opsiclientd WAN cache.")
				shutil.rmtree(cache_dir)
		except Exception as error:
			logger.warning("Failed to clean up cache: %s", error)

	async def prepare_installation(self) -> None:
		await self.show_message("Loading data...")
		if platform.system().lower() == "windows":
			logger.info("Filling empty config fields from windows registry.")
			self.config.fill_config_from_registry(parse_args)

		logger.info("Filling empty config fields from config files.")
		self.config.fill_config_from_files(base_dir=Path(sys.argv[0]).parent)  # using cwd as base dir
		await self.configure_from_zeroconf_default()
		if self.dialog:
			await self.dialog.update_values()
		await self.show_message("Finished loading data")

	def run(self) -> None:
		error = None
		try:
			# self.ensure_admin()
			if self.config.interactive:
				if self.config.use_gui:
					from ocainstallationhelper.gui import GUIDialog

					self.dialog = GUIDialog(self)  # has to call prepare_installation after gui setup!
				else:
					from ocainstallationhelper.console import ConsoleDialog  # only import if needed

					self.dialog = ConsoleDialog(self)  # has to call prepare_installation after gui setup!
				self.dialog.run_gui()
			else:
				asyncio.run(self.prepare_installation())
				asyncio.run(self.install())

		except Exception as err:
			logger.error(err, exc_info=True)
			error = err
			asyncio.run(self.show_message(str(err), "error"))
			if self.dialog:
				for _num in range(3):
					time.sleep(1)
		else:
			self.cleanup()
		if self.dialog:
			self.dialog.close()

		if self.config.end_command:
			try:
				subprocess.check_call(self.config.end_command, shell=True)
			except subprocess.CalledProcessError as err:
				logger.error(err)
				error = err

		if self.config.end_marker:
			with open(self.config.end_marker, "wb"):
				pass

		if error:
			print(f"ERROR: {error}", file=sys.stderr)
			sys.exit(1)


class ArgumentParser(argparse.ArgumentParser):
	def _print_message(self, message: str, file: IO[str] | None = None) -> None:
		show_message(message, message_type="stderr")


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
	if args is None:
		args = sys.argv[1:]  # executable path is not processed
	f_actions = ["noreboot", "reboot", "shutdown"]
	condition_choices = ["always", "notinstalled", "outdated"]
	parser = ArgumentParser()
	parser.add_argument("--version", action="version", version=__version__)
	parser.add_argument(
		"--log-file",
		default=str(Path(tempfile.gettempdir()) / "oca-installation-helper.log"),
	)
	parser.add_argument(
		"--log-level",
		"-l",
		default="warning",
		choices=[
			"0",
			"none",
			"1",
			"essential",
			"2",
			"critical",
			"3",
			"error",
			"4",
			"warning",
			"5",
			"notice",
			"6",
			"info",
			"7",
			"debug",
			"8",
			"trace",
			"9",
			"secret",
		],
	)
	parser.add_argument("--service-address", default=None, help="Service address to use.")
	parser.add_argument(
		"--service-username",
		default=None,
		help="Username to use for service connection.",
	)
	parser.add_argument(
		"--service-password",
		default=None,
		help="Password to use for service connection.",
	)
	parser.add_argument("--client-id", default=None, help="Client id to use.")
	parser.add_argument("--non-interactive", action="store_true", help="Do not ask questions.")
	parser.add_argument("--no-gui", action="store_true", help="Do not use gui.")
	parser.add_argument("--gui", action="store_true", help="Use gui.")
	parser.add_argument("--encode-password", action="store", metavar="PASSWORD", help="Encode PASSWORD.")
	parser.add_argument("--depot", help="Assign client to specified depot.", metavar="DEPOT")
	parser.add_argument("--group", help="Insert client into specified host group.", metavar="HOSTGROUP")
	parser.add_argument(
		"--force-recreate-client",
		action="store_true",
		help="Always call host_createOpsiClient, even if it exists.",
	)
	parser.add_argument(
		"--finalize",
		default="noreboot",
		choices=f_actions,
		help="Action to perform after successfull installation.",
	)
	parser.add_argument(
		"--dns-domain",
		default=None,
		help="DNS domain for assembling client id (ignored if client id is given).",
	)
	parser.add_argument(
		"--no-set-mac-address",
		action="store_true",
		help="Avoid retrieving and setting mac-address on client creation.",
	)
	parser.add_argument("--end-command", default=None, help="Run this command at the end.")
	parser.add_argument("--end-marker", default=None, help="Create this marker file at the end.")
	parser.add_argument(
		"--read-conf-files",
		nargs="*",
		metavar="FILE",
		default=("install.conf", "config.ini", "opsiclientd.conf"),
		help="config files to scan for informations (default: install.conf config.ini opsiclientd.conf)",
	)
	parser.add_argument(
		"--install-condition",
		default="always",
		choices=condition_choices,
		help="Under which condition should the client-agent be installed.",
	)
	parser.add_argument(
		"--setup-after-install",
		default=None,
		help="Comma separated list of products to set to setup after installation.",
	)

	return parser.parse_args(args)


def main() -> None:
	args = parse_args()
	if args.encode_password:
		show_message("{crypt}" + encode_password(args.encode_password))
		return

	try:
		log_level = int(args.log_level)
	except ValueError:
		log_level = LEVEL_TO_OPSI_LEVEL[NAME_TO_LEVEL[args.log_level.upper()]]

	if log_level != 0:
		log_file = Path(args.log_file)
		if log_file.exists():
			log_file.unlink()
		logging_config(
			stderr_level=log_level if args.non_interactive else 0,
			file_level=log_level,
			file_format="[%(levelname)-9s %(asctime)s] %(message)s   (%(filename)s:%(lineno)d)",
			log_file=str(log_file),
		)

	InstallationHelper(args).run()
