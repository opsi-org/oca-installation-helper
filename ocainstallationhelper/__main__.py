# -*- coding: utf-8 -*-

# opsiclientd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2010-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsi-client-agent installation_helper
"""

import argparse
import ctypes
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import IO

from opsicommon.exceptions import BackendAuthenticationError
from opsicommon.logging import logging_config, NAME_TO_LEVEL, LEVEL_TO_OPSI_LEVEL
from opsicommon.system.subprocess import patch_popen

from ocainstallationhelper import (
	__version__,
	decode_password,
	encode_password,
	get_installed_oca_version,
	get_this_oca_version,
	logger,
	show_message,
	CONFIG_CACHE_DIRS,
)
from ocainstallationhelper.backend import Backend, InstallationUnsuccessful
from ocainstallationhelper.config import Config, SETUP_SCRIPT_NAME
from ocainstallationhelper import Dialog

patch_popen()


class InstallationHelper:
	def __init__(self, cmdline_args: argparse.Namespace, full_path: Path | None = None) -> None:
		# macos does not use DISPLAY. gui does not work properly on macos right now.
		self.dialog: Dialog | None = None
		self.clear_message_timer: threading.Timer | None = None
		self.backend: Backend | None = None

		self.full_path: Path
		if full_path is None:
			self.full_path = Path(sys.argv[0])
		else:
			self.full_path = full_path
		self.should_stop: bool = False
		self.opsi_script_logfile: Path | None = None
		self.tmp_dir: Path = Path(tempfile.gettempdir()) / "oca-installation-helper-tmp"
		if not self.full_path.is_absolute():
			self.full_path = (Path() / self.full_path).absolute()
		logger.info(
			"Installation helper running from '%s', working dir '%s'",
			self.full_path,
			Path().absolute(),
		)
		self.config = Config(cmdline_args, self.full_path)

	def configure_from_reg_file(self) -> None:
		if platform.system().lower() == "windows":
			logger.info("Filling empty config fields from windows registry.")
			self.config.fill_config_from_registry(parse_args)

		logger.info("Filling empty config fields from config files.")
		self.config.fill_config_from_files()

	def configure_from_zeroconf_default(self) -> None:
		logger.info("Filling empty config fields from zeroconf information.")
		if not self.config.service_address:
			self.show_message("Searching for opsi config services", display_seconds=5)
			self.config.fill_config_from_zeroconf()
			for _sec in range(5):
				if self.config.service_address:
					break
				time.sleep(1)
			self.show_message(
				f"opsi config services found: {len(self.config.zeroconf_addresses)}",
				display_seconds=3,
			)
		if self.dialog:
			self.dialog.update()
		logger.info("Filling empty config fields from default.")
		self.config.fill_config_from_default()
		logger.info(
			"Got config: service_address='%s', service_username='%s', client_id='%s'",
			self.config.service_address,
			self.config.service_username,
			self.config.client_id,
		)
		if self.dialog:
			self.dialog.update()

	def copy_installation_files(self) -> None:
		self.cleanup()
		self.show_message(f"Copy installation files from '{self.config.base_dir}' to '{self.tmp_dir}'")
		shutil.copytree(str(self.config.base_dir), str(self.tmp_dir))
		self.show_message(f"Installation files succesfully copied to '{self.tmp_dir}'", "success")
		self.config.base_dir = self.tmp_dir
		self.config.setup_script = self.config.base_dir / SETUP_SCRIPT_NAME

	def run_setup_script(self) -> None:
		if not (self.config.service_address and self.config.client_id and self.config.client_key and self.config.finalize and self.backend):
			raise ValueError("Incomplete data - cannot run setup_script.")
		self.show_message("Running setup script")

		if platform.system().lower() == "windows":
			oca_package = "opsi-client-agent"
			opsi_script = self.config.base_dir / "files" / "opsi-script" / "opsi-script.exe"
			log_dir = Path(r"c:\opsi.org\log")
			param_char = "/"
		elif platform.system().lower() == "linux":
			oca_package = "opsi-linux-client-agent"
			opsi_script = self.config.base_dir / "files" / "opsi-script" / "opsi-script"
			log_dir = Path("/var/log/opsi-script")
			param_char = "-"
		elif platform.system().lower() == "darwin":
			opsi_script = self.config.base_dir / "files" / "opsi-script.app" / "Contents" / "MacOS" / "opsi-script"
			oca_package = "opsi-mac-client-agent"
			log_dir = Path("/var/log/opsi-script")
			param_char = "-"
		else:
			raise NotImplementedError(f"Not implemented for {platform.system()}")

		if not log_dir.exists():
			try:
				log_dir.mkdir(parents=True)
			except Exception as exc:
				logger.error(
					"Could not create log directory %s due to %s\n still trying to continue",
					log_dir,
					exc,
					exc_info=True,
				)
		self.opsi_script_logfile = log_dir / "opsi-client-agent.log"
		arg_list = [
			str(self.config.setup_script),
			str(self.opsi_script_logfile),
			f"{param_char}servicebatch",
			f"{param_char}productid",
			oca_package,
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
			try:
				output = subprocess.check_output(["powershell", "-command", "$PSVersionTable"])
				logger.debug("Found powershell with following version information:\n%s", output)
			except subprocess.CalledProcessError as error:
				logger.error("Cannot execute powershell. Maybe missing in system PATH? Error: %s", error)
				raise error
			arg_string = ",".join([f"'\"{arg}\"'" for arg in arg_list])  # Enclosing by ' and " to be robust against spaces in params
			ps_script = f'Start-Process -Verb runas -FilePath "{opsi_script}" -ArgumentList {arg_string} -Wait'
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
			command = [str(opsi_script)] + arg_list

		self.backend.set_poc_to_installing(oca_package, self.config.client_id)
		logger.info("Executing: %s\n", command)
		with subprocess.Popen(
			command,
			stderr=subprocess.STDOUT,
			stdout=subprocess.PIPE,
			stdin=subprocess.PIPE,
		) as proc:
			out = proc.communicate()[0]
			logger.info("Command exit code: %s", proc.returncode)
			logger.info("Command output: %s", out)

	def install(self) -> bool:
		try:
			logger.info("Starting installation")
			if not self.config.client_id:
				raise ValueError("Client id undefined.")
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
				self.show_message(f"Skipping installation as condition {self.config.install_condition} is not met.")
				return False
			self.config.check_values()
			self.cleanup_cache()
			self.service_setup()
			if not self.backend:
				raise ValueError("Backend is not initialized.")

			self.run_setup_script()
			self.show_message("Evaluating script result")
			self.backend.evaluate_success(self.config.client_id)
			return True
		except Exception as err:
			logger.error(err, exc_info=True)
			raise

	def service_setup(self) -> None:
		if not self.config.client_id:
			raise ValueError("Client id undefined.")

		if self.dialog:
			self.dialog.set_button_enabled("install", False)

		self.show_message("Connecting to service...")

		password = self.config.service_password or ""
		if password.startswith("{crypt}"):
			password = decode_password(password)

		if self.config.service_address is None or self.config.service_username is None or password is None:
			raise ValueError("Incomplete data - cannot run service_setup.")
		self.backend = Backend(self.config.service_address, self.config.service_username, password)

		self.show_message("Connected", "success")
		if "." not in self.config.client_id:
			self.config.client_id = f"{self.config.client_id}.{self.backend.get_domain()}"
			if self.dialog:
				self.dialog.update()

		client = self.backend.get_or_create_client(
			self.config.client_id,
			force_create=self.config.force_recreate_client,
			set_mac_address=self.config.set_mac_address,
		)
		self.config.client_key = client.opsiHostKey
		self.config.client_id = str(client.id)
		self.show_message("Client exists", "success")
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
			self.dialog.update()

	def show_message(self, message: str, severity: str | None = None, display_seconds: float = 0) -> None:
		if self.clear_message_timer:
			self.clear_message_timer.cancel()

		if message:
			log = logger.info
			exc_info = False
			if severity == "error":
				log = logger.error
				exc_info = True
			log(message, exc_info=exc_info)

		if self.dialog:
			self.dialog.show_message(message, severity)
			if display_seconds > 0:
				self.clear_message_timer = threading.Timer(display_seconds, self.show_message, args=[""])
				self.clear_message_timer.start()

	def show_logpath(self, logpath: Path | str | None) -> None:
		logger.info("See logs at: %s", logpath)
		if self.dialog:
			self.dialog.show_logpath(logpath)

	def on_cancel_button(self) -> None:
		self.show_message("Canceled")
		sys.exit(1)

	def on_install_button(self) -> None:
		if not self.dialog:
			raise ValueError("How did we end up here?")
		self.dialog.set_button_enabled("install", False)
		try:
			# install returns True if installation successfull, False if skipped and throws Exception on error
			if self.install():
				self.show_message("Installation completed (closing in 5 Seconds)", "success")
			if self.dialog:
				# if using a dialog, wait for 5 Seconds before closing
				for _num in range(5):
					time.sleep(1)
				self.dialog.close()
		except BackendAuthenticationError:
			self.show_message("Authentication error, wrong username or password", "error")
			self.show_logpath(self.config.log_file)
		except InstallationUnsuccessful as err:
			self.show_message(f"Installation Unsuccessful: {err}", "error")
			self.show_logpath(self.opsi_script_logfile or "Undefined logfile.")
		except Exception as err:
			self.show_message(str(err), "error")
			self.show_logpath(self.config.log_file)
		self.dialog.set_button_enabled("install", True)

	def on_zeroconf_button(self) -> None:
		if self.dialog:
			self.dialog.update()
		self.config.service_address = None
		self.show_message("Searching for opsi config services", display_seconds=5)
		self.config.fill_config_from_zeroconf()
		for _sec in range(5):
			if self.config.service_address:
				break
			time.sleep(1)
		self.show_message(
			f"opsi config services found: {len(self.config.zeroconf_addresses)}",
			display_seconds=3,
		)
		if self.dialog:
			self.dialog.update()

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
			if self.full_path.drive != Path(tempfile.gettempdir()).drive:
				self.copy_installation_files()
			if not self.config.base_dir:
				raise ValueError("Installation base directory not defined.")
			if ctypes.windll.shell32.IsUserAnAdmin() == 0:  # type: ignore
				# not elevated
				new_path = self.config.base_dir / "oca-installation-helper.exe"
				arg_string = "-ArgumentList " + ",".join([f'"{arg}"' for arg in sys.argv[1:]]) if sys.argv[1:] else ""
				ps_script = f'Start-Process -Verb runas -FilePath "{str(new_path)}" {arg_string} -Wait'
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

	def run(self) -> None:
		error = None
		try:
			self.ensure_admin()
			self.configure_from_reg_file()
			if self.config.interactive:
				if self.config.use_gui:
					if platform.system().lower() == "darwin":
						logger.error("Console dialog currently not implemented on macos. Use --no-gui instead.")
					else:
						try:
							from ocainstallationhelper.gui import GUIDialog  # only import if needed
						except ImportError as err:
							logger.error(err)
							raise RuntimeError(
								"Cannot import GUIDialog. Use --no-gui instead or install required libraries (like libxcb))"
							) from err
						self.dialog = GUIDialog(self)  # type: ignore[assignment]
						assert self.dialog
						self.dialog.show()
				else:
					if platform.system().lower() == "windows":
						logger.error("Console dialog currently not implemented on windows. Use --gui instead")
					else:
						from ocainstallationhelper.console import ConsoleDialog  # only import if needed

						self.dialog = ConsoleDialog(self)
						self.dialog.show()
			self.configure_from_zeroconf_default()
			if self.dialog:
				self.dialog.update()

			if self.config.interactive and self.dialog:
				self.dialog.wait()
			else:
				self.install()

		except Exception as err:
			logger.error(err, exc_info=True)
			error = err
			self.show_message(str(err), "error")
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


def parse_args(args: list[str] | None = None):
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
		default="warning",
		choices=["none", "debug", "info", "warning", "error", "critical"],
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

	return parser.parse_args(args)


def main() -> None:
	args = parse_args()
	if args.encode_password:
		show_message("{crypt}" + encode_password(args.encode_password))
		return

	log_level = args.log_level.upper()
	if log_level != "NONE":
		log_file = Path(args.log_file)
		if log_file.exists():
			log_file.unlink()
		logging_config(
			file_level=LEVEL_TO_OPSI_LEVEL[NAME_TO_LEVEL[log_level]],
			file_format="[%(levelname)-9s %(asctime)s] %(message)s   (%(filename)s:%(lineno)d)",
			log_file=str(log_file),
		)

	InstallationHelper(args).run()
