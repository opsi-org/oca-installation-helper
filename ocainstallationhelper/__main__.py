# This file is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2023-2026 uib GmbH <info@uib.de>
# This code is owned by the uib GmbH, Mainz, Germany (uib.de). All rights reserved.
# License: AGPL-3.0-only

"""
opsi-client-agent installation_helper
"""

import argparse
import asyncio
import os
import platform
import shutil
import sys
import tempfile
import time
import traceback
from pathlib import Path
from typing import IO, Literal

from opsi.archive import extract_archive
from opsi.exception import BackendAuthenticationError
from opsi.logging import LEVEL_TO_OPSI_LEVEL, NAME_TO_LEVEL, logging_config
from opsi.process import run_command, run_script

from ocainstallationhelper import CONFIG_CACHE_DIRS, Dialog, __version__, logger
from ocainstallationhelper.backend import Backend, InstallationUnsuccessful
from ocainstallationhelper.config import SETUP_SCRIPT_NAME, Config
from ocainstallationhelper.utils import decode_password, encode_password, get_installed_oca_version, make_executable, show_message

OCA_INSTALL_TIMEOUT = 60 * 20  # 20 minutes
INSTALLATION_SUCCESS_CLOSE_DELAY = 5


class InstallationHelper:
	def __init__(self, cmdline_args: argparse.Namespace) -> None:
		# macos does not use DISPLAY. gui does not work properly on macos right now.
		self.dialog: Dialog | None = None
		self.backend: Backend | None = None
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

	async def copy_installation_files(self, depot_id: str) -> Path:
		if not self.backend:
			raise ValueError("No backend connection.")
		if not self.config.client_id:
			raise ValueError("Insufficient data - no client_id set.")
		self.cleanup()
		self.tmp_dir.mkdir(parents=True, exist_ok=True)
		await self.show_message(f"Copying installation files to '{self.tmp_dir}'")
		depot_backend = self.backend
		if depot_id != self.backend.get_configserver_id():
			depot_backend = Backend(f"https://{depot_id}:4447", self.config.client_id, self.config.client_key)
			depot_backend.connect()
		if self.config.oca_package_source:
			self._copy_package_from_source(
				self.config.oca_package_source,
				self.config.oca_package,
				Path(SETUP_SCRIPT_NAME),
			)
		else:
			depot_backend.get_from_depot(self.config.oca_package, self.tmp_dir)
		if self.config.opsi_script_package_source:
			self._copy_package_from_source(
				self.config.opsi_script_package_source,
				"opsi-script",
				self.config.opsi_script_path,
			)
		else:
			depot_backend.get_from_depot("opsi-script", self.tmp_dir)

		await self.show_message(f"Installation files successfully copied to '{self.tmp_dir}'", "success")
		self.config.opsi_script = self.tmp_dir / "opsi-script" / self.config.opsi_script_path
		assert isinstance(self.config.opsi_script, Path)
		logger.debug(
			"Copying opsi-script additional files from %s to %s",
			self.tmp_dir / "opsi-script" / "common",
			self.config.opsi_script.parent,
		)
		shutil.copytree(self.tmp_dir / "opsi-script" / "common" / "skin", self.config.opsi_script.parent / "skin", dirs_exist_ok=True)
		shutil.copytree(self.tmp_dir / "opsi-script" / "common" / "lib", self.config.opsi_script.parent / "lib", dirs_exist_ok=True)
		make_executable(self.config.opsi_script)
		return self.tmp_dir / self.config.oca_package

	def _copy_package_from_source(self, source: Path, package_name: str, required_file: Path) -> None:
		destination = self.tmp_dir / package_name
		if source.is_dir():
			package_root = source / package_name if (source / package_name).is_dir() else source
			shutil.copytree(package_root, destination)
		else:
			extraction_dir = self.tmp_dir / f"{package_name}-source"
			extract_archive(source, extraction_dir)
			package_root = extraction_dir / package_name if (extraction_dir / package_name).is_dir() else extraction_dir
			if not (package_root / required_file).is_file():
				client_data_archives = sorted(
					(path for path in extraction_dir.rglob("CLIENT_DATA.*") if path.is_file()),
					key=lambda path: len(path.name.split(".")),
				)
				if client_data_archives:
					package_root = extraction_dir / "CLIENT_DATA"
					for client_data_archive in client_data_archives:
						extract_archive(client_data_archive, package_root)
			shutil.move(package_root, destination)

		if not (destination / required_file).is_file():
			raise ValueError(f"Package source '{source}' does not contain {required_file}.")

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
			except Exception as exc:  # noqa: BLE001
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
		if self.config.bootimage:
			arg_list += [f"{param_char}parameter", "bootimage"]

		self.backend.set_poc_to_installing(self.config.oca_package, self.config.client_id)
		if platform.system().lower() == "windows":
			arg_string = ",".join([f"'\"{arg}\"'" for arg in arg_list])  # Enclosing by ' and " to be robust against spaces in params
			await asyncio.get_event_loop().run_in_executor(
				None,
				lambda: run_script(
					f'Start-Process -Verb runas -FilePath "{self.config.opsi_script}" -ArgumentList {arg_string} -Wait',
					interpreter="powershell",
					timeout=OCA_INSTALL_TIMEOUT,
				),
			)
		else:
			await asyncio.get_event_loop().run_in_executor(
				None,
				lambda: run_command(
					[str(self.config.opsi_script)] + arg_list,
					timeout=OCA_INSTALL_TIMEOUT,
				),
			)

	async def install(self) -> bool:
		await self.show_message("Connecting to service...")
		password = self.config.service_password or ""
		if password.startswith("{crypt}"):
			password = decode_password(password)
		if self.config.service_address is None or self.config.service_username is None or password is None:
			raise ValueError("Incomplete data - cannot run service_setup.")

		await self.show_message("Connecting to service...")
		password = self.config.service_password or ""
		if password.startswith("{crypt}"):
			password = decode_password(password)
		if (
			self.config.service_address is None
			or not self.config.client_id
			or (not self.config.sso and (self.config.service_username is None or password is None))
		):
			raise ValueError("Incomplete data - cannot run service_setup.")
		self.backend = Backend(self.config.service_address, self.config.service_username, password, sso=self.config.sso)
		self.backend.connect()

		await self.show_message("Connected", "success")
		if "." not in self.config.client_id:
			self.config.client_id = f"{self.config.client_id}.{self.backend.get_domain()}"
		try:
			assert self.config.client_id
			logger.info("Starting installation")
			configserver_id = self.backend.get_configserver_id()
			await self.service_setup()
			depot_id = self.backend.get_depot_id(self.config.client_id)
			installed_oca_version = get_installed_oca_version()
			depot_id, avail_oca_version = self.backend.get_available_oca_version(configserver_id, depot_id)
			logger.debug(
				"opsi-client-agent versions: installed=%s, available=%s",
				installed_oca_version,
				avail_oca_version,
			)
			if (self.config.install_condition == "notinstalled" and installed_oca_version) or (
				self.config.install_condition == "outdated" and installed_oca_version == avail_oca_version
			):
				await self.show_message(f"Skipping installation as condition {self.config.install_condition} is not met.")
				return False
			self.cleanup_cache()
			self.config.check_values()
			self.base_dir = await self.copy_installation_files(depot_id)
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

		if self.dialog:
			await self.dialog.set_button_enabled("install", False)

		await self.show_message("Obtaining Client object")
		assert self.config.client_id
		client = self.backend.get_or_create_client(
			self.config.client_id,
			force_create=self.config.force_recreate_client,
			set_mac_address=self.config.set_mac_address,
		)
		self.config.client_key = client.opsiHostKey
		self.config.client_id = str(client.id)
		assert self.config.client_id

		await self.show_message("Client exists", "success")

		if self.config.setup_after_install:
			self.backend.set_product_property(
				client_id=self.config.client_id, property_id="setup_after_install", value=self.config.setup_after_install
			)

		if self.config.set_product_actions:
			self.backend.set_product_action_requests(self.config.client_id, self.config.set_product_actions)

		if self.config.depot or self.config.depot_by_network:
			if self.config.client_id == self.config.service_username:
				raise PermissionError(
					"Authorization error: Need opsi admin privileges to assign to depot",
					"error",
				)
			if self.config.depot:
				depot = self.config.depot
			else:
				depot = self.backend.get_depot_id_by_network()
				if not depot:
					raise InstallationUnsuccessful(f"Failed to get depot ID for client {self.config.client_id}")
				logger.info("Using depot %s for client %s", depot, self.config.client_id)
			self.backend.assign_client_to_depot(self.config.client_id, depot)

		if self.config.group:
			if self.config.client_id == self.config.service_username:
				raise PermissionError(
					"Authorization error: Need opsi admin privileges to add to hostgroup",
					"error",
				)
			self.backend.put_client_into_group(self.config.client_id, self.config.group)

		if self.dialog:
			await self.dialog.update_values()

	async def show_message(self, message: str, severity: Literal["normal", "error", "success"] = "normal") -> None:
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
				await asyncio.sleep(INSTALLATION_SUCCESS_CLOSE_DELAY)
				self.dialog.close()
		except BackendAuthenticationError:
			await self.show_message("Authentication error, wrong username or password", "error")
			await self.show_logpath(self.config.log_file)
		except InstallationUnsuccessful as err:
			await self.show_message(f"Installation Unsuccessful: {err}", "error")
			await self.show_logpath(self.opsi_script_logfile or "Undefined logfile.")
		except Exception as err:  # noqa: BLE001
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

	def ensure_root(self) -> None:
		if os.geteuid() != 0:
			print(f"{Path(sys.argv[0]).name} has to be run as root")
			os.execvp("sudo", ["sudo"] + sys.argv)

	def cleanup_cache(self) -> None:
		cache_dir = CONFIG_CACHE_DIRS.get(platform.system().lower())
		try:
			if cache_dir and cache_dir.exists():
				logger.info("Deleting opsiclientd WAN cache.")
				shutil.rmtree(cache_dir)
		except Exception as error:  # noqa: BLE001
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
		logger.info("Starting installation helper %s", __version__)
		error = None
		try:
			if platform.system().lower() != "windows":
				self.ensure_root()
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

		except Exception as err:  # noqa: BLE001
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
				run_script(self.config.end_command)
			except Exception as err:  # noqa: BLE001
				logger.error(err)
				error = err

		if self.config.end_marker:
			with open(self.config.end_marker, "wb"):
				pass

		if self.backend:
			self.backend.stop()
		if error:
			print(f"ERROR: {error}", file=sys.stderr)
			sys.exit(1)


class ArgumentParser(argparse.ArgumentParser):
	def _print_message(self, message: str, file: IO[str] | None = None) -> None:  # ty: ignore[invalid-method-override]
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
		default=str(
			(Path(r"C:\opsi.org\log") if platform.system().lower() == "windows" else Path("/var/log")) / "oca-installation-helper.log"
		),
	)
	parser.add_argument(
		"--log-level",
		"-l",
		default="notice",
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
		help="Username (on Config Server) to use for service connection.",
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
	parser.add_argument("--depot-by-network", help="Assign client to depot with matching network.", action="store_true")
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
		"--oca-package-source",
		type=Path,
		metavar="PATH",
		help="Use a local directory or archive instead of downloading the client-agent package from the depot.",
	)
	parser.add_argument(
		"--opsi-script-package-source",
		type=Path,
		metavar="PATH",
		help="Use a local directory or archive instead of downloading opsi-script from the depot.",
	)
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
	parser.add_argument(
		"--set-product-actions",
		default=None,
		help=(
			"Comma separated list of products action requests in the form <product>[:<action>] to set.\n"
			"If action is not given, it defaults to 'setup'.\n"
		),
	)
	parser.add_argument(
		"--sso",
		action="store_true",
		help="Use single-sign-on for login.",
	)
	parser.add_argument(
		"--bootimage",
		action="store_true",
		help="Set this flag for Installation in bootimage context.",
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

	if log_level > 0:
		log_file = Path(args.log_file)
		log_file.parent.mkdir(parents=True, exist_ok=True)
		if log_file.exists():
			log_file.unlink()
		stderr_level = log_level
		if not args.non_interactive and args.no_gui:  # no-gui mode and interactive
			stderr_level = 0
		logging_config(
			stderr_level=stderr_level,
			file_level=log_level,
			file_format="[%(levelname)-9s %(asctime)s] %(message)s   (%(filename)s:%(lineno)d)",
			log_file=str(log_file),
		)

	InstallationHelper(args).run()


if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		print("Interrupted", file=sys.stderr)
		sys.exit(1)
	except Exception:  # noqa: BLE001
		# Do not let pyinstaller handle exceptions and print:
		# "Failed to execute script"
		traceback.print_exc()
		sys.exit(1)
