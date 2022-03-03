# -*- coding: utf-8 -*-

# opsiclientd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2010-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsi-client-agent installation_helper
"""

import ctypes
import os
import re
import sys
import time
import threading
import codecs
import socket
import ipaddress
import tempfile
import platform
import subprocess
from pathlib import Path
from configparser import ConfigParser
import argparse
import shutil
from urllib.parse import urlparse
from typing import IO, Any, List, Optional
from zeroconf import ServiceBrowser, Zeroconf

import opsicommon  # type: ignore[import]
from opsicommon.exceptions import BackendAuthenticationError  # type: ignore[import]
from opsicommon.logging import logging_config  # type: ignore[import]
from opsicommon.types import forceHostId  # type: ignore[import]

from ocainstallationhelper import (
	__version__,
	monkeypatch_subprocess_for_frozen,
	logger,
	encode_password,
	decode_password,
	get_ip_interfaces,
	show_message,
	get_installed_oca_version,
	get_this_oca_version,
)
from ocainstallationhelper.console import ConsoleDialog
from ocainstallationhelper.gui import GUIDialog
from ocainstallationhelper.backend import Backend

DEFAULT_CONFIG_SERVICE_PORT = 4447

monkeypatch_subprocess_for_frozen()


class InstallationHelper:  # pylint: disable=too-many-instance-attributes,too-many-public-methods
	setup_script_name = "setup.opsiscript"

	def __init__(self, cmdline_args):
		self.cmdline_args = cmdline_args
		# macos does not use DISPLAY. gui does not work properly on macos right now.
		self.use_gui = platform.system().lower() == "windows" or os.environ.get("DISPLAY") not in (None, "")
		self.depot = None
		self.group = None
		self.force_recreate_client = False
		self.dialog = None
		self.clear_message_timer = None
		self.backend = None
		self.zeroconf = None
		self.zeroconf_addresses = []
		self.zeroconf_idx = -1
		self.interactive = True
		self.client_id = None
		self.client_key = None
		self.service_address = None
		self.service_username = None
		self.service_password = None
		self.finalize = None
		self.dns_domain = None
		self.base_dir = None
		self.setup_script = None
		self.full_path = Path(sys.argv[0])
		self.should_stop = False
		self.read_conf_files = ()
		self.install_condition = None
		self.tmp_dir = Path(tempfile.gettempdir()) / "oca-installation-helper-tmp"
		if not self.full_path.is_absolute():
			self.full_path = (Path(".") / self.full_path).absolute()
		self.get_cmdline_config()
		logger.info("Installation helper running from '%s', working dir '%s'", self.full_path, Path(".").absolute())

	@property
	def opsiclientd_conf(self) -> Optional[Path]:
		if platform.system().lower() == "windows":
			programs = os.environ.get("PROGRAMFILES(X86)") or os.environ.get("PROGRAMFILES")
			if programs:
				return Path(programs) / "opsi.org" / "opsi-client-agent" / "opsiclientd" / "opsiclientd.conf"
		if platform.system().lower() in ("linux", "darwin"):
			return Path("/etc/opsi-client-agent/opsiclientd.conf")
		return None

	def get_config_file_paths(self) -> List[Path]:
		if not self.base_dir:
			raise ValueError("No base dir given.")

		result = []
		for conffile in self.read_conf_files:
			if conffile == "install.conf":
				path = self.base_dir / "custom" / "install.conf"
				if not path.exists():
					path = self.base_dir / "install.conf"
			elif conffile == "config.ini":
				path = self.base_dir / "files" / "opsi" / "cfg" / "config.ini"
			elif conffile == "opsiclientd.conf":
				path = self.opsiclientd_conf
			else:
				path = Path(conffile)

			try:
				if path.exists():
					result.append(path)
				else:
					logger.info("Config file '%s' not found", path)
			except PermissionError:
				logger.info("No permission to open file '%s'", path)
		return result

	def read_config_files(self) -> None:  # pylint: disable=too-many-branches
		placeholder_regex = re.compile(r"#\@(\w+)\**#+")
		placeholder_regex_new = re.compile(r"%([\w\-]+)%")

		def get_value_from_config_file(key_tuples):
			for (section, key) in key_tuples:
				result = config.get(section, key, fallback=None)
				if result and not placeholder_regex.search(result) and not placeholder_regex_new.search(result):
					return result
			return None

		for config_file in self.get_config_file_paths():
			try:
				logger.info("Reading config file '%s'", config_file)
				config = ConfigParser()
				with codecs.open(str(config_file), "r", "utf-8") as file:
					data = file.read().replace("\r\n", "\n")
					if config_file.name == "install.conf" and "[install]" not in data:
						data = "[install]\n" + data
					config.read_string(data)

					self.client_id = self.client_id or get_value_from_config_file(
						[("install", "client_id"), ("global", "host_id")]  # install.conf, config.ini  # opsiclientd.conf
					)
					self.service_address = self.service_address or get_value_from_config_file(
						[("install", "service_address"), ("config_service", "url")]  # install.conf, config.ini  # opsiclientd.conf
					)
					self.service_username = self.service_username or get_value_from_config_file(
						[
							("install", "service_username"),  # install.conf
							("install", "client_id"),  # config.ini
							("global", "host_id"),  # opsiclientd.conf
						]
					)
					self.service_password = self.service_password or get_value_from_config_file(
						[
							("install", "service_password"),  # install.conf
							("install", "client_key"),  # config.ini
							("global", "opsi_host_key"),  # opsiclientd.conf
						]
					)
					self.depot = self.depot or get_value_from_config_file(
						[
							("install", "depot"),  # install.conf
						]
					)
					self.group = self.group or get_value_from_config_file(
						[
							("install", "group"),  # install.conf
						]
					)
					self.dns_domain = self.dns_domain or get_value_from_config_file(
						[
							("install", "dns_domain"),  # install.conf
							("install", "client_domain"),  # config.ini
						]
					)
					val = config.get("install", "interactive", fallback=None)  # install.conf
					if val and not placeholder_regex.search(val) and not placeholder_regex_new.search(val):
						self.interactive = val.lower().strip() in ("yes", "true", "on", "1")
					logger.debug(
						"Config after reading '%s': interactive=%s, client_id=%s, service_address=%s, "
						"service_username=%s, service_password=%s, dns_domain=%s",
						config_file,
						self.interactive,
						self.client_id,
						self.service_address,
						self.service_username,
						"*" * len(self.service_password or ""),
						self.dns_domain or "",
					)
			except Exception as err:  # pylint: disable=broad-except
				logger.error(err, exc_info=True)

	def get_cmdline_config(self) -> None:
		if self.cmdline_args.gui:
			self.use_gui = True
		if self.cmdline_args.no_gui:
			self.use_gui = False
		self.interactive = not self.cmdline_args.non_interactive
		self.client_id = self.cmdline_args.client_id
		self.service_address = self.cmdline_args.service_address
		self.service_username = self.cmdline_args.service_username
		self.service_password = self.cmdline_args.service_password
		self.depot = self.cmdline_args.depot
		self.group = self.cmdline_args.group
		self.force_recreate_client = self.cmdline_args.force_recreate_client
		self.finalize = self.cmdline_args.finalize
		self.dns_domain = self.cmdline_args.dns_domain
		self.read_conf_files = self.cmdline_args.read_conf_files
		self.install_condition = self.cmdline_args.install_condition
		logger.debug(
			"Config from cmdline: interactive=%s, client_id=%s, service_address=%s, "
			"service_username=%s, service_password=%s, depot=%s, group=%s, "
			"force_recreate_client=%s, finalize=%s, dns_domain=%s, "
			"read_conf_files=%s, install_condition=%s",
			self.interactive,
			self.client_id,
			self.service_address,
			self.service_username,
			"*" * len(self.service_password or ""),
			self.depot,
			self.group,
			self.force_recreate_client,
			self.finalize,
			self.dns_domain,
			self.read_conf_files,
			self.install_condition,
		)

	def get_config(self) -> None:
		self.read_config_files()

		# Do not overwrite client_id if explicitely set by parameter or found in config file
		if not self.client_id:
			self.client_id = socket.getfqdn().rstrip(".").lower()
			if self.dns_domain:
				self.client_id = ".".join((self.client_id.split(".")[0], self.dns_domain))

		if not self.service_address:
			self.start_zeroconf()
			for _sec in range(5):
				if self.service_address:
					break
				time.sleep(1)

		logger.debug(
			"Config: interactive=%s, client_id=%s, " "service_address=%s, service_username=%s, service_password=%s",
			self.interactive,
			self.client_id,
			self.service_address,
			self.service_username,
			"*" * len(self.service_password or ""),
		)

		if self.dialog:
			self.dialog.update()

	def start_zeroconf(self) -> None:
		self.show_message("Searching for opsi config services", display_seconds=5)
		if self.zeroconf:
			self.zeroconf.close()
		try:
			self.zeroconf = Zeroconf()
			ServiceBrowser(zc=self.zeroconf, type_="_opsics._tcp.local.", handlers=[self.zeroconf_handler])
		except Exception as err:  # pylint: disable=broad-except
			logger.error("Failed to start zeroconf: %s", err, exc_info=True)

	def zeroconf_handler(
		self, zeroconf: Zeroconf, service_type: str, name: str, state_change: Any  # pylint: disable=unused-argument
	) -> None:
		info = zeroconf.get_service_info(service_type, name)
		if not info:
			return
		logger.info(
			"opsi config service detected: server=%s, port=%s, version=%s",
			info.server,
			info.port,
			info.properties.get(b"version", b"").decode(),
		)
		logger.debug(info)

		if self.service_address:
			return

		ifaces = list(get_ip_interfaces())
		logger.info("Local ip interfaces: %s", [iface.compressed for iface in ifaces])
		for service_address in info.parsed_addresses():
			logger.info("Service address: %s", service_address)
			try:
				service_address = ipaddress.ip_address(service_address)
			except ValueError as err:
				logger.warning("Failed to parse service address '%s': %s", service_address, err)
			for iface in ifaces:
				if service_address in iface.network:
					logger.info("Service address '%s' in network '%s'", service_address, iface.network)
					service_url = f"https://{service_address}:{info.port}"
					if service_url not in self.zeroconf_addresses:
						self.zeroconf_addresses.append(service_url)
				logger.debug("Service address '%s' not in network '%s'", service_address, iface.network)

		self.zeroconf_idx += 1
		if self.zeroconf_idx >= len(self.zeroconf_addresses):
			self.zeroconf_idx = 0

		self.service_address = self.zeroconf_addresses[self.zeroconf_idx]
		if self.dialog:
			self.dialog.update()
		self.show_message(f"opsi config services found: {len(self.zeroconf_addresses)}", display_seconds=3)

	def copy_installation_files(self) -> None:
		dst_dir = Path(self.tmp_dir)
		dst_dir.mkdir(exist_ok=True)
		self.show_message(f"Copy installation files from '{self.base_dir}' to '{dst_dir}'")
		if dst_dir.exists():
			shutil.rmtree(str(dst_dir))
		shutil.copytree(str(self.base_dir), str(dst_dir))
		self.show_message(f"Installation files succesfully copied to '{dst_dir}'", "success")
		self.base_dir = dst_dir
		self.setup_script = self.base_dir / self.setup_script_name

	def find_setup_script(self) -> None:
		# iterating over full_path and all its parents
		for path in (self.full_path / "something").parents:
			script = path / self.setup_script_name
			if script.exists():
				self.setup_script = script
				self.base_dir = path
				break

		if not self.setup_script:
			raise RuntimeError(f"{self.setup_script_name} not found")

	def run_setup_script(self) -> None:
		self.show_message("Running setup script")

		if platform.system().lower() == "windows":
			oca_package = "opsi-client-agent"
			opsi_script = self.base_dir / "files" / "opsi-script" / "opsi-script.exe"
			log_dir = Path(r"c:\opsi.org\log")
			param_char = "/"
		elif platform.system().lower() == "linux":
			oca_package = "opsi-linux-client-agent"
			opsi_script = self.base_dir / "files" / "opsi-script" / "opsi-script"
			log_dir = Path("/var/log/opsi-script")
			param_char = "-"
		elif platform.system().lower() == "darwin":
			opsi_script = self.base_dir / "files" / "opsi-script.app" / "Contents" / "MacOS" / "opsi-script"
			oca_package = "opsi-mac-client-agent"
			log_dir = Path("/var/log/opsi-script")
			param_char = "-"
		else:
			raise NotImplementedError(f"Not implemented for {platform.system()}")

		if not log_dir.exists():
			try:
				log_dir.mkdir(parents=True)
			except Exception as exc:  # pylint: disable=broad-except
				logger.error("Could not create log directory %s due to %s\n still trying to continue", exc, log_dir, exc_info=True)
		arg_list = [
			str(self.setup_script),
			str(log_dir / "opsi-client-agent.log"),
			f"{param_char}servicebatch",
			f"{param_char}productid",
			oca_package,
			f"{param_char}opsiservice",
			self.service_address,
			f"{param_char}clientid",
			self.client_id,
			f"{param_char}username",
			self.client_id,
			f"{param_char}password",
			self.client_key,
			f"{param_char}parameter",
			self.finalize,
		]
		if platform.system().lower() == "windows":
			arg_string = ",".join([f'"{arg}"' for arg in arg_list])
			ps_script = f'Start-Process -Verb runas -FilePath "{opsi_script}" -ArgumentList {arg_string} -Wait'
			command = ["powershell", "-ExecutionPolicy", "bypass", "-WindowStyle", "hidden", "-command", ps_script]
		else:
			command = [opsi_script] + arg_list

		self.backend.set_poc_to_installing(oca_package, self.client_id)
		logger.info("Executing: %s\n", command)
		subprocess.call(command)

	def check_values(self) -> None:
		if not self.service_address:
			raise ValueError("Service address undefined")

		if not self.client_id:
			raise ValueError("Client id undefined")

		if "://" not in self.service_address:
			self.service_address = f"https://{self.service_address}"
		url = urlparse(self.service_address)
		port = url.port or DEFAULT_CONFIG_SERVICE_PORT
		hostname = str(url.hostname)
		if ":" in hostname:
			hostname = f"[{hostname}]"
		self.service_address = f"{url.scheme}://{hostname}:{port}{url.path}"

		self.client_id = forceHostId(self.client_id)

	def install(self) -> bool:
		try:
			if (self.install_condition == "not_installed" and get_installed_oca_version()) or (
				self.install_condition == "outdated" and get_installed_oca_version() != get_this_oca_version()
			):
				self.show_message(f"Skipping installation as condition {self.install_condition} is not met.")
				return False
			self.check_values()
			self.service_setup()
			self.run_setup_script()
			self.show_message("Evaluating script result")
			self.backend.evaluate_success(self.client_id)
			return True
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)
			raise

	def service_setup(self) -> None:
		if self.dialog:
			self.dialog.set_button_enabled("install", False)

		self.show_message("Connecting to service...")

		password = self.service_password
		if password.startswith("{crypt}"):
			password = decode_password(password)

		self.backend = Backend(address=self.service_address, username=self.service_username, password=password)

		self.show_message("Connected", "success")
		if "." not in self.client_id:  # pylint: disable=unsupported-membership-test
			self.client_id = f"{self.client_id}.{self.backend.get_domain()}"
			if self.dialog:
				self.dialog.update()

		client = self.backend.get_or_create_client(self.client_id, force_create=self.force_recreate_client)
		self.client_key = client.opsiHostKey
		self.client_id = client.id
		self.show_message("Client exists", "success")
		if self.depot:
			if self.client_id == self.service_username:
				raise PermissionError("Authorization error: Need opsi admin privileges to assign to depot", "error")
			self.backend.assign_client_to_depot(self.client_id, self.depot)
		if self.group:
			if self.client_id == self.service_username:
				raise PermissionError("Authorization error: Need opsi admin privileges to add to hostgroup", "error")
			self.backend.put_client_into_group(self.client_id, self.group)
		if self.dialog:
			self.dialog.update()

	def show_message(self, message: str, severity: str = None, display_seconds: float = 0) -> None:
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

	def on_cancel_button(self) -> None:
		self.show_message("Canceled")
		sys.exit(1)

	def on_install_button(self) -> None:
		self.dialog.set_button_enabled("install", False)
		try:
			# install returns True if installation successfull, False if skipped and throws Exception on error
			if self.install():
				self.show_message("Installation completed", "success")
			if self.dialog:
				# if using a dialog, wait for 5 Seconds before closing
				for _num in range(5):
					time.sleep(1)
				self.dialog.close()
		except BackendAuthenticationError:
			self.show_message("Authentication error, wrong username or password", "error")
		except Exception as err:  # pylint: disable=broad-except
			self.show_message(str(err), "error")
		self.dialog.set_button_enabled("install", True)

	def on_zeroconf_button(self) -> None:
		self.service_address = None
		if self.dialog:
			self.dialog.update()
		self.start_zeroconf()

	def cleanup(self) -> None:
		if self.tmp_dir.is_dir():
			logger.debug("Delete temp dir '%s'", self.tmp_dir)
			shutil.rmtree(self.tmp_dir)

	def ensure_admin(self) -> None:
		if platform.system().lower() != "windows":
			if os.geteuid() != 0:
				# not root
				if self.use_gui and platform.system().lower() == "linux":
					try:
						subprocess.call(["xhost", "+si:localuser:root"])
					except subprocess.SubprocessError as err:
						logger.error(err)
				print(f"{Path(sys.argv[0]).name} has to be run as root")
				os.execvp("sudo", ["sudo"] + sys.argv)
		else:
			if self.full_path.drive != Path(tempfile.gettempdir()).drive:
				# TODO test condition
				self.copy_installation_files()
			if ctypes.windll.shell32.IsUserAnAdmin() == 0:  # type: ignore
				# not elevated
				new_path = self.base_dir / "oca-installation-helper.exe"
				arg_string = ",".join([f'"{arg}"' for arg in sys.argv[1:]])
				ps_script = f'Start-Process -Verb runas -FilePath "{str(new_path)}" -ArgumentList {arg_string} -Wait'
				command = ["powershell", "-ExecutionPolicy", "bypass", "-WindowStyle", "hidden", "-command", ps_script]
				logger.info("Not running elevated. Rerunning oca-installation-helper as admin: %s\n", command)
				subprocess.call(command)

	def run(self) -> None:  # pylint: disable=too-many-branches
		error = None
		try:
			try:
				self.ensure_admin()
				if self.interactive:
					if self.use_gui:
						self.dialog = GUIDialog(self)
						self.dialog.show()
					else:
						self.dialog = ConsoleDialog(self)
						self.dialog.show()

				self.find_setup_script()
				self.get_config()

				self.cleanup()
				logger.debug("Create temp dir '%s'", self.tmp_dir)
				self.tmp_dir.mkdir(parents=True)

				if self.interactive and self.dialog:
					self.dialog.wait()
				else:
					self.install()

			except Exception as err:  # pylint: disable=broad-except
				error = err
				self.show_message(str(err), "error")
				if self.dialog:
					for _num in range(3):
						time.sleep(1)
			else:
				self.cleanup()
		finally:
			if self.dialog:
				self.dialog.close()
		if error:
			print(f"ERROR: {error}", file=sys.stderr)
			sys.exit(1)


class ArgumentParser(argparse.ArgumentParser):
	def _print_message(self, message: str, file: Optional[IO[str]] = None) -> None:
		show_message(message)


def parse_args(args: List[str] = None):
	if args is None:
		args = sys.argv[1:]  # executable path is not processed
	f_actions = ["noreboot", "reboot", "shutdown"]
	condition_choices = ["always", "noninstalled", "outdated"]
	parser = ArgumentParser()
	parser.add_argument("--version", action="version", version=__version__)
	parser.add_argument("--log-file", default=Path(tempfile.gettempdir()) / "oca-installation-helper.log")
	parser.add_argument("--log-level", default="warning", choices=["none", "debug", "info", "warning", "error", "critical"])
	parser.add_argument("--service-address", default=None, help="Service address to use.")
	parser.add_argument("--service-username", default=None, help="Username to use for service connection.")
	parser.add_argument("--service-password", default=None, help="Password to use for service connection.")
	parser.add_argument("--client-id", default=None, help="Client id to use.")
	parser.add_argument("--non-interactive", action="store_true", help="Do not ask questions.")
	parser.add_argument("--no-gui", action="store_true", help="Do not use gui.")
	parser.add_argument("--gui", action="store_true", help="Use gui.")
	parser.add_argument("--encode-password", action="store", metavar="PASSWORD", help="Encode PASSWORD.")
	parser.add_argument("--depot", help="Assign client to specified depot.", metavar="DEPOT")
	parser.add_argument("--group", help="Insert client into specified host group.", metavar="HOSTGROUP")
	parser.add_argument("--force-recreate-client", action="store_true", help="Always call host_createOpsiClient, even if it exists.")
	parser.add_argument("--finalize", default="noreboot", choices=f_actions, help="Action to perform after successfull installation.")
	parser.add_argument("--dns-domain", default=None, help="DNS domain for assembling client id (ignored if client id is given).")
	parser.add_argument(
		"--read-conf-files",
		nargs="*",
		metavar="FILE",
		default=("install.conf", "config.ini", "opsiclientd.conf"),
		help="config files to scan for informations, if empty no files are read (default: install.conf config.ini opsiclientd.conf)",
	)
	parser.add_argument(
		"--install-condition",
		default="always",
		choices=condition_choices,
		help="Uunder which condition should the client-agent be installed.",
	)

	return parser.parse_args(args)


def main() -> None:
	args = parse_args()
	if args.encode_password:
		show_message("{crypt}" + encode_password(args.encode_password))
		return

	log_level = args.log_level.upper()
	if log_level == "TRACE":
		log_level = "DEBUG"

	if log_level != "NONE":
		if args.log_file.exists():
			args.log_file.unlink()
		logging_config(
			file_level=getattr(opsicommon.logging, f"LOG_{log_level}"),
			file_format="[%(levelname)-9s %(asctime)s] %(message)s   (%(filename)s:%(lineno)d)",
			log_file=args.log_file,
		)

	InstallationHelper(args).run()
