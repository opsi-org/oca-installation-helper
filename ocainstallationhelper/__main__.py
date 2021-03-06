# -*- coding: utf-8 -*-

# opsiclientd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2010-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsi-client-agent installation_helper
"""

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
)
from ocainstallationhelper.console import ConsoleDialog
from ocainstallationhelper.gui import GUIDialog
from ocainstallationhelper.backend import Backend

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
		self.finalize = "noreboot"  # or reboot or shutdown
		self.base_dir = None
		self.setup_script = None
		self.full_path = Path(sys.argv[0])
		self.should_stop = False
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

	def read_config_files(self) -> None:  # pylint: disable=too-many-branches
		placeholder_regex = re.compile(r"#\@(\w+)\**#+")
		placeholder_regex_new = re.compile(r"%([\w\-]+)%")

		def get_value_from_config_file(key_tuples):
			for (section, key) in key_tuples:
				result = config.get(section, key, fallback=None)
				if result and not placeholder_regex.search(result) and not placeholder_regex_new.search(result):
					return result
			return None

		if not self.base_dir:
			raise ValueError("No base dir given.")

		install_conf = self.base_dir / "custom" / "install.conf"
		if not install_conf.exists():
			install_conf = self.base_dir / "install.conf"

		for config_file in (install_conf, self.base_dir / "files" / "opsi" / "cfg" / "config.ini", self.opsiclientd_conf):
			if not config_file.exists():
				logger.info("Config file '%s' not found", config_file)
				continue
			try:
				logger.info("Reading config file '%s'", config_file)
				config = ConfigParser()
				with codecs.open(config_file, "r", "utf-8") as file:
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
					val = config.get("install", "interactive", fallback=None)  # install.conf
					if val and not placeholder_regex.search(val) and not placeholder_regex_new.search(val):
						self.interactive = val.lower().strip() in ("yes", "true", "on", "1")
					logger.debug(
						"Config after reading '%s': interactive=%s, client_id=%s, "
						"service_address=%s, service_username=%s, service_password=%s",
						config_file,
						self.interactive,
						self.client_id,
						self.service_address,
						self.service_username,
						"*" * len(self.service_password or ""),
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
		logger.debug(
			"Config from cmdline: interactive=%s, client_id=%s, service_address=%s, "
			"service_username=%s, service_password=%s, depot=%s, group=%s, force_recreate_client=%s",
			self.interactive,
			self.client_id,
			self.service_address,
			self.service_username,
			"*" * len(self.service_password or ""),
			self.depot,
			self.group,
			self.force_recreate_client,
		)

	def get_config(self) -> None:
		self.read_config_files()

		if not self.client_id:
			self.client_id = socket.getfqdn().rstrip(".").lower()

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

	def run_setup_script_windows(self) -> None:
		opsi_script = self.base_dir / "files" / "opsi-script" / "opsi-script.exe"
		log_dir = Path(r"c:\opsi.org\log")
		if not log_dir.exists():
			try:
				log_dir.mkdir(parents=True)
			except Exception as exc:  # pylint: disable=broad-except
				logger.error("Could not create log directory %s due to %s\n still trying to continue", exc, log_dir, exc_info=True)
		log_file = log_dir / "opsi-client-agent.log"
		arg_list = [
			str(self.setup_script),
			str(log_file),
			"/servicebatch",
			"/productid",
			"opsi-client-agent",
			"/opsiservice",
			self.service_address,
			"/clientid",
			self.client_id,
			"/username",
			self.client_id,
			"/password",
			self.client_key,
			"/parameter",
			self.finalize,
		]

		arg_string = ",".join([f'"{arg}"' for arg in arg_list])
		ps_script = f'Start-Process -Verb runas -FilePath "{opsi_script}" -ArgumentList {arg_string} -Wait'
		command = ["powershell", "-ExecutionPolicy", "bypass", "-WindowStyle", "hidden", "-command", ps_script]
		logger.info("Executing: %s", command)
		subprocess.call(command)

	def run_setup_script_posix(self) -> None:
		if platform.system().lower() == "linux":
			opsi_script = self.base_dir / "files" / "opsi-script" / "opsi-script"
			productid = "opsi-linux-client-agent"
		elif platform.system().lower() == "darwin":
			opsi_script = self.base_dir / "files" / "opsi-script.app" / "Contents" / "MacOS" / "opsi-script"
			productid = "opsi-mac-client-agent"
		else:
			raise RuntimeError("'run_setup_script_posix' can only be executed on linux or macos!")

		log_dir = Path("/var/log/opsi-script")
		if not log_dir.exists():
			log_dir.mkdir(parents=True)
		log_file = log_dir / "opsi-client-agent.log"
		arg_list = [
			"-servicebatch",
			str(self.setup_script),
			str(log_file),
			"-productid",
			productid,
			"-opsiservice",
			self.service_address,
			"-clientid",
			self.client_id,
			"-username",
			self.client_id,
			"-password",
			self.client_key,
			"-parameter",
			self.finalize,
		]

		command = [opsi_script]
		command.extend(arg_list)
		logger.info("Executing: %s", command)
		print("\n\n")
		subprocess.call(command)

	def run_setup_script(self) -> None:
		self.show_message("Running setup script")

		if platform.system().lower() == "windows":
			self.backend.set_poc_to_installing("opsi-client-agent", self.client_id)
			return self.run_setup_script_windows()
		if platform.system().lower() == "linux":
			self.backend.set_poc_to_installing("opsi-linux-client-agent", self.client_id)
			return self.run_setup_script_posix()
		if platform.system().lower() == "darwin":
			self.backend.set_poc_to_installing("opsi-mac-client-agent", self.client_id)
			return self.run_setup_script_posix()

		raise NotImplementedError(f"Not implemented for {platform.system()}")

	def check_values(self) -> None:
		if not self.service_address:
			raise ValueError("Service address undefined")

		if not self.client_id:
			raise ValueError("Client id undefined")

		self.client_id = forceHostId(self.client_id)

	def install(self) -> None:
		try:
			self.check_values()
			self.service_setup()
			if platform.system().lower() == "windows" and self.full_path.drive != Path(tempfile.gettempdir()).drive:
				self.copy_installation_files()
			self.run_setup_script()
			self.show_message("Evaluating script result")
			self.backend.evaluate_success(self.client_id)
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

		client = self.backend.get_or_create_client(self.client_id)
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
			self.install()
			self.show_message("Installation completed", "success")
			for _num in range(5):
				time.sleep(1)
			if self.dialog:
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

	def run(self) -> None:  # pylint: disable=too-many-branches
		error = None
		try:
			try:
				if platform.system().lower() != "windows" and os.geteuid() != 0:
					if self.use_gui and platform.system().lower() == "linux":
						try:
							subprocess.call(["xhost", "+si:localuser:root"])
						except subprocess.SubprocessError as err:
							logger.error(err)
					print(f"{Path(sys.argv[0]).name} has to be run as root")
					os.execvp("sudo", ["sudo"] + sys.argv)

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


def show_message(message: str) -> None:
	if platform.system().lower() == "windows":
		from .gui import show_message as _show_message  # pylint: disable=import-outside-toplevel

		_show_message(message)
	else:
		sys.stdout.write(message)


class ArgumentParser(argparse.ArgumentParser):
	def _print_message(self, message: str, file: Optional[IO[str]] = None) -> None:
		show_message(message)


def parse_args(args: List[str] = None):
	if args is None:
		args = sys.argv[1:]  # executable path is not processed
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
