"""
opsi-client-agent installation_helper config class
"""

import argparse
import codecs
import os
import platform
import re
import ipaddress

import socket

from configparser import ConfigParser
from pathlib import Path
from typing import Any, Callable, List, Optional, Tuple
from urllib.parse import urlparse
from zeroconf import ServiceBrowser, Zeroconf


from opsicommon.types import forceHostId  # type: ignore[import]

from ocainstallationhelper import (
	get_ip_interfaces,
	logger,
)

SETUP_SCRIPT_NAME = "setup.opsiscript"
DEFAULT_CONFIG_SERVICE_PORT = 4447


class Config:  # pylint: disable=too-many-instance-attributes
	def __init__(self, cmdline_args: argparse.Namespace, full_path) -> None:
		self.client_id: Optional[str] = cmdline_args.client_id
		self.client_key: Optional[str] = None
		self.service_address: Optional[str] = cmdline_args.service_address
		self.service_username: Optional[str] = cmdline_args.service_username
		self.service_password: Optional[str] = cmdline_args.service_password
		self.finalize: Optional[str] = cmdline_args.finalize
		self.dns_domain: Optional[str] = cmdline_args.dns_domain
		self.depot: Optional[str] = cmdline_args.depot
		self.group: Optional[str] = cmdline_args.group

		self.use_gui: bool = platform.system().lower() == "windows" or os.environ.get("DISPLAY") not in (None, "")
		if cmdline_args.gui:
			self.use_gui = True
		if cmdline_args.no_gui:
			self.use_gui = False

		self.set_mac_address: bool = True
		if cmdline_args.no_set_mac_address:
			self.set_mac_address = False

		self.interactive: bool = not cmdline_args.non_interactive
		self.force_recreate_client: bool = cmdline_args.force_recreate_client
		self.read_conf_files: Tuple[Path, ...] = cmdline_args.read_conf_files
		self.install_condition: Optional[str] = cmdline_args.install_condition

		self.log_file: Optional[str] = cmdline_args.log_file
		# iterating over full_path and all its parents
		for path in (full_path / "something").parents:
			script = path / SETUP_SCRIPT_NAME
			if script.exists():
				self.setup_script: Path = script
				self.base_dir: Path = path
				break
		else:  # did not find a setup_script
			raise RuntimeError(f"{SETUP_SCRIPT_NAME} not found")

		self.zeroconf: Optional[Zeroconf] = None
		self.zeroconf_addresses: List[str] = []
		self.zeroconf_idx: int = -1

		logger.debug(
			"Config from cmdline: interactive=%s, client_id=%s, service_address=%s, "
			"service_username=%s, service_password=%s, depot=%s, group=%s, "
			"force_recreate_client=%s, finalize=%s, dns_domain=%s, "
			"read_conf_files=%s, install_condition=%s, set_mac_address=%s",
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
			self.set_mac_address,
		)

	def get_config_file_paths(self) -> List[Path]:
		if not self.base_dir:
			raise ValueError("No base dir given.")

		result = []
		for conffile in self.read_conf_files:
			if conffile == "install.conf":
				path = self.base_dir / "files" / "custom" / "install.conf"
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

	def fill_config_from_files(self, config_files: List[Path] = None) -> None:  # pylint: disable=too-many-branches
		if config_files is None:
			config_files = self.get_config_file_paths()
		placeholder_regex = re.compile(r"#\@(\w+)\**#+")
		placeholder_regex_new = re.compile(r"%([\w\-]+)%")

		def get_value_from_config_file(key_tuples: List[Tuple[str, str]]) -> Optional[str]:
			for (section, key) in key_tuples:
				result = config.get(section, key, fallback=None)
				if result and not placeholder_regex.search(result) and not placeholder_regex_new.search(result):
					return result
			return None

		for config_file in config_files:
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

	@property
	def opsiclientd_conf(self) -> Path:
		if platform.system().lower() == "windows":
			programs = os.environ.get("PROGRAMFILES(X86)") or os.environ.get("PROGRAMFILES")
			if programs:
				return Path(programs) / "opsi.org" / "opsi-client-agent" / "opsiclientd" / "opsiclientd.conf"
		if platform.system().lower() in ("linux", "darwin"):
			return Path("/etc/opsi-client-agent/opsiclientd.conf")
		raise ValueError(f"Unrecognised platform {platform.system()}.")

	def fill_config_from_default(self) -> None:
		# Do not overwrite client_id if explicitely set by parameter or found in config file
		if not self.client_id:
			self.client_id = socket.getfqdn().rstrip(".").lower()
			if self.dns_domain:
				self.client_id = ".".join((self.client_id.split(".")[0], self.dns_domain))

	def fill_config_from_registry(self, parse_args_function: Callable) -> None:
		if platform.system().lower() != "windows":
			return
		import winreg  # pylint: disable=import-outside-toplevel,import-error

		def get_registry_value(key, sub_key, value_name):
			logger.debug("Requesting key %s and value %s", sub_key, value_name)
			hkey = None
			try:
				hkey = winreg.OpenKey(key, sub_key)
				(value, _type) = winreg.QueryValueEx(hkey, value_name)
			finally:
				if hkey:
					winreg.CloseKey(hkey)
			return value

		# or HKEY_LOCAL_MACHINE\SOFTWARE\opsi.org\general ?
		try:
			install_params_string = get_registry_value(
				winreg.HKEY_LOCAL_MACHINE,  # type: ignore[attr-defined]
				"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\opsi-client-agent",
				"INSTALL_PARAMS",
			)
		except Exception as error:  # pylint: disable=broad-except
			logger.info("Could not open registry key, skipping fill_config_from_registry.")
			logger.debug("Caught Error %s", error, exc_info=True)
			return
		logger.info("Obtained install_params_string %s", install_params_string)
		if not install_params_string:
			return
		args = parse_args_function(re.split(" |=", install_params_string))
		self.client_id = self.client_id or args.client_id
		self.service_address = self.service_address or args.service_address
		self.service_username = self.service_username or args.service_username
		self.service_password = self.service_password or args.service_password
		self.depot = self.depot or args.depot
		self.group = self.group or args.group
		self.dns_domain = self.dns_domain or args.dns_domain
		if args.non_interactive is not None:
			self.interactive = not args.non_interactive

	def check_values(self) -> None:
		if not self.service_address:
			raise ValueError("Service address undefined.")

		if not self.client_id:
			raise ValueError("Client id undefined.")

		if "://" not in self.service_address:
			self.service_address = f"https://{self.service_address}"
		url = urlparse(self.service_address)
		port = url.port or DEFAULT_CONFIG_SERVICE_PORT
		hostname = str(url.hostname)
		if ":" in hostname:
			hostname = f"[{hostname}]"
		self.service_address = f"{url.scheme}://{hostname}:{port}{url.path}"

		self.client_id = forceHostId(self.client_id)

	def fill_config_from_zeroconf(self):
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
		for service_address_str in info.parsed_addresses():
			logger.info("Service address: %s", service_address_str)
			try:
				service_address = ipaddress.ip_address(service_address_str)
			except ValueError as err:
				logger.warning("Failed to parse service address '%s': %s", service_address_str, err)
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
