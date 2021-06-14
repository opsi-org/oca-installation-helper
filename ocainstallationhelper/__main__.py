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
import signal
import ipaddress
import tempfile
import platform
import subprocess
import logging
from configparser import ConfigParser
import argparse
import shutil
import psutil
from zeroconf import ServiceBrowser, Zeroconf

from ocainstallationhelper import __version__, logger
from ocainstallationhelper.jsonrpc import JSONRPCClient, BackendAuthenticationError
from ocainstallationhelper.console import ConsoleDialog
from ocainstallationhelper.gui import GUIDialog


class InstallationHelper:  # pylint: disable=too-many-instance-attributes
	setup_script_name = "setup.opsiscript"

	def __init__(self, cmdline_args):
		self.cmdline_args = cmdline_args
		# macos does not use DISPLAY. gui does not work properly on macos right now.
		self.use_gui = platform.system().lower() == "windows" or os.environ.get("DISPLAY")
		self.dialog = None
		self.clear_message_timer = None
		self.service = None
		self.zeroconf = None
		self.zeroconf_addresses = []
		self.zeroconf_idx = -1
		self.interactive = True
		self.client_id = None
		self.client_key = None
		self.service_address = None
		self.service_username = None
		self.service_password = None
		self.finalize = "noreboot"	# or reboot or shutdown
		self.base_dir = None
		self.setup_script = None
		self.full_path = sys.argv[0]
		self.should_stop = False
		self.tmp_dir = os.path.join(tempfile.gettempdir(), "oca-installation-helper-tmp")
		if not os.path.isabs(self.full_path):
			self.full_path = os.path.abspath(os.path.join(os.path.curdir, self.full_path))
		#signal.signal(signal.SIGINT, self.signal_handler)
		self.get_cmdline_config()

	def signal_handler(self, sig, frame):  # pylint: disable=unused-argument,no-self-use
		logger.info("Signal: %s", sig)
		sys.exit(0)

	@property
	def opsiclientd_conf(self):
		if platform.system().lower() == 'windows':
			return os.path.join(
				os.environ.get("PROGRAMFILES(X86)") or os.environ.get("PROGRAMFILES"),
				"opsi.org", "opsi-client-agent", "opsiclientd", "opsiclientd.conf"
			)
		if platform.system().lower() in ('linux', 'darwin'):
			return "/etc/opsi-client-agent/opsiclientd.conf"
		return None

	def get_ip_interfaces(self):  # pylint: disable=no-self-use
		for snics in psutil.net_if_addrs().values():
			for snic in snics:
				if snic.family not in (socket.AF_INET, socket.AF_INET6) or not snic.address or not snic.netmask:
					continue
				try:
					netmask = snic.netmask
					if ":" in netmask:
						netmask = netmask.lower().count('f') * 4
					yield ipaddress.ip_interface(f"{snic.address.split('%')[0]}/{netmask}")
				except ValueError:
					continue

	def read_config_files(self):  # pylint: disable=too-many-branches
		placeholder_regex = re.compile(r'#\@(\w+)\**#+')
		placeholder_regex_new = re.compile(r'%([\w\-]+)%')

		install_conf = os.path.join(self.base_dir, "custom", "install.conf")
		if not os.path.exists(install_conf):
			install_conf = os.path.join(self.base_dir, "install.conf")

		for config_file in (
			install_conf,
			os.path.join(self.base_dir, "files", "opsi", "cfg", "config.ini"),
			self.opsiclientd_conf
		):
			if not os.path.exists(config_file):
				logger.info("Config file '%s' not found", config_file)
				continue
			try:
				logger.info("Reading config file '%s'", config_file)
				config = ConfigParser()
				with codecs.open(config_file, "r", "utf-8") as file:
					data = file.read().replace("\r\n", "\n")
					if os.path.basename(config_file) == "install.conf" and not "[install]" in data:
						data = "[install]\n" + data
					config.read_string(data)

					if not self.client_id:
						val = config.get(
							"install", "client_id", # install.conf, config.ini
							fallback=config.get("global", "host_id", # opsiclientd.conf
								fallback=None
							)
						)
						if val and not placeholder_regex.search(val) and not placeholder_regex_new.search(val):
							self.client_id = val
					if not self.service_address:
						val = config.get(
							"install", "service_address", # install.conf, config.ini
							fallback=config.get("config_service", "url", # opsiclientd.conf
								fallback=None
							)
						)
						if val and not placeholder_regex.search(val) and not placeholder_regex_new.search(val):
							self.service_address = val
					if not self.service_username:
						val = config.get(
							"install", "service_username", # install.conf
							fallback=config.get("install", "client_id", # config.ini
								fallback=config.get("global", "host_id", # opsiclientd.conf
									fallback=None
								)
							)
						)
						if val and not placeholder_regex.search(val) and not placeholder_regex_new.search(val):
							self.service_username = val
					if not self.service_password:
						val = config.get(
							"install", "service_password", # install.conf
							fallback=config.get("install", "client_key", # config.ini
								fallback=config.get("global", "opsi_host_key", # opsiclientd.conf
									fallback=None
								)
							)
						)
						if val and not placeholder_regex.search(val) and not placeholder_regex_new.search(val):
							self.service_password = val
					val = config.get("install", "interactive", fallback=None) # install.conf
					if val and not placeholder_regex.search(val) and not placeholder_regex_new.search(val):
						self.interactive = val.lower().strip() in ("yes", "true", "on", "1")
					logger.debug(
						"Config after reading '%s': interactive=%s, client_id=%s, "
						"service_address=%s, service_username=%s, service_password=%s",
						config_file, self.interactive, self.client_id, self.service_address,
						self.service_username, "*" * len(self.service_password or "")
					)
			except Exception as err:  # pylint: disable=broad-except
				logger.error(err, exc_info=True)

	def get_cmdline_config(self):
		if self.cmdline_args.gui:
			self.use_gui = True
		if self.cmdline_args.no_gui:
			self.use_gui = False
		self.interactive = not self.cmdline_args.non_interactive
		self.client_id = self.cmdline_args.client_id
		self.service_address = self.cmdline_args.service_address
		self.service_username = self.cmdline_args.service_username
		self.service_password = self.cmdline_args.service_password
		logger.debug(
			"Config from cmdline: interactive=%s, client_id=%s, "
			"service_address=%s, service_username=%s, service_password=%s",
			self.interactive, self.client_id, self.service_address,
			self.service_username, "*" * len(self.service_password or "")
		)

	def get_config(self):
		self.read_config_files()

		if not self.client_id:
			self.client_id = socket.getfqdn()

		if not self.service_address:
			self.start_zeroconf()
			for _sec in range(5):
				if self.service_address:
					break
				time.sleep(1)

		logger.debug(
			"Config: interactive=%s, client_id=%s, "
			"service_address=%s, service_username=%s, service_password=%s",
			self.interactive, self.client_id, self.service_address,
			self.service_username, "*" * len(self.service_password or "")
		)

		if self.dialog:
			self.dialog.update()

	def start_zeroconf(self):
		self.show_message("Searching for opsi config services", display_seconds=5)
		if self.zeroconf:
			self.zeroconf.close()
		self.zeroconf = Zeroconf()
		ServiceBrowser(
			zc=self.zeroconf,
			type_="_opsics._tcp.local.",
			handlers=[self.zeroconf_handler]
		)

	def zeroconf_handler(self, zeroconf, service_type, name, state_change):  # pylint: disable=unused-argument
		info = zeroconf.get_service_info(service_type, name)
		logger.info(
			"opsi config service detected: server=%s, port=%s, version=%s",
			info.server, info.port, info.properties.get(b'version', b'').decode()
		)
		logger.debug(info)

		if self.service_address:
			return

		ifaces = list(self.get_ip_interfaces())
		logger.info("Local ip interfaces: %s", [iface.compressed for iface in  ifaces])
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
					if not service_url in self.zeroconf_addresses:
						self.zeroconf_addresses.append(service_url)
				logger.debug("Service address '%s' not in network '%s'", service_address, iface.network)

		self.zeroconf_idx += 1
		if self.zeroconf_idx >= len(self.zeroconf_addresses):
			self.zeroconf_idx = 0

		self.service_address = self.zeroconf_addresses[self.zeroconf_idx]
		if self.dialog:
			self.dialog.update()

		self.show_message(f"opsi config services found: {len(self.zeroconf_addresses)}", display_seconds=3)


	def copy_installation_files(self):
		dst_dir = os.path.join(self.tmp_dir)
		self.show_message(f"Copy installation files from '{self.base_dir}' to '{dst_dir}'")
		if os.path.exists(dst_dir):
			shutil.rmtree(dst_dir)
		shutil.copytree(self.base_dir, dst_dir)
		self.show_message(f"Installation files succesfully copied to '{dst_dir}'", "success")
		self.base_dir = dst_dir
		self.setup_script = os.path.join(self.base_dir, self.setup_script_name)

	def find_setup_script(self):
		path = self.full_path
		while not self.setup_script and os.path.dirname(path) != path:
			script = os.path.join(path, self.setup_script_name)
			if os.path.exists(script):
				self.setup_script = script
				self.base_dir = os.path.dirname(script)
			else:
				path = os.path.dirname(path)

		if not self.setup_script:
			raise RuntimeError(f"{self.setup_script_name} not found")

	def run_setup_script_windows(self):
		opsi_script = os.path.join(self.base_dir, "files", "opsi-script", "opsi-script.exe")
		log_dir = r"c:\opsi.org\log"
		if not os.path.exists(log_dir):
			os.makedirs(log_dir)
		log_file = os.path.join(log_dir, "opsi-client-agent.log")
		arg_list = [
			self.setup_script, log_file, "/batch",
			"/productid", "opsi-client-agent",
			"/opsiservice", self.service_address,
			"/clientid", self.client_id,
			"/username", self.client_id,
			"/password", self.client_key,
			"/parameter", self.finalize
		]

		arg_list = ",".join([f'"{arg}"' for arg in arg_list])
		ps_script = f'Start-Process -Verb runas -FilePath "{opsi_script}" -ArgumentList {arg_list} -Wait'
		logger.debug(ps_script)
		ps_script_file = os.path.join(self.tmp_dir, "setup.ps1")
		with codecs.open(ps_script_file, "w", "windows-1252") as file:
			file.write(f"{ps_script}\r\n")

		command = ["powershell", "-ExecutionPolicy", "bypass", "-WindowStyle", "hidden", "-File", ps_script_file]
		logger.info("Executing: %s", command)
		subprocess.call(command)

	def run_setup_script_posix(self):
		if platform.system().lower() == "linux":
			opsi_script = os.path.join(self.base_dir, "files", "opsi-script", "opsi-script")
			productid = "opsi-linux-client-agent"
		elif platform.system().lower() == "darwin":
			opsi_script = os.path.join(self.base_dir, "files", "opsi-script.app", "Contents", "MacOS", "opsi-script")
			productid = "opsi-mac-client-agent"
		else:
			raise RuntimeError("'run_setup_script_posix' can only be executed on linux or macos!")

		log_dir = "/var/log/opsi-client-agent/opsi-script"
		if not os.path.exists(log_dir):
			os.makedirs(log_dir)
		log_file = os.path.join(log_dir, "opsi-client-agent.log")
		arg_list = [
			"-batch", self.setup_script, log_file,
			"-productid", productid,
			"-opsiservice", self.service_address,
			"-clientid", self.client_id,
			"-username", self.client_id,
			"-password", self.client_key,
			"-parameter", self.finalize
		]

		command = [opsi_script]
		command.extend(arg_list)
		logger.info("Executing: %s", command)
		print("\n\n")
		subprocess.call(command)

	def run_setup_script(self):
		self.show_message("Running setup script")
		if platform.system().lower() == 'windows':
			return self.run_setup_script_windows()
		if platform.system().lower() in ('linux', 'darwin'):
			return self.run_setup_script_posix()
		raise NotImplementedError(f"Not implemented for {platform.system()}")

	def check_values(self):
		if not self.service_address:
			raise ValueError("Service address undefined")

		if not self.client_id:
			raise ValueError("Client id undefined")

		for part in self.client_id.split("."):
			if len(part) < 1 or len(part) > 63:
				raise ValueError("Invalid client id")

	def install(self):
		try:
			self.check_values()
			self.service_setup()
			if self.full_path.startswith("\\\\"):
				self.copy_installation_files()
			self.run_setup_script()
		except Exception as err:
			logger.error(err, exc_info=True)
			raise

	def service_setup(self):
		if self.dialog:
			self.dialog.set_button_enabled("install", False)

		self.show_message("Connecting to service...")

		self.service = JSONRPCClient(
			address=self.service_address,
			username=self.service_username,
			password=self.service_password
		)
		self.show_message("Connected", "success")
		if "." not in self.client_id:
			self.client_id = f"{self.client_id}.{self.service.execute_rpc('getDomain')}"
			if self.dialog:
				self.dialog.update()

		client = self.service.execute_rpc("host_getObjects", [[], {"id": self.client_id}])
		if not client:
			self.show_message("Create client...")
			# id, opsiHostKey, description, notes, hardwareAddress, ipAddress,
			# inventoryNumber, oneTimePassword, created, lastSeen
			client = [self.client_id]
			logger.info("Creating client: %s", client)
			self.service.execute_rpc("host_createOpsiClient", client)
			self.show_message("Client created", "success")
			client = self.service.execute_rpc("host_getObjects", [[], {"id": self.client_id}])

		self.client_key = client[0]["opsiHostKey"]
		self.client_id = client[0]["id"]
		self.show_message("Client exists", "success")
		if self.dialog:
			self.dialog.update()

	def show_message(self, message, severity=None, display_seconds=0):
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

	def on_cancel_button(self):
		self.show_message("Canceled")
		sys.exit(1)

	def on_install_button(self):
		self.dialog.set_button_enabled("install", False)
		try:
			self.install()
			self.show_message("Installation completed", "success")
			for _num in range(5):
				time.sleep(1)
			if self.dialog:
				self.dialog.close()
		except BackendAuthenticationError as err:
			self.show_message("Authentication error, wrong username or password", "error")
		except Exception as err:  # pylint: disable=broad-except
			self.show_message(str(err), "error")
		self.dialog.set_button_enabled("install", True)

	def on_zeroconf_button(self):
		self.service_address = None
		if self.dialog:
			self.dialog.update()
		self.start_zeroconf()

	def run(self):
		error = None
		try:
			try:
				if platform.system().lower() != "windows" and os.geteuid() != 0:
					if self.use_gui and platform.system().lower() == "linux":
						try:
							subprocess.call(["xhost", "+si:localuser:root"])
						except subprocess.SubprocessError as err:
							logger.error(err)
					print(f"{os.path.basename(sys.argv[0])} has to be run as root")
					os.execvp("sudo", ["sudo"] + sys.argv)

				if self.interactive:
					if self.use_gui:
						self.dialog = GUIDialog(self)
					else:
						self.dialog = ConsoleDialog(self)
					self.dialog.show()

				self.find_setup_script()
				self.get_config()

				if os.path.isdir(self.tmp_dir):
					shutil.rmtree(self.tmp_dir)
				logger.debug("Create temp dir '%s'", self.tmp_dir)
				os.makedirs(self.tmp_dir)

				if self.interactive and self.dialog:
					self.dialog.wait()
				else:
					self.install()

			except Exception as err:
				error = err
				self.show_message(str(err), "error")
				if self.dialog:
					for _num in range(3):
						time.sleep(1)
		finally:
			if self.dialog:
				self.dialog.close()
			if os.path.isdir(self.tmp_dir):
				logger.debug("Delete temp dir '%s'", self.tmp_dir)
				shutil.rmtree(self.tmp_dir)
		if error:
			print(f"ERROR: {error}", file=sys.stderr)
			sys.exit(1)


class ArgumentParser(argparse.ArgumentParser):
	def _print_message(self, message, file=None):
		if platform.system().lower() == "windows":
			from .gui import show_message
			show_message(message)
		else:
			sys.stderr.write(message)


def main():
	parser = ArgumentParser()
	parser.add_argument(
		"--version",
		action="version",
		version=__version__
	)
	parser.add_argument(
		"--log-file",
		default=os.path.join(
			tempfile.gettempdir(), "oca-installation-helper.log"
		)
	)
	parser.add_argument(
		"--log-level",
		default="warning",
		choices=["none", "debug", "info", "warning", "error", "critical"]
	)
	parser.add_argument(
		"--service-address",
		default=None,
		help="Service address to use."
	)
	parser.add_argument(
		"--service-username",
		default=None,
		help="Username to use for service connection."
	)
	parser.add_argument(
		"--service-password",
		default=None,
		help="Password to use for service connection."
	)
	parser.add_argument(
		"--client-id",
		default=None,
		help="Client id to use."
	)
	parser.add_argument(
		"--non-interactive",
		action="store_true",
		help="Do not ask questions."
	)
	parser.add_argument(
		"--no-gui",
		action="store_true",
		help="Do not use gui."
	)
	parser.add_argument(
		"--gui",
		action="store_true",
		help="Use gui."
	)

	args = parser.parse_args()

	log_level = args.log_level.upper()
	if log_level == "TRACE":
		log_level = "DEBUG"

	if log_level != "NONE":
		logging.basicConfig(
			level=getattr(logging, log_level),
			format="[%(levelname)-9s %(asctime)s] %(message)s   (%(filename)s:%(lineno)d)",
			handlers=[
				logging.FileHandler(filename=args.log_file, mode="w", encoding="utf-8")
				#logging.StreamHandler(stream=sys.stderr)
			]
		)

	InstallationHelper(args).run()
