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
import codecs
import socket
import signal
import ipaddress
import tempfile
import platform
import subprocess
import logging
from configparser import ConfigParser
from argparse import ArgumentParser
import shutil
import psutil
from zeroconf import ServiceBrowser, Zeroconf
import PySimpleGUI.PySimpleGUI
from rich.prompt import Prompt

from ocainstallationhelper import __version__, logger
from ocainstallationhelper.jsonrpc import JSONRPCClient, BackendAuthenticationError

SG_THEME = "Default1" # "Reddit"


def _refresh_debugger():
	pass

def _create_error_message():
	pass

PySimpleGUI.PySimpleGUI._refresh_debugger = _refresh_debugger  # pylint: disable=protected-access
PySimpleGUI.PySimpleGUI._create_error_message = _create_error_message  # pylint: disable=protected-access

sg = PySimpleGUI.PySimpleGUI

def get_resource_path(relative_path):
	""" Get absolute path to resource, works for dev and for PyInstaller """
	try:
		# PyInstaller creates a temp folder and stores path in _MEIPASS
		base_path = sys._MEIPASS  # pylint: disable=protected-access,no-member
	except Exception:  # pylint: disable=broad-except
		base_path = os.path.abspath(".")

	return os.path.join(base_path, relative_path)

class InstallationHelper:  # pylint: disable=too-many-instance-attributes
	setup_script_name = "setup.opsiscript"

	def __init__(self, cmdline_args):
		self.cmdline_args = cmdline_args
		self.window = None
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
		self.tmp_dir = os.path.join(tempfile.gettempdir(), "oca-installation-helper")
		if not os.path.isabs(self.full_path):
			self.full_path = os.path.abspath(os.path.join(os.path.curdir, self.full_path))
		signal.signal(signal.SIGINT, self.signal_handler)
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

		install_conf = os.path.join("custom", "install.conf")
		if not os.path.exists(install_conf):
			install_conf = "install.conf"
		for config_file in (install_conf, os.path.join("files", "opsi", "cfg", "config.ini")):
			config_file = os.path.join(self.base_dir, config_file)
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

		if self.window:
			for attr in ("client_id", "service_address", "service_username", "service_password"):
				self.window[attr].update(getattr(self, attr))

	def start_zeroconf(self):
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
		if self.window:
			self.window['service_address'].update(self.service_address)
			self.window.refresh()

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
		elif platform.system().lower() == "darwin":
			opsi_script = os.path.join(self.base_dir, "files", "opsi-script.app", "Contents", "MacOS", "opsi-script")
		else:
			raise ValueError("'run_setup_script_posix' can only be executed on linux or macos!")

		log_dir = "/var/log"
		if not os.path.exists(log_dir):
			os.makedirs(log_dir)
		log_file = os.path.join(log_dir, "opsi-client-agent.log")
		arg_list = [
			"-batch", self.setup_script, log_file,
			"-productid", "opsi-linux-client-agent",
			"-opsiservice", self.service_address,
			"-clientid", self.client_id,
			"-username", self.client_id,
			"-password", self.client_key,
			"-parameter", self.finalize
		]

		if os.environ.get("USER") != "root" and os.environ.get("DISPLAY"):
			xhost_command = ["xhost", "+si:localuser:root"]
			subprocess.call(xhost_command)

		command = ["sudo", opsi_script]
		command.extend(arg_list)
		logger.info("Executing: %s", command)
		subprocess.call(command)

	def run_setup_script(self):
		self.show_message("Running setup script")
		if platform.system().lower() == 'windows':
			return self.run_setup_script_windows()
		if platform.system().lower() in ('linux', 'darwin'):
			return self.run_setup_script_posix()
		raise NotImplementedError(f"Not implemented for {platform.system()}")

	def install(self):
		try:
			self.service_setup()
			if self.full_path.startswith("\\\\"):
				self.copy_installation_files()
			self.run_setup_script()
		except Exception as err:
			logger.error(err, exc_info=True)
			raise

	def service_setup(self):
		if self.window:
			self.window['install'].update(disabled=True)
			self.window.refresh()
		self.show_message("Connecting to service...")

		if not self.service_address:
			raise ValueError("Invalid service address")

		self.service = JSONRPCClient(
			address=self.service_address,
			username=self.service_username,
			password=self.service_password
		)
		self.show_message("Connected", "success")
		if "." not in self.client_id:
			self.client_id = f"{self.client_id}.{self.service.execute_rpc('getDomain')}"
			if self.window:
				self.window['client_id'].update(self.client_id)
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
		if self.window:
			self.window["client_id"].update(self.client_id)

	def show_message(self, message, severity=None):
		text_color = "black"
		log = logger.notice
		if severity == "success":
			text_color = "green"
		if severity == "error":
			text_color = "red"
			log = logger.error

		log(message)
		if self.window:
			self.window['message'].update(message, text_color=text_color)
			self.window.refresh()

	def show_dialog(self):
		sg.theme(SG_THEME)
		sg.ChangeLookAndFeel('LightTeal')
		sg.SetOptions(element_padding=((1,1),0))
		layout = [
			[sg.Text("Client-ID")],
			[sg.Input(key='client_id', size=(70,1), default_text=self.client_id)],
			[sg.Text("", font='Any 3')],
			[sg.Text("Service")],
			[
				sg.Input(key='service_address', size=(55,1), default_text=self.service_address),
				sg.Button('Zeroconf', key='zeroconf', size=(15,1))
			],
			[sg.Text("", font='Any 3')],
			[sg.Text("Username")],
			[sg.Input(key='service_username', size=(70,1), default_text=self.service_username)],
			[sg.Text("", font='Any 3')],
			[sg.Text("Password")],
			[sg.Input(key='service_password', size=(70,1), default_text=self.service_password, password_char="*")],
			[sg.Text("", font='Any 3')],
			[sg.Text(size=(70,3), key='message')],
			[sg.Text("", font='Any 3')],
			[
				sg.Text("", size=(35,1)),
				sg.Button('Cancel', key='cancel', size=(10,1)),
				sg.Button('Install', key="install", size=(10,1), bind_return_key=True)
			]
		]

		height = 350
		icon = None
		if platform.system().lower() == "windows":
			height = 310
			icon = get_resource_path("opsi.ico")

		logger.debug("rendering window with icon %s and layout %s", icon, layout)
		self.window = sg.Window(
			title="opsi client agent installation",
			icon=icon,
			size=(500, height),
			layout=layout,
			finalize=True
		)

	def dialog_event_loop(self):
		while True:
			event, values = self.window.read(timeout=1000)
			if event == "__TIMEOUT__":
				continue

			if values:
				self.__dict__.update(values)

			if event in (sg.WINDOW_CLOSED, 'cancel'):
				sys.exit(1)
			if event == "zeroconf":
				self.service_address = None
				self.window["service_address"].update("")
				self.window.refresh()
				self.start_zeroconf()
			elif event == "install":
				try:
					self.install()
					self.show_message("Installation completed", "success")
					for _num in range(5):
						time.sleep(1)
					return
				except BackendAuthenticationError as err:
					self.show_message("Authentication error, wrong username or password", "error")
				except Exception as err:  # pylint: disable=broad-except
					self.show_message(str(err), "error")

				self.window['install'].update(disabled=False)
				self.window.refresh()

	def rich_input(self):
		default = self.client_id or None
		self.client_id = Prompt.ask("Please enter the ClientID [i](fqdn)[/i]", default=default)
		default = self.service_address or None
		self.service_address = Prompt.ask("Please enter the service address [i](https://<url>:<port>)[/i]", default=default)
		default = self.service_username or self.client_id or None
		self.service_username = Prompt.ask("Please enter the service username [i](e.g. the ClientID)[/i]", default=default)
		default = self.service_password or None
		self.service_password = Prompt.ask("Please enter the service password [i](e.g. Host-Key)[/i]", default=default, password=True)

	def run(self):
		try:
			try:
				use_gui = os.environ.get("DISPLAY") or platform.system().lower() == "darwin"
				if self.interactive and use_gui:
					self.show_dialog()

				self.find_setup_script()
				self.get_config()

				if self.interactive and not use_gui:
					self.rich_input()

				if os.path.exists(self.tmp_dir):
					shutil.rmtree(self.tmp_dir)
				logger.debug("Create temp dir '%s'", self.tmp_dir)
				os.makedirs(self.tmp_dir)

				if self.interactive and use_gui:
					self.dialog_event_loop()
				else:
					self.install()

			except Exception as err:
				self.show_message(str(err), "error")
				if self.window:
					for _num in range(3):
						time.sleep(1)
				raise
		finally:
			if os.path.exists(self.tmp_dir):
				logger.debug("Delete temp dir '%s'", self.tmp_dir)
				shutil.rmtree(self.tmp_dir)

def main():

	#sg.theme_previewer()
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
