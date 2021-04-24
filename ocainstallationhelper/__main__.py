# -*- coding: utf-8 -*-

# opsiclientd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2010-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsi-client-agent installation_helper
"""

import os
import sys
import time
import codecs
import socket
import signal
import shutil
import psutil
import ipaddress
import tempfile
import platform
import subprocess
import logging
from configparser import ConfigParser
from argparse import ArgumentParser
from zeroconf import ServiceBrowser, Zeroconf
import PySimpleGUI as sg

from . import __version__, logger
from .jsonrpc import JSONRPCClient, BackendAuthenticationError

SG_THEME = "Default1" # "Reddit"

class InstallationHelper:  # pylint: disable=too-many-instance-attributes
	setup_script_name = "setup.opsiscript"

	def __init__(self, cmdline_args):
		self.cmdline_args = cmdline_args
		self.window = None
		self.service = None
		self.zeroconf = None
		self.interactive = True
		self.client_id = None
		self.client_key = None
		self.service_address = None
		self.service_username = None
		self.service_password = None
		self.base_dir = None
		self.setup_script = None
		self.full_path = sys.argv[0]
		self.should_stop = False
		self.tmp_dir = os.path.join(tempfile.gettempdir(), "oca-installation-helper")
		if not os.path.isabs(self.full_path):
			self.full_path = os.path.abspath(os.path.join(os.path.curdir, self.full_path))
		signal.signal(signal.SIGINT, self.signal_handler)

	def signal_handler(self, signal, frame):
		logger.info("Signal: %s", signal)
		sys.exit(0)

	@property
	def opsiclientd_conf(self):
		if platform.system().lower() == 'windows':
			return os.path.join(
				os.environ.get("PROGRAMFILES(X86)") or os.environ.get("PROGRAMFILES"),
				"opsi.org", "opsi-client-agent", "opsiclientd", "opsiclientd.conf"
			)
		if platform.system().lower() == 'linux':
			return "/etc/opsi-client-agent/opsiclientd.conf"

	def get_ip_interfaces(self):
		for interface, snics in psutil.net_if_addrs().items():
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

	def read_config_files(self):
		for config_file in ("install.conf", self.opsiclientd_conf, "files/opsi/cfg/config.ini"):
			config_file = os.path.join(self.base_dir, config_file)
			if not os.path.exists(config_file):
				logger.info("Config file '%s' not found", config_file)
				continue
			try:
				logger.info("Reading config file '%s'", config_file)
				config = ConfigParser()
				config.read(config_file, encoding="utf-8")
				if not self.client_id:
					self.service_address = config.get("client", "id", fallback=None)
				if not self.service_address:
					self.service_address = config.get(
						"service", "address", fallback=config.get(
							"opsiclientd", "config_service.url", fallback=config.get(
								"config_service", "url", fallback=None
							)
						)
					)
				if not self.service_username:
					self.service_username = config.get(
						"service", "username", fallback=config.get(
							"installation", "service_user", fallback=None
						)
					)
				if not self.service_password:
					self.service_password = config.get(
						"service", "password", fallback=config.get(
							"installation", "service_password", fallback=None
						)
					)
				#config.get("general", "dnsdomain", fallback=None)
			except Exception as err:  # pylint: disable=broad-except
				logger.error(err)

	def get_config(self):
		self.interactive = not self.cmdline_args.non_interactive
		self.client_id = self.cmdline_args.client_id
		self.service_address = self.cmdline_args.service_address
		self.service_username = self.cmdline_args.service_username
		self.service_password = self.cmdline_args.service_password

		self.read_config_files()

		if not self.client_id:
			self.client_id = socket.getfqdn()

		if not self.service_address:
			self.start_zeroconf()
			for _sec in range(5):
				if self.service_address:
					break
				time.sleep(1)

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
		if not self.service_address:
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
						self.service_address = f"https://{service_address}:{info.port}"
						if self.window:
							self.window['service_address'].update(self.service_address)
							self.window.refresh()
						return
					else:
						logger.debug("Service address '%s' not in network '%s'", service_address, iface.network)

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
			"/batch", self.setup_script, log_file,
			#"/opsiservice", self.service_address,
			#"/clientid", self.client_id,
			#"/username", self.service_username,
			#"/password", self.service_password
			"/parameter", (
				f"{self.client_id}||{self.service_address}||{self.service_username}||{self.service_password}"
			)
		] #,"/PARAMETER INSTALL:CREATE_CLIENT:REBOOT"

		arg_list = ",".join([f'"{arg}"' for arg in arg_list])
		ps_script = f'Start-Process -Verb runas -FilePath "{opsi_script}" -ArgumentList {arg_list} -Wait'
		logger.debug(ps_script)
		ps_script_file = os.path.join(self.tmp_dir, "setup.ps1")
		with codecs.open(ps_script_file, "w", "windows-1252") as file:
			file.write(f"{ps_script}\r\n")

		command = ["powershell", "-ExecutionPolicy", "bypass", "-File", ps_script_file]
		logger.info("Executing: %s", command)
		subprocess.call(command)

	def run_setup_script(self):
		self.show_message("Running setup script")
		if platform.system().lower() == 'windows':
			return self.run_setup_script_windows()
		#if platform.system().lower() == 'linux':
		#	return self.run_setup_script_windows()
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
		height = 310 if platform.system().lower() == 'windows' else 350
		self.window = sg.Window(
			title='opsi client agent installation',
			icon='opsi.ico',
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

	def run(self):
		try:
			try:
				self.get_config()

				if os.path.exists(self.tmp_dir):
					shutil.rmtree(self.tmp_dir)
				logger.debug("Create temp dir '%s'", self.tmp_dir)
				os.makedirs(self.tmp_dir)

				if self.interactive:
					self.show_dialog()

				self.find_setup_script()

				if not self.interactive:
					self.install()
				else:
					self.dialog_event_loop()
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
	parser.add_argument('--version',
		action='version',
		version=__version__
	)
	parser.add_argument("--log-level",
		default="warning",
		choices=['debug', 'info', 'warning', 'error', 'critical']
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

	logging.basicConfig(
		level=getattr(logging, log_level),
		format="[%(levelname)-9s %(asctime)s] %(message)s",
		handlers=[
			logging.StreamHandler(stream=sys.stderr)
		]
	)
	arg_dict = dict(args.__dict__)
	if arg_dict["service_password"]:
		arg_dict["service_password"] = "***confidential***"
	logger.debug("Cmdline arguments: %s", arg_dict)

	InstallationHelper(args).run()
