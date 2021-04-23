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
		self.error = None
		self.base_dir = None
		self.setup_script = None
		self.full_path = sys.argv[0]
		self.should_stop = False
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
				if snic.family not in (socket.AF_INET, socket.AF_INET6):
					continue
				try:
					netmask = snic.netmask
					if ":" in netmask:
						netmask = netmask.lower().count('f') * 4
					yield ipaddress.ip_interface(f"{snic.address.split('%')[0]}/{netmask}")
				except ValueError:
					continue

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
		os.makedirs(log_dir)
		log_file = os.path.join(log_dir, "opsi-client-agent.log")
		arg_list = [
			"/opsiservice", self.service_address,
			"/clientid", self.client_id,
			"/username", self.service_username,
			"/password", self.service_password,
			"/batch", self.setup_script, log_file
		] #,"/PARAMETER INSTALL:CREATE_CLIENT:REBOOT"

		arg_list = ",".join([ f'\\"{arg}\\"' for arg in arg_list ])
		logger.info(arg_list)
		start_proc = f'"Start-Process -FilePath \\"{opsi_script}\\" -ArgumentList {arg_list} -Wait"'
		logger.info(start_proc)
		subprocess.call(
			["powershell", "-ExcecutionPolicy", "bypass", "-Verb", "runas", "-Command", start_proc]
		)

	def run_setup_script(self):
		self.show_message("Running setup script")
		if platform.system().lower() == 'windows':
			return self.run_setup_script_windows()
		#if platform.system().lower() == 'linux':
		#	return self.run_setup_script_windows()
		raise NotImplementedError(f"Not implemented for {platform.system()}")

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


	def copy_installation_files(self):
		dst_dir = os.path.join(tempfile.gettempdir(), "ocd")
		self.show_message(f"Copy installation files from '{self.base_dir}' to '{dst_dir}'")
		if os.path.exists(dst_dir):
			shutil.rmtree(dst_dir)
		shutil.copytree(self.base_dir, dst_dir)
		self.show_message(f"Installation files succesfully copied to '{dst_dir}'", "success")
		self.base_dir = dst_dir
		self.setup_script = os.path.join(self.base_dir, self.setup_script_name)

	def run(self):
		try:
			if self.interactive:
				self.show_dialog()

			self.find_setup_script()
			self.get_config()
			if (
				self.client_id and self.service_address and
				self.service_username and self.service_password
			):
				self.connect_service()
				if not self.error:
					return

			if self.interactive:
				self.dialog_event_loop()

			#if self.full_path.startswith("\\\\"):
			self.copy_installation_files()
			self.run_setup_script()
		except Exception as err:
			self.show_message(str(err), "error")
			if self.window:
				time.sleep(3)
			raise

	def read_config_files(self):
		#for config_file in ("installation.ini", self.opsiclientd_conf, "files/opsi/cfg/config.ini"):
		for config_file in ("installation.ini", "files/opsi/cfg/config.ini"):
			config_file = os.path.join(self.base_dir, config_file)
			if not os.path.exists(config_file):
				continue
			try:
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

	def start_zeroconf(self):
		if not self.zeroconf:
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
						self.service_address = f"https://{service_address}:{info.port}"
						return

	def connect_service(self):
		self.error = None
		if self.window:
			self.window['connect'].update(disabled=True)
			self.window.refresh()
		self.show_message("Connecting...")

		try:
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
				self.service.execute_rpc("host_createOpsiClient", [{"type": "OpsiClient", "id": self.client_id}])
				self.show_message("Client created", "success")
				client = self.service.execute_rpc("host_getObjects", [[], {"id": self.client_id}])

			self.client_key = client[0]["opsiHostKey"]
			self.client_id = client[0]["id"]
			self.show_message("Client exists", "success")
			if self.window:
				self.window["client_id"].update(self.client_id)
		except BackendAuthenticationError as err:
			self.error = err
			self.show_message("Authentication error, wrong username or password", "error")
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err, exc_info=True)
			self.error = err
			self.show_message(str(err), "error")

		if self.error and self.window:
			self.window['connect'].update(disabled=False)
			self.window.refresh()

	def show_dialog(self):
		sg.theme("Reddit")
		sg.SetOptions(element_padding=((1,1),0))
		layout = [
			[sg.Text("Client-ID")],
			[sg.Input(key='client_id', size=(70,1), default_text=self.client_id)],
			[sg.Text("", font='Any 3')],
			[sg.Text("Service")],
			[sg.Input(key='service_address', size=(70,1), default_text=self.service_address)],
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
				sg.Text("", size=(39,1)),
				sg.Button('Cancel', key='cancel', size=(10,1)),
				sg.Button('Connect', key="connect", size=(10,1), bind_return_key=True)
			]
		]
		self.window = sg.Window(
			title='opsi service',
			size=(500,350),
			layout=layout,
			finalize=True
		)
		if self.error:
			self.window['message'].update(str(self.error), text_color="red")

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

	def dialog_event_loop(self):
		while True:
			event, values = self.window.read(timeout=1000)
			if event == "__TIMEOUT__":
				continue

			if values:
				self.__dict__.update(values)

			if event in (sg.WINDOW_CLOSED, 'cancel'):
				sys.exit(1)
			if event == "connect":
				self.connect_service()
				if not self.error:
					return


def main():
	#sg.theme_previewer()
	parser = ArgumentParser()
	parser.add_argument('--version',
		action='version',
		version=__version__
	)
	"""
	parser.add_argument("-l", "--log-level",
		default=LOG_NONE,
		type=int,
		choices=range(0, 10),
		help=(
			"Set the log level. "
			"0: nothing, 1: essential, 2: critical, 3: errors, 4: warnings, 5: notices "
			"6: infos, 7: debug messages, 8: trace messages, 9: secrets"
		)
	)
	"""
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

	logging.basicConfig(
		level=logging.DEBUG,
		format="[%(levelname)-9s %(asctime)s] %(message)s",
		handlers=[
			logging.StreamHandler(stream=sys.stderr)
		]
	)
	InstallationHelper(args).run()
