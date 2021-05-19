# -*- coding: utf-8 -*-

# opsiclientd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2010-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

import time
import threading
import platform
import PySimpleGUI.PySimpleGUI

from ocainstallationhelper import logger, get_resource_path

SG_THEME = "Default1" # "Reddit"

def _refresh_debugger():
	pass

def _create_error_message():
	pass

PySimpleGUI.PySimpleGUI._refresh_debugger = _refresh_debugger  # pylint: disable=protected-access
PySimpleGUI.PySimpleGUI._create_error_message = _create_error_message  # pylint: disable=protected-access

sg = PySimpleGUI.PySimpleGUI


def get_icon():
	if platform.system().lower() != "windows":
		return None
	return get_resource_path("opsi.ico")


def show_message(message):
	sg.theme(SG_THEME)
	sg.popup_scrolled(
		message,
		title="opsi client agent installer",
		icon=get_icon(),
		auto_close=True,
		auto_close_duration=20
	)


class GUIDialog(threading.Thread):
	def __init__(self, installation_helper) -> None:
		threading.Thread.__init__(self)
		self.daemon = True
		self.inst_helper = installation_helper
		self.window = None
		self._closed = False

	def show(self):
		self.start()
		while not self.window:
			time.sleep(1)

	def close(self):
		self._closed = True

	def wait(self):
		self.join()

	def run(self):
		sg.theme(SG_THEME)
		sg.SetOptions(element_padding=((1,1),0))
		layout = [
			[sg.Text("Client-ID")],
			[sg.Input(key='client_id', size=(70,1), default_text=self.inst_helper.client_id)],
			[sg.Text("", font='Any 3')],
			[sg.Text("Service")],
			[
				sg.Input(key='service_address', size=(55,1), default_text=self.inst_helper.service_address),
				sg.Button('Zeroconf', key='zeroconf', size=(15,1))
			],
			[sg.Text("", font='Any 3')],
			[sg.Text("Username")],
			[sg.Input(key='service_username', size=(70,1), default_text=self.inst_helper.service_username)],
			[sg.Text("", font='Any 3')],
			[sg.Text("Password")],
			[sg.Input(key='service_password', size=(70,1), default_text=self.inst_helper.service_password, password_char="*")],
			[sg.Text("", font='Any 3')],
			[sg.Text(size=(70,3), key='message')],
			[sg.Text("", font='Any 3')],
			[
				sg.Text("", size=(35,1)),
				sg.Button('Cancel', key='cancel', size=(10,1)),
				sg.Button('Install', key='install', size=(10,1), bind_return_key=True)
			]
		]

		height = 350
		if platform.system().lower() == "windows":
			height = 310
		icon = get_icon()
		logger.debug("rendering window with icon %s and layout %s", icon, layout)
		self.window = sg.Window(
			title="opsi client agent installation",
			icon=icon,
			size=(500, height),
			layout=layout,
			finalize=True
		)

		while not self._closed:
			event, values = self.window.read(timeout=1000)
			if event == "__TIMEOUT__":
				continue

			if values:
				for key, val in values.items():
					setattr(self.inst_helper, key, val)

			if event in (sg.WINDOW_CLOSED, 'cancel'):
				self.inst_helper.on_cancel_button()
			elif event == "zeroconf":
				self.inst_helper.on_zeroconf_button()
			elif event == "install":
				self.inst_helper.on_install_button()

	def update(self):
		for attr in ("client_id", "service_address", "service_username", "service_password"):
			self.window[attr].update(getattr(self.inst_helper, attr))
		self.window.refresh()

	def set_button_enabled(self, button_id, enabled):
		self.window[button_id].update(disabled=not enabled)
		self.window.refresh()

	def show_message(self, message, severity=None):
		text_color = "black"
		if severity == "success":
			text_color = "green"
		if severity == "error":
			text_color = "red"

		self.window['message'].update(message, text_color=text_color)
		self.window.refresh()
