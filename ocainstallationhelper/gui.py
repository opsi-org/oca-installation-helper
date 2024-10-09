# -*- coding: utf-8 -*-

# opsiclientd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2010-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsi-client-agent installation_helper gui component
"""

from __future__ import annotations

import platform
import subprocess
import time
from pathlib import Path
from typing import TYPE_CHECKING

import toga
from opsicommon.logging import get_logger

from ocainstallationhelper import Dialog
from ocainstallationhelper.utils import get_resource_path

if TYPE_CHECKING:
	from ocainstallationhelper.__main__ import InstallationHelper

WIDTH = 70

logger = get_logger("oca-installation-helper")


def get_icon() -> str | None:
	if platform.system().lower() != "windows":
		return None
	return get_resource_path("opsi.ico")


def show_message(message: str) -> None:
	sg.popup_scrolled(message, title="opsi client agent installer", icon=get_icon(), auto_close=True, auto_close_duration=20)


class GUIDialog(Dialog, toga.App):
	def __init__(self, installation_helper: InstallationHelper) -> None:
		toga.App.__init__(self)
		self.inst_helper = installation_helper
		self.relevant_log_file = ""

	def show(self) -> None:
		self.start()
		while not self.window:
			time.sleep(1)

	def close(self) -> None:
		self._closed = True

	def wait(self) -> None:
		self.join()

	def run(self) -> None:
		sg.theme(SG_THEME)
		sg.SetOptions(element_padding=((1, 1), 0))
		layout = [
			[sg.Text("Client-ID")],
			[sg.Input(key="client_id", size=(WIDTH, 1), default_text=self.inst_helper.config.client_id)],
			[sg.Text("", font="Any 3")],
			[sg.Text("Opsi Service url")],
			[
				sg.Input(key="service_address", size=(WIDTH - 15, 1), default_text=self.inst_helper.config.service_address),
				sg.Button("Zeroconf", key="zeroconf", size=(15, 1)),
			],
			[sg.Text("", font="Any 3")],
			[sg.Text("Username")],
			[sg.Input(key="service_username", size=(WIDTH, 1), default_text=self.inst_helper.config.service_username)],
			[sg.Text("", font="Any 3")],
			[sg.Text("Password")],
			[sg.Input(key="service_password", size=(WIDTH, 1), default_text=self.inst_helper.config.service_password, password_char="*")],
			[sg.Text("", font="Any 3")],
			[sg.Text(size=(WIDTH, 3), key="message")],
			[sg.Text("", font="Any 3")],
			[
				sg.Text("", size=(35, 1)),
				sg.Button("Cancel", key="cancel", size=(10, 1)),
				sg.Button("Install", key="install", size=(10, 1), bind_return_key=True, disabled=True),
			],
			[sg.Button("Open logs", key="logs", size=(10, 1), disabled=False)],
		]

		height = 370
		if platform.system().lower() == "windows":
			height = 320
		icon = get_icon()
		logger.debug("rendering window with icon %s and layout %s", icon, layout)
		self.window = Window(title="opsi client agent installation", icon=icon, size=(500, height), layout=layout, finalize=True)
		assert self.window

		while not self._closed:
			event, values = self.window.read(timeout=1000)
			if event == "__TIMEOUT__":
				continue

			if values:
				for key, val in values.items():
					setattr(self.inst_helper.config, key, val)

			if event in (sg.WINDOW_CLOSED, "cancel"):
				self.inst_helper.on_cancel_button()
			elif event == "zeroconf":
				self.inst_helper.on_zeroconf_button()
			elif event == "install":
				self.inst_helper.on_install_button()
			elif event == "logs":
				self.open_logs()

	def update(self) -> None:
		if not self.window:
			return
		for attr in ("client_id", "service_address", "service_username", "service_password"):
			if attr in self.window.AllKeysDict:
				self.window[attr].update(getattr(self.inst_helper.config, attr))
		self.window.refresh()
		self.refresh()

	def set_button_enabled(self, button_id: str, enabled: bool) -> None:
		assert self.window
		self.window[button_id].update(disabled=not enabled)
		self.window.refresh()
		self.refresh()

	def show_message(self, message: str, severity: str | None = None) -> None:
		assert self.window
		text_color = "black"
		if severity == "success":
			text_color = "green"
		if severity == "error":
			text_color = "red"

		self.window["message"].update(message, text_color=text_color)
		self.window.refresh()
		self.refresh()

	def show_logpath(self, logpath: Path | str | None) -> None:
		assert self.window
		self.relevant_log_file = str(logpath) if logpath else ""
		self.window["logs"].update(disabled=False)
		self.window.refresh()

	def open_logs(self) -> None:
		if platform.system().lower() == "darwin":
			subprocess.Popen(("cat", self.relevant_log_file))
		elif platform.system().lower() == "windows":
			subprocess.Popen(("notepad.exe", self.relevant_log_file))
		else:
			subprocess.Popen(("cat", self.relevant_log_file))
