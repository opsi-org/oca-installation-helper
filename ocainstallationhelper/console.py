# -*- coding: utf-8 -*-

# opsiclientd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2010-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

import time
import signal
import threading
import platform

from picotui.widgets import *
from picotui.menu import *
from picotui.context import Context

from ocainstallationhelper import logger

class WDialogTextEntry(WTextEntry):
	def __init__(self, w, text):
		self.password_char = None
		super().__init__(w, text)

	def handle_edit_key(self, key):
		res = None
		if key is not None:
			res = super().handle_edit_key(key)
		self.signal("changed")
		return res

	def show_line(self, l, i):
		if l is None:
			l = ""
		self.attr_color(C_BLACK, C_WHITE)
		l = l[self.margin:]
		l = l[:self.width]
		if self.password_char is not None:
			l = self.password_char * len(l)
		self.wr(l)
		self.clear_num_pos(self.width - len(l))
		self.attr_reset()


class ConsoleDialog(threading.Thread):
	def __init__(self, installation_helper) -> None:
		threading.Thread.__init__(self)
		self.daemon = True
		self.inst_helper = installation_helper
		self.inputs = {}
		self.buttons = {}
		self._closed = False
		if platform.system().lower() != "windows":
			signal.signal(signal.SIGWINCH, self._sigwinch_handler)

	def show(self):
		self.start()
		time.sleep(1)

	def close(self):
		self._closed = True
		Screen.goto(0, 50)
		Screen.cursor(True)
		Screen.deinit_tty()
		print()

	def wait(self):
		self.join()

	def update(self):
		for attr in ("client_id", "service_address", "service_username", "service_password"):
			self.inputs[attr].set(getattr(self.inst_helper, attr))
		self._redraw()

	def set_button_enabled(self, button_id, enabled):
		self.buttons[button_id].disabled = not enabled

	def show_message(self, message, severity=None):
		self.message.t = message
		self._redraw()

	def _sigwinch_handler(self, *args):
		self._redraw()

	def _redraw(self):
		try:
			self._screen_redraw(Screen)
		except Exception:  # pylint: disable=broad-except
			pass

	def _screen_redraw(self, screen, allow_cursor=False):
		#screen.attr_color(C_WHITE, C_BLUE)
		screen.cls()
		screen.attr_reset()
		self.dialog.redraw()

	def _on_change(self, _widget):
		for attr in ("client_id", "service_address", "service_username", "service_password"):
			setattr(self.inst_helper, attr, self.inputs[attr].get())

	def _on_cancel(self, _widget):
		self.inst_helper.on_cancel_button()

	def _on_install(self, _widget):
		self.inst_helper.on_install_button()

	def _on_zeroconf(self, _widget):
		self.inst_helper.on_zeroconf_button()

	def run(self):
		with Context():
			width = 80
			height = 13
			padding = 3
			label_width = 10
			button_y = 11
			button_w = 14

			self.dialog = Dialog(x=1, y=1, w=width, h=height, title="opsi client agent installer")

			self.inputs["client_id"] = WDialogTextEntry(w=width-2*padding-label_width-1, text="")
			self.inputs["client_id"].on("changed", self._on_change)
			self.inputs["service_address"] = WDialogTextEntry(w=width-2*padding-label_width-1, text="")
			self.inputs["service_address"].on("changed", self._on_change)
			self.inputs["service_username"] = WDialogTextEntry(w=width-2*padding-label_width-1, text="")
			self.inputs["service_username"].on("changed", self._on_change)
			self.inputs["service_password"] = WDialogTextEntry(w=width-2*padding-label_width-1, text="")
			self.inputs["service_password"].password_char = "*"
			self.inputs["service_password"].on("changed", self._on_change)

			self.dialog.add(x=padding, y=2, widget=WLabel(w=label_width, text="Client-ID:"))
			self.dialog.add(x=padding+label_width+1, y=2, widget=self.inputs["client_id"])
			self.dialog.add(x=padding, y=3, widget=WLabel(w=label_width, text="Service:"))
			self.dialog.add(x=padding+label_width+1, y=3, widget=self.inputs["service_address"])
			self.dialog.add(x=padding, y=4, widget=WLabel(w=label_width, text="Username:"))
			self.dialog.add(x=padding+label_width+1, y=4, widget=self.inputs["service_username"])
			self.dialog.add(x=padding, y=5, widget=WLabel(w=label_width, text="Password:"))
			self.dialog.add(x=padding+label_width+1, y=5, widget=self.inputs["service_password"])

			self.message = WLabel(w=width-padding*2, text="")
			self.dialog.add(x=padding, y=8, widget=self.message)

			self.buttons["zeroconf"] = WButton(w=button_w, text="Zeroconf")
			self.dialog.add(x=padding, y=button_y, widget=self.buttons["zeroconf"])
			self.buttons["zeroconf"].on("click", self._on_zeroconf)

			self.buttons["cancel"] = WButton(w=button_w, text="Cancel")
			self.dialog.add(x=width-padding-button_w*2-1, y=button_y, widget=self.buttons["cancel"])
			self.buttons["cancel"].on("click", self._on_cancel)

			self.buttons["install"] = WButton(w=button_w, text="Install")
			self.dialog.add(x=width-padding-button_w, y=button_y, widget=self.buttons["install"])
			self.buttons["install"].on("click", self._on_install)

			self._redraw()
			Screen.set_screen_redraw(self._screen_redraw)

			while not self._closed:
				try:
					self.dialog.loop()
				except Exception as err:  # pylint: disable=broad-except
					logger.error(err, exc_info=True)
