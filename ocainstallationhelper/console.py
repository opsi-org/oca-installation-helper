# -*- coding: utf-8 -*-

# opsiclientd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2010-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsi-client-agent installation_helper console output component
"""

from __future__ import annotations

import platform
import signal
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from picotui.context import Context
from picotui.menu import Screen
from picotui.widgets import C_BLACK, C_WHITE, Dialog, WButton, Widget, WLabel, WTextEntry

from ocainstallationhelper import Dialog as BaseDialog
from ocainstallationhelper import get_logger

if TYPE_CHECKING:
	from ocainstallationhelper.__main__ import InstallationHelper


logger = get_logger()


class WDialogTextEntry(WTextEntry):
	def __init__(self, w: int, text: str) -> None:
		self.password_char = None
		super().__init__(w, text)

	def handle_edit_key(self, key: int | None) -> Any:
		res = None
		if key is not None:
			res = super().handle_edit_key(key)
		self.signal("changed")
		return res

	def show_line(self, l: str | None, i: int) -> None:  # noqa: E741
		if l is None:
			l = ""  # noqa: E741
		self.attr_color(C_BLACK, C_WHITE)
		l = l[self.margin :]  # noqa: E741
		l = l[: self.width]  # noqa: E741
		if self.password_char is not None:
			l = self.password_char * len(l)  # noqa: E741
		self.wr(l)
		self.clear_num_pos(self.width - len(l))
		self.attr_reset()


class ConsoleDialog(BaseDialog):
	def __init__(self, installation_helper: InstallationHelper) -> None:
		threading.Thread.__init__(self)
		self.daemon = True
		self.inst_helper = installation_helper
		self.inputs: dict[str, WTextEntry] = {}
		self.buttons: dict[str, WButton] = {}
		self._closed = False
		self.dialog: Dialog | None = None
		self.message: WLabel | None = None
		self.logpath: WLabel | None = None
		if platform.system().lower() != "windows":
			signal.signal(signal.SIGWINCH, self._sigwinch_handler)

	def show(self) -> None:
		self.start()
		time.sleep(1)

	def close(self) -> None:
		self._closed = True
		Screen.goto(0, 50)
		Screen.cursor(True)
		Screen.deinit_tty()
		print()

	def wait(self) -> None:
		self.join()

	def update(self) -> None:
		if not self.inputs:
			return
		for attr in ("client_id", "service_address", "service_username", "service_password"):
			if attr in self.inputs:
				self.inputs[attr].set(getattr(self.inst_helper.config, attr) or "")
		self._redraw()

	def set_button_enabled(self, button_id: str, enabled: bool) -> None:
		self.buttons[button_id].disabled = not enabled
		self._redraw()

	def show_message(self, message: str, severity: str | None = None) -> None:
		assert self.message
		self.message.t = message
		self._redraw()

	def show_logpath(self, logpath: Path | str | None) -> None:
		assert self.logpath
		self.logpath.t = f"See logs at: {logpath}"
		self._redraw()

	def _sigwinch_handler(self, *args: Any) -> None:
		self._redraw()

	def _redraw(self) -> None:
		try:
			self._screen_redraw(Screen)
		except Exception:
			pass

	def _screen_redraw(self, screen: Screen, allow_cursor: bool = False) -> None:
		assert self.dialog
		# screen.attr_color(C_WHITE, C_BLUE)
		screen.cls()
		screen.attr_reset()
		self.dialog.redraw()

	def _on_change(self, _widget: Widget) -> None:
		for attr in ("client_id", "service_address", "service_username", "service_password"):
			setattr(self.inst_helper.config, attr, self.inputs[attr].get())

	def _on_cancel(self, _widget: Widget) -> None:
		self.inst_helper.on_cancel_button()

	def _on_install(self, _widget: Widget) -> None:
		self.inst_helper.on_install_button()

	def _on_zeroconf(self, _widget: Widget) -> None:
		self.inst_helper.on_zeroconf_button()

	def _run(self) -> None:
		width = 80
		height = 14
		padding = 3
		label_width = 18
		button_y = 11
		button_w = 14

		self.dialog = Dialog(x=1, y=1, w=width, h=height, title="opsi client agent installer")
		assert self.dialog

		self.inputs["client_id"] = WDialogTextEntry(w=width - 2 * padding - label_width - 1, text="")
		self.inputs["client_id"].on("changed", self._on_change)
		self.inputs["service_address"] = WDialogTextEntry(w=width - 2 * padding - label_width - 1, text="")
		self.inputs["service_address"].on("changed", self._on_change)
		self.inputs["service_username"] = WDialogTextEntry(w=width - 2 * padding - label_width - 1, text="")
		self.inputs["service_username"].on("changed", self._on_change)
		self.inputs["service_password"] = WDialogTextEntry(w=width - 2 * padding - label_width - 1, text="")
		self.inputs["service_password"].password_char = "*"
		self.inputs["service_password"].on("changed", self._on_change)

		self.dialog.add(x=padding, y=2, widget=WLabel(w=label_width, text="Client-ID:"))
		self.dialog.add(x=padding + label_width + 1, y=2, widget=self.inputs["client_id"])
		self.dialog.add(x=padding, y=3, widget=WLabel(w=label_width, text="Opsi Service url:"))
		self.dialog.add(x=padding + label_width + 1, y=3, widget=self.inputs["service_address"])
		self.dialog.add(x=padding, y=4, widget=WLabel(w=label_width, text="Username:"))
		self.dialog.add(x=padding + label_width + 1, y=4, widget=self.inputs["service_username"])
		self.dialog.add(x=padding, y=5, widget=WLabel(w=label_width, text="Password:"))
		self.dialog.add(x=padding + label_width + 1, y=5, widget=self.inputs["service_password"])

		self.message = WLabel(w=width - padding * 2, text="")
		self.dialog.add(x=padding, y=8, widget=self.message)

		self.buttons["zeroconf"] = WButton(w=button_w, text="Zeroconf")
		self.dialog.add(x=padding, y=button_y, widget=self.buttons["zeroconf"])
		self.buttons["zeroconf"].on("click", self._on_zeroconf)

		self.buttons["cancel"] = WButton(w=button_w, text="Cancel")
		self.dialog.add(x=width - padding - button_w * 2 - 1, y=button_y, widget=self.buttons["cancel"])
		self.buttons["cancel"].on("click", self._on_cancel)

		self.buttons["install"] = WButton(w=button_w, text="Install")
		self.dialog.add(x=width - padding - button_w, y=button_y, widget=self.buttons["install"])
		self.buttons["install"].on("click", self._on_install)

		self.logpath = WLabel(w=width - padding * 2, text="")
		self.dialog.add(x=padding, y=12, widget=self.logpath)

		self._redraw()
		Screen.set_screen_redraw(self._screen_redraw)

		# Not using Dialog.loop, as it loops forever
		while not self._closed:
			key = self.dialog.get_input()
			res = self.dialog.handle_input(key)
			if res is not None and res is not True:
				break

	def run(self) -> None:
		try:
			with Context():
				return self._run()
		except Exception as err:
			logger.error(err, exc_info=True)
			raise
