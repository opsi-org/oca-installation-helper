# -*- coding: utf-8 -*-

# opsiclientd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2010-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsi-client-agent installation_helper gui component
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from platform import system
from tkinter import Toplevel
from tkinter.ttk import Button, Entry, Frame, Label
from typing import TYPE_CHECKING

from opsicommon.logging import get_logger

from ocainstallationhelper import Dialog as BaseDialog

if TYPE_CHECKING:
	from ocainstallationhelper.__main__ import InstallationHelper

logger = get_logger("oca-installation-helper-gui")


class GUIDialog(BaseDialog, Toplevel):
	def __init__(self, installation_helper: InstallationHelper) -> None:
		Toplevel.__init__(None)
		self.installation_helper = installation_helper
		self.width = 800
		self.height = 500
		self.content = Frame(self)

		self.inputs: dict[str, Entry] = {
			"client_id": Entry(self.content),
			"service_address": Entry(self.content),
			"service_username": Entry(self.content),
			"service_password": Entry(self.content),  # TODO: password protection
		}
		self.buttons: dict[str, Button] = {
			"zeroconf": self._make_button("zeroconf"),
			"cancel": self._make_button("cancel"),
			"install": self._make_button("install"),
			"open_logs": self._make_button("open_logs", "open logs"),
		}
		self.message: Label = Label(self.content, text="")
		self.logpath: Label = Label(self.content, text="")
		self._build()

	def _make_button(self, button_id: str, button_text: str | None = None) -> Button:
		def on_button_click(button_id: str = button_id) -> None:
			self.on_button_pressed(button_id)

		return Button(
			self.content,
			text=button_text or button_id,
			style="Accent.TButton",
			width=10,
			command=on_button_click,
		)

	def _set_geometry(self) -> None:
		screen_width = self.winfo_screenwidth()
		screen_height = self.winfo_screenheight()

		taskbar_height = 0  # TODO
		if system().lower() == "windows":
			taskbar_height = self.winfo_rooty()

		left = int((screen_width - self.width) / 2)
		top = int((screen_height - taskbar_height - self.height) / 2)

		self.geometry(f"{self.width}x{self.height}+{left}+{top}")

	def _build(self) -> None:
		self.content.grid(column=0, row=0)

		Label(self.content, text="Client ID").grid(column=0, row=0)
		self.inputs["client_id"].grid(column=1, row=0)
		Label(self.content, text="Opsi Service url").grid(column=0, row=1)
		self.inputs["service_address"].grid(column=1, row=1)
		self.buttons["zeroconf"].grid(column=2, row=1)
		Label(self.content, text="Username").grid(column=0, row=2)
		self.inputs["service_username"].grid(column=1, row=2)
		Label(self.content, text="Password").grid(column=0, row=3)
		self.inputs["service_password"].grid(column=1, row=3)

		self.message.grid(column=0, row=4)
		self.buttons["cancel"].grid(column=0, row=5)
		self.buttons["install"].grid(column=1, row=5)
		self.buttons["open_logs"].grid(column=0, row=6)
		self.logpath.grid(column=1, row=6)

	def on_button_pressed(self, button_name: str) -> None:
		if button_name == "cancel":
			asyncio.run(self.installation_helper.on_cancel_button())
		elif button_name == "install":
			asyncio.run(self.installation_helper.on_install_button())
		elif button_name == "zeroconf":
			asyncio.run(self.installation_helper.on_zeroconf_button())

	def run_gui(self) -> None:
		self.mainloop()

	def close(self) -> None:
		logger.notice("Stopping oca installation helper gui")
		self.after(200, self.quit)

	async def update(self) -> None:
		raise NotImplementedError("todo")

	async def set_button_enabled(self, button: str, state: bool) -> None:
		raise NotImplementedError("todo")

	async def show_message(self, message: str, severity: str | None) -> None:
		if severity == "error":
			message = f"[red]{message}[/red]"
		elif severity == "success":
			message = f"[green]{message}[/green]"
		self.message.config(text=message)
		self.message.update()

	async def show_logpath(self, logpath: Path | str | None) -> None:
		self.logpath.config(text=f"See logs at: {logpath}")
		self.logpath.update()
