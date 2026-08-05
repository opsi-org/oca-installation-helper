# This file is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2023-2026 uib GmbH <info@uib.de>
# This code is owned by the uib GmbH, Mainz, Germany (uib.de). All rights reserved.
# License: AGPL-3.0-only

"""
opsi-client-agent inst_helper gui component
"""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path
from platform import system
from tkinter import Message, StringVar, Text, Tk
from tkinter.ttk import Button, Entry, Frame, Label
from typing import TYPE_CHECKING, Literal

from opsi.logging import get_logger
from PIL import Image, ImageTk

from ocainstallationhelper import Dialog as BaseDialog

if TYPE_CHECKING:
	from ocainstallationhelper.__main__ import InstallationHelper

logger = get_logger("oca-installation-helper-gui")


class GUIDialog(BaseDialog, Tk):
	def __init__(self, inst_helper: InstallationHelper) -> None:
		Tk.__init__(self)
		icon = (Path(__file__).parent.parent / "opsi.ico").resolve()
		try:
			self.wm_iconphoto(True, ImageTk.PhotoImage(Image.open(str(icon))))  # ty: ignore[invalid-argument-type]
		except Exception as err:  # noqa: BLE001
			logger.warning("Could not set icon '%s': %s", icon, err)
		self.title("opsi-client-agent Installer")
		self.inst_helper = inst_helper
		self.width = 600
		self.height = 300
		self.padding = 10
		if system().lower() != "windows":
			self.attributes("-type", "dialog")
		self.content = Frame(self, width=self.width, height=self.height, border=10, relief="groove")
		self.string_vars: dict[str, StringVar] = {
			"client_id": StringVar(name="client_id"),
			"service_address": StringVar(name="service_address"),
			"service_username": StringVar(name="service_username"),
			"service_password": StringVar(name="service_password"),
		}
		self.inputs: dict[str, Entry] = {
			"client_id": Entry(self.content, textvariable=self.string_vars["client_id"]),
			"service_address": Entry(self.content, textvariable=self.string_vars["service_address"]),
			"service_username": Entry(self.content, textvariable=self.string_vars["service_username"]),
			"service_password": Entry(self.content, show="*", textvariable=self.string_vars["service_password"]),
		}

		def on_input_changed(var: str, index: str, mode: str) -> None:
			setattr(self.inst_helper.config, var, self.string_vars[var].get())

		for string_var in self.string_vars.values():
			string_var.trace_add("write", on_input_changed)
		self.buttons: dict[str, Button] = {
			"zeroconf": self._make_button("zeroconf"),
			"cancel": self._make_button("cancel"),
			"install": self._make_button("install"),
			"open_logs": self._make_button("open_logs", "open logs", disabled=True),
		}
		self.message: Message = Message(self.content, width=self.width - 2 * self.padding, anchor="w")
		self.relevant_log_file: str = ""
		self._set_geometry()
		self._build()
		self._loop = asyncio.get_event_loop()

	def _make_button(self, button_id: str, button_text: str | None = None, disabled: bool = False) -> Button:
		def on_button_click(button_id: str = button_id) -> None:
			self.on_button_pressed(button_id)

		button = Button(
			self.content,
			text=button_text or button_id,
			style="Accent.TButton",
			width=10,
			command=on_button_click,
		)
		if disabled:
			button.config(state="disabled")
		return button

	def _set_geometry(self) -> None:
		screen_width = self.winfo_screenwidth()
		screen_height = self.winfo_screenheight()

		taskbar_height = 0 if system().lower() != "windows" else self.winfo_rooty()
		left = int((screen_width - self.width) / 2)
		top = int((screen_height - taskbar_height - self.height) / 2)

		self.geometry(f"{self.width}x{self.height}+{left}+{top}")

	def _build(self) -> None:
		self.columnconfigure(0, weight=1)
		self.rowconfigure(0, weight=1)
		self.content.grid(column=0, row=0, sticky="nsew")

		self.content.columnconfigure(list(range(4)), weight=1)
		self.content.rowconfigure(list(range(7)), weight=1)

		Label(self.content, text="Client ID").grid(column=0, row=0)
		self.inputs["client_id"].grid(column=1, row=0, columnspan=3, sticky="we", padx=self.padding)
		Label(self.content, text="Opsi Service url").grid(column=0, row=1)
		self.inputs["service_address"].grid(column=1, row=1, columnspan=3, sticky="we", padx=self.padding)
		Label(self.content, text="Username (on Config Server)").grid(column=0, row=2)
		self.inputs["service_username"].grid(column=1, row=2, columnspan=3, sticky="we", padx=self.padding)
		Label(self.content, text="Password").grid(column=0, row=3)
		self.inputs["service_password"].grid(column=1, row=3, columnspan=3, sticky="we", padx=self.padding)

		self.message.grid(column=0, row=4, columnspan=4, sticky="we", padx=self.padding)
		self.buttons["zeroconf"].grid(column=0, row=5)
		self.buttons["cancel"].grid(column=1, row=5)
		self.buttons["install"].grid(column=2, row=5)
		self.buttons["open_logs"].grid(column=3, row=5)

	def on_button_pressed(self, button_name: str) -> None:
		if button_name == "cancel":
			self._loop.run_until_complete(self.inst_helper.on_cancel_button())
		elif button_name == "install":
			self._loop.run_until_complete(self.inst_helper.on_install_button())
		elif button_name == "zeroconf":
			self._loop.run_until_complete(self.inst_helper.on_zeroconf_button())
		elif button_name == "open_logs":
			self.open_logs()

	def run_gui(self) -> None:
		assert self._loop, "Event loop not running"
		self._loop.run_until_complete(self.inst_helper.prepare_installation())
		# asyncio.run(self.inst_helper.prepare_installation())
		self.mainloop()

	def close(self) -> None:
		logger.notice("Stopping oca installation helper gui")
		self.after(200, self.quit)

	async def update_values(self) -> None:
		for attr in ("client_id", "service_address", "service_username", "service_password"):
			if attr in self.inputs:
				self.string_vars[attr].set(getattr(self.inst_helper.config, attr) or "")

	async def set_button_enabled(self, button: str, state: bool) -> None:
		if button not in self.buttons:
			raise ValueError(f"Button {button} not found")
		self.buttons[button].config(state="normal" if state else "disabled")

	async def show_message(self, message: str, severity: Literal["normal", "error", "success"] = "normal") -> None:
		try:
			color = "black"
			if severity == "error":
				color = "red"
			elif severity == "success":
				color = "green"
			self.message.config(text=message, foreground=color)
			self.message.update()
		except Exception as err:  # noqa: BLE001
			logger.error("Error showing message: %s", err)

	async def show_logpath(self, logpath: Path | str | None) -> None:
		self.relevant_log_file = str(logpath) if logpath else ""
		await self.set_button_enabled("open_logs", bool(logpath))

	def open_logs(self) -> None:
		if system().lower() == "darwin":
			subprocess.Popen(("open", self.relevant_log_file))
		elif system().lower() == "windows":
			subprocess.Popen(("notepad.exe", self.relevant_log_file))
		else:
			subprocess.Popen(("xdg-open", self.relevant_log_file))


def show_message(message: str, severity: Literal["normal", "error", "success"] = "normal") -> None:
	"""
	Show a message in a GUI dialog.
	:param message: The message to show.
	:param severity: The severity of the message, can be "normal", "error", or "success".
	"""
	window = Tk()
	msg = Text(window, wrap="word", height=10, width=50)
	msg.insert("1.0", message)
	if severity == "error":
		msg.config(fg="red")
	elif severity == "success":
		msg.config(fg="green")
	msg.pack(padx=20, pady=20)
	window.title("Message")
	window.geometry("400x200")
	window.mainloop()  # Start the GUI event loop
	logger.info("Message dialog closed")
