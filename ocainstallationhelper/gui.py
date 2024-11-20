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
import tkinter as tk
from platform import system
from threading import Event
from tkinter import N, Tk, Toplevel
from tkinter.ttk import Button, Frame
from typing import TYPE_CHECKING, Any, Callable, Literal

from opsicommon.logging import get_logger
from pydantic import BaseModel

from ocainstallationhelper import Dialog as BaseDialog

if TYPE_CHECKING:
	from ocainstallationhelper.__main__ import InstallationHelper

logger = get_logger("oca-installation-helper-gui")


class OCAIHWindowModel(BaseModel):
	title: str = "Nachricht"
	width: int = 800
	height: int = 500
	pos_x: str = "center"
	pos_y: str = "center"
	resizable: bool = True
	frameless: bool = False
	stay_on_top: bool = False
	message_title: str = ""
	message_text: str = ""
	message_format: Literal["plain", "markdown", "html"] = "markdown"
	button_texts: list[str] | None = None
	button_callback: Callable | None = None

	def __setattr__(self, attribute: str, value: Any) -> None:
		if value == getattr(self, attribute, None):
			return
		super().__setattr__(attribute, value)
		if not (field := self.model_fields.get(attribute)) or field.exclude:
			return


class MessageWindow(Toplevel):
	_fade_step = 0.05

	def __init__(
		self,
		master: Tk | Toplevel,
		model: OCAIHWindowModel,
	) -> None:
		self._ignore_model_changes = True
		super().__init__(master)
		self._model = model
		self._alpha = 0.0
		self._hidden = Event()
		self._set_visible(False)
		self.set_model(model)
		self._ignore_model_changes = False

	def ignore_model_changes(self, duration: int = 100) -> None:
		self._ignore_model_changes = True
		self.after(duration, lambda: setattr(self, "_ignore_model_changes", False))

	def get_model(self) -> OCAIHWindowModel:
		return self._model

	def set_model(self, model: OCAIHWindowModel) -> None:
		self._model = model
		self._build()
		self._apply_changed_model()

	def _model_changed(self, model: OCAIHWindowModel) -> None:
		if self._ignore_model_changes:
			return
		self.after(1, self._apply_changed_model)

	def _set_alpha(self, alpha: float) -> None:
		self._alpha = min(max(alpha, 0.0), 1.0)
		self.attributes("-alpha", self._alpha)

	def _set_visible(self, visible: bool) -> None:
		if visible:
			self.deiconify()
			self._set_alpha(1.0)
			self._hidden.clear()
		else:
			self._set_alpha(0.0)
			self.withdraw()
			self._hidden.set()

	def bring_to_top(self) -> None:
		self.attributes("-topmost", True)
		self.lift()
		self.focus_force()
		if not self._model.stay_on_top:
			self.after(1, self.attributes, "-topmost", False)

	def show(self, bring_to_top: bool = False) -> None:
		if bring_to_top:
			self.bring_to_top()
		self._hidden.clear()
		self.after(100, self._set_visible, True)

	def hide(self) -> None:
		self._set_visible(False)

	def is_visible(self) -> bool:
		return not self._hidden.is_set()

	def _set_geometry(self) -> None:
		screen_width = self.winfo_screenwidth()
		screen_height = self.winfo_screenheight()

		# TODO
		taskbar_height = 30
		if system().lower() == "windows":
			taskbar_height = self.winfo_rooty()

		left = 0
		if self._model.pos_x:
			if self._model.pos_x == "left":
				left = 0
			elif self._model.pos_x == "right":
				left = screen_width - self._model.width - 1
			elif self._model.pos_x == "center":
				left = int((screen_width - self._model.width) / 2)

		top = 0
		if self._model.pos_y:
			if self._model.pos_y == "bottom":
				top = screen_height - self._model.height - 1
			elif self._model.pos_y == "bottom_bar":
				top = screen_height - taskbar_height - self._model.height - 1
			elif self._model.pos_y == "top":
				top = 0
			elif self._model.pos_y == "center":
				top = int((screen_height - taskbar_height - self._model.height) / 2)

		self.geometry(f"{self._model.width}x{self._model.height}+{left}+{top}")

	def _apply_changed_model(self) -> None:
		self.title(self._model.title)
		self.resizable(width=self._model.resizable, height=self._model.resizable)
		if self._model.frameless != bool(self.overrideredirect()):
			visible = self.is_visible()
			if visible:
				self.withdraw()
			self.overrideredirect(self._model.frameless)
			if visible:
				self.deiconify()
		self.attributes("-topmost", self._model.stay_on_top)
		if self._model.stay_on_top:
			self.bring_to_top()
		self._set_geometry()
		self._setup_buttons()

	def _build(self) -> None:
		self.grid_rowconfigure(4, weight=1)
		self.grid_columnconfigure(2, weight=1)
		self._content_frame = Frame(self, name="content", borderwidth=0)
		self._content_frame.grid(row=4, column=0, padx=10, pady=10, sticky=N)
		self._setup_buttons()

	def _setup_buttons(self) -> None:
		for widget in self._content_frame.winfo_children():
			widget.destroy()

		for index, button_text in enumerate(self._model.button_texts or []):

			def on_button_click(button_name: str = button_text) -> None:
				if self._model.button_callback:
					self._model.button_callback(button_name)

			greeting = tk.Label(text=button_text)
			greeting.grid(row=index, column=0, padx=10, pady=10, sticky=N)
			button = Button(
				self._content_frame,
				text=button_text,
				style="Accent.TButton",
				width=10,
				command=on_button_click,
			)
			button.grid(row=index, column=1, padx=10, pady=10, sticky=N)


class GUIDialog(BaseDialog):
	def __init__(self, installation_helper: InstallationHelper) -> None:
		self._app = tk.Toplevel()
		self._app.overrideredirect(True)
		self._app.withdraw()
		self.inst_helper = installation_helper

		self.model = OCAIHWindowModel(button_texts=["zeroconf", "cancel", "install"], button_callback=self.on_button_pressed)
		self.window = MessageWindow(self._app, model=self.model)

	def run(self) -> None:
		self.window.show(bring_to_top=True)
		self._app.mainloop()

	def close(self) -> None:
		logger.notice("Stopping oca installation helper gui")
		self.window.hide()
		self._app.after(300, self._app.quit)

	def on_button_pressed(self, button_name: str) -> None:
		if button_name == "cancel":
			asyncio.run(self.inst_helper.on_cancel_button())
		elif button_name == "install":
			asyncio.run(self.inst_helper.on_install_button())
		elif button_name == "zeroconf":
			asyncio.run(self.inst_helper.on_zeroconf_button())
