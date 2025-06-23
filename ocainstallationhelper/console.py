# -*- coding: utf-8 -*-

# opsiclientd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2010-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsi-client-agent installation_helper console output component
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from textual.app import App, ComposeResult
from textual.containers import Container
from textual.widgets import Button, Input, Label

from ocainstallationhelper import Dialog as BaseDialog

if TYPE_CHECKING:
	from ocainstallationhelper.__main__ import InstallationHelper


class InputContainer(Container):
	DEFAULT_CSS = """
	InputContainer {
		height: 15;
		layout: grid;
		grid-size: 2 4;
		grid-gutter: 1 2;
		grid-columns: 18 1fr;
	}
	"""


class ButtonContainer(Container):
	DEFAULT_CSS = """
	ButtonContainer {
		height: 5;
		grid-size: 3 1;
		layout: grid;
		grid-gutter: 1 2;
	}
	"""


class PaddedLabel(Label):
	DEFAULT_CSS = """
	PaddedLabel {
		padding: 1;
		height: 3;
	}
	"""


class CenteredButton(Button):
	DEFAULT_CSS = """
	CenteredButton {
		width: 100%;
		content-align: center middle;
	}
	"""


class ConsoleDialog(BaseDialog, App):
	def __init__(self, installation_helper: InstallationHelper) -> None:
		App.__init__(self)
		self.inst_helper = installation_helper
		self.inputs: dict[str, Input] = {
			"client_id": Input(id="client_id"),
			"service_address": Input(id="service_address"),
			"service_username": Input(id="service_username"),
			"service_password": Input(id="service_password", password=True),
		}
		self.buttons: dict[str, CenteredButton] = {
			"zeroconf": CenteredButton("zeroconf", id="zeroconf"),
			"cancel": CenteredButton("cancel", id="cancel"),
			"install": CenteredButton("install", id="install"),
		}
		self.message: PaddedLabel = PaddedLabel("")
		self.log_path: PaddedLabel = PaddedLabel("")

	def compose(self) -> ComposeResult:
		yield InputContainer(
			PaddedLabel("Client-ID"),
			self.inputs["client_id"],
			PaddedLabel("Opsi Service url"),
			self.inputs["service_address"],
			PaddedLabel("Username"),
			self.inputs["service_username"],
			PaddedLabel("Password"),
			self.inputs["service_password"],
		)
		yield self.message
		yield ButtonContainer(self.buttons["zeroconf"], self.buttons["cancel"], self.buttons["install"])
		yield self.log_path

	def run_gui(self) -> None:
		self.run()

	def close(self) -> None:
		self._closed = True

	async def on_mount(self) -> None:
		assert self._loop, "Event loop not running"
		self._loop.create_task(self.inst_helper.prepare_installation())

	async def update_values(self) -> None:
		if not self.inputs:
			return
		for attr in ("client_id", "service_address", "service_username", "service_password"):
			if attr in self.inputs:
				self.inputs[attr].value = getattr(self.inst_helper.config, attr) or ""
				self.inputs[attr].refresh()
		await asyncio.sleep(0.05)  # forces idle event and gives time for widgets to handle it

	async def set_button_enabled(self, button_id: str, enabled: bool) -> None:
		self.buttons[button_id].disabled = not enabled
		await asyncio.sleep(0.05)  # forces idle event and gives time for widgets to handle it

	async def show_message(self, message: str, severity: Literal["normal", "error", "success"] = "normal") -> None:
		assert self.message
		if severity == "error":
			message = f"[red]{message}[/red]"
		elif severity == "success":
			message = f"[green]{message}[/green]"
		self.message.update(message)
		await asyncio.sleep(0.05)  # forces idle event and gives time for widgets to handle it

	async def show_log_path(self, log_path: Path | str | None) -> None:
		assert self.log_path
		self.log_path.update(f"See logs at: {log_path}")
		await asyncio.sleep(0.05)  # forces idle event and gives time for widgets to handle it

	async def on_button_pressed(self, event: Button.Pressed) -> None:
		if event.button is self.buttons["cancel"]:
			await self.inst_helper.on_cancel_button()
		elif event.button is self.buttons["install"]:
			await self.inst_helper.on_install_button()
		elif event.button is self.buttons["zeroconf"]:
			await self.inst_helper.on_zeroconf_button()

	async def on_input_changed(self, event: Input.Changed) -> None:
		setattr(self.inst_helper.config, event.input.id or "", event.value)
