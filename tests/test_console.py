# This file is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2023-2025 uib GmbH <info@uib.de>
# This code is owned by the uib GmbH, Mainz, Germany (uib.de). All rights reserved.
# License: AGPL-3.0-only

import asyncio
import platform
from pathlib import Path
from unittest.mock import patch

import pytest
from rich.text import Text

import ocainstallationhelper.console
from ocainstallationhelper import logger

from .utils import get_installation_helper

caller_log = []


async def fake_async(self) -> None:  # type: ignore[no-untyped-def]
	global caller_log
	caller_log.append(self.__class__.__name__)


has_exit_been_called = False


def fake_exit(code: int) -> None:
	global has_exit_been_called
	has_exit_been_called = True


@pytest.mark.asyncio
async def test_cancel_button() -> None:
	global has_exit_been_called
	has_exit_been_called = False
	with (
		get_installation_helper() as installation_helper,
		patch("ocainstallationhelper.console.ConsoleDialog.on_mount", fake_async),
		patch("ocainstallationhelper.__main__.sys.exit", fake_exit),
	):
		app = ocainstallationhelper.console.ConsoleDialog(installation_helper)
		async with app.run_test() as pilot:
			await pilot.click("#cancel")
			assert has_exit_been_called


@pytest.mark.asyncio
async def test_install_button() -> None:
	global caller_log
	caller_log = []
	with (
		patch("ocainstallationhelper.console.ConsoleDialog.on_mount", fake_async),
		get_installation_helper() as installation_helper,
		patch("tests.utils.InstallationHelper.install", fake_async),
	):
		app = ocainstallationhelper.console.ConsoleDialog(installation_helper)
		installation_helper.dialog = app
		async with app.run_test() as pilot:
			await pilot.click("#install")
			# await pilot.pause()  # should wait until all message have been processed, but runs into timeout
			await asyncio.sleep(5.5)
			logger.devel("Checking for closed app")
			assert app._closed  # install calls close at the end


@pytest.mark.asyncio
async def test_update() -> None:
	with (
		patch("ocainstallationhelper.console.ConsoleDialog.on_mount", fake_async),
		get_installation_helper(
			["--client-id", "client.domain.local", "--service-address", "https://server.domain.local:4447"]
		) as installation_helper,
	):
		app = ocainstallationhelper.console.ConsoleDialog(installation_helper)
		installation_helper.dialog = app
		async with app.run_test():
			assert app.inputs["client_id"].value == ""
			assert app.inputs["service_address"].value == ""
			await app.update_values()
			assert app.inputs["client_id"].value == "client.domain.local"
			assert app.inputs["service_address"].value == "https://server.domain.local:4447"


@pytest.mark.asyncio
async def test_show_message_log_path() -> None:
	with (
		patch("ocainstallationhelper.console.ConsoleDialog.on_mount", fake_async),
		get_installation_helper() as installation_helper,
	):
		app = ocainstallationhelper.console.ConsoleDialog(installation_helper)
		async with app.run_test():
			assert app.message.renderable == ""

			await app.show_message("foo", severity="error")
			assert isinstance(app.message.renderable, Text)
			assert app.message.renderable._text == ["foo"]
			assert app.message.renderable._spans[0].style == "red"

			await app.show_message("bar", severity="success")
			assert app.message.renderable._text == ["bar"]
			assert app.message.renderable._spans[0].style == "green"

			await app.show_message("baz")
			assert app.message.renderable._text == ["baz"]
			assert not app.message.renderable._spans

			assert app.log_path.renderable == ""
			await app.show_log_path(Path("/tmp/foo.log"))
			assert isinstance(app.log_path.renderable, Text)
			checkstring = "See logs at: /tmp/foo.log"
			if platform.system().lower() == "windows":
				checkstring = checkstring.replace("/", "\\")
			assert app.log_path.renderable._text == [checkstring]


@pytest.mark.asyncio
async def test_on_input_changed() -> None:
	with (
		patch("ocainstallationhelper.console.ConsoleDialog.on_mount", fake_async),
		get_installation_helper() as installation_helper,
	):
		app = ocainstallationhelper.console.ConsoleDialog(installation_helper)
		async with app.run_test() as pilot:
			assert installation_helper.config.service_address is None
			await pilot.click("#service_address")
			await pilot.press(*(key for key in "https://server.domain.local:4447"))
			assert installation_helper.config.service_address == "https://server.domain.local:4447"
