import asyncio
from unittest.mock import patch

import pytest

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
async def test_cancel() -> None:
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
async def test_install() -> None:
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
