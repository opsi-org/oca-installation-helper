# This file is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2023-2025 uib GmbH <info@uib.de>
# This code is owned by the uib GmbH, Mainz, Germany (uib.de). All rights reserved.
# License: AGPL-3.0-only

"""
opsi-client-agent installation_helper
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from opsicommon.logging import get_logger

if TYPE_CHECKING:
	from ocainstallationhelper.__main__ import InstallationHelper

__version__ = "4.3.3.4"


KEY = "ahmaiweepheeVee5Eibieshai4tei7nohhochudae7show0phahmujai9ahk6eif"
THIS_OCA_VERSION_FILE = Path("files/opsi-client-agent.version")
WINDOWS_OCA_VERSION_FILE = Path(os.path.expandvars("%programfiles%")) / "opsi.org" / "opsi-client-agent" / "opsi-client-agent.version"
POSIX_OCA_VERSION_FILE = Path("/etc/opsi-client-agent/opsi-client-agent.version")
VERSION_PATTERN = re.compile(r"[0-9.]+-[0-9.~]+")
CONFIG_CACHE_DIRS = {
	"windows": Path("c:\\opsi.org\\cache\\config"),
	"linux": Path("/var/cache/opsi-client-agent/config"),
	"darwin": Path("/var/cache/opsi-client-agent/config"),
}
logger = get_logger("oca-installation-helper")


class Dialog:
	def __init__(self, installation_helper: InstallationHelper) -> None:
		pass

	async def update_values(self) -> None:
		raise NotImplementedError("Methods of Dialog must be implemented by subclass")

	async def set_button_enabled(self, button: str, state: bool) -> None:
		raise NotImplementedError("Methods of Dialog must be implemented by subclass")

	async def show_message(self, message: str, severity: Literal["normal", "error", "success"]) -> None:
		raise NotImplementedError("Methods of Dialog must be implemented by subclass")

	async def show_logpath(self, logpath: Path | str | None) -> None:
		raise NotImplementedError("Methods of Dialog must be implemented by subclass")

	def close(self) -> None:
		raise NotImplementedError("Methods of Dialog must be implemented by subclass")

	def run_gui(self) -> None:
		raise NotImplementedError("Methods of Dialog must be implemented by subclass")
