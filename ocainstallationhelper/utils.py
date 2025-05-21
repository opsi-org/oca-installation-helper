# -*- coding: utf-8 -*-

# opsiclientd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2010-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsi-client-agent installation_helper
"""

from __future__ import annotations

import base64
import ipaddress
import os
import platform
import re
import socket
import sys
from pathlib import Path
from typing import Generator

import netifaces  # type: ignore[import]
import psutil

from . import KEY, POSIX_OCA_VERSION_FILE, THIS_OCA_VERSION_FILE, VERSION_PATTERN, WINDOWS_OCA_VERSION_FILE, logger


def encode_password(cleartext: str) -> str:
	cipher = ""
	for num, char in enumerate(cleartext):
		key_c = KEY[num % len(KEY)]
		cipher += chr((ord(char) + ord(key_c)) % 256)
	return base64.urlsafe_b64encode(cipher.encode("utf-8")).decode("ascii")


def decode_password(cipher: str) -> str:
	cipher = cipher.replace("{crypt}", "")
	cleartext = ""
	cipher = base64.urlsafe_b64decode(cipher).decode("utf-8")
	for num, char in enumerate(cipher):
		key_c = KEY[num % len(KEY)]
		cleartext += chr((ord(char) - ord(key_c) + 256) % 256)
	return cleartext


def get_resource_path(relative_path: str) -> str:
	"""Get absolute path to resource, works for dev and for PyInstaller"""
	try:
		# PyInstaller creates a temp folder and stores path in _MEIPASS
		base_path = getattr(sys, "_MEIPASS")
	except AttributeError:
		base_path = Path(".").absolute()

	return os.path.join(base_path, relative_path)


def get_mac_address() -> str | None:
	gateways = netifaces.gateways()
	logger.debug("Gateways: %s", gateways)
	if "default" not in gateways or not gateways["default"].values():
		return None
	default_if = list(gateways["default"].values())[0][1]
	logger.info("Default interface: %s", default_if)
	addrs = netifaces.ifaddresses(default_if)
	mac = addrs[netifaces.AF_LINK][0]["addr"]
	logger.info("Default mac address: %s", mac)
	return mac


def get_ip_interfaces() -> Generator[ipaddress.IPv4Interface | ipaddress.IPv6Interface, None, None]:
	for snics in psutil.net_if_addrs().values():
		for snic in snics:
			if snic.family not in (socket.AF_INET, socket.AF_INET6) or not snic.address or not snic.netmask:
				continue
			try:
				netmask = snic.netmask
				if ":" in netmask:
					yield ipaddress.ip_interface(f"{snic.address.split('%')[0]}/{netmask.lower().count('f') * 4}")
				else:
					yield ipaddress.ip_interface(f"{snic.address.split('%')[0]}/{netmask}")
			except ValueError:
				continue


def get_versionfile_content(version_file: Path) -> str | None:
	if not version_file.exists():
		return None
	content = version_file.read_text(encoding="utf-8")
	if re.search(VERSION_PATTERN, content):
		return content
	return None


def get_installed_oca_version() -> str | None:
	if platform.system().lower() == "windows":
		version_file = WINDOWS_OCA_VERSION_FILE
	elif platform.system().lower() in ("linux", "darwin"):
		version_file = POSIX_OCA_VERSION_FILE
	else:
		raise ValueError(f"Invalid system {platform.system()}")
	return get_versionfile_content(version_file)


def get_this_oca_version() -> str | None:
	return get_versionfile_content(THIS_OCA_VERSION_FILE)


def show_message(message: str, message_type: str = "stdout") -> None:
	# if platform.system().lower() == "windows":
	# from .gui import show_message as _show_message

	# _show_message(message)
	# else:
	if message_type == "stdout":
		sys.stdout.write(message)
	elif message_type == "stderr":
		sys.stderr.write(message)
	else:
		raise ValueError(f"Invalid type {message_type} for show_message")


def make_executable(path: Path) -> None:
	path.chmod(path.stat().st_mode | 0o111)
