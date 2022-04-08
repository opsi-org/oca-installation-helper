# -*- coding: utf-8 -*-

# opsiclientd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2010-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsi-client-agent installation_helper
"""

import base64
import ipaddress
import os
import platform
import re
import socket
import subprocess
import sys
from pathlib import Path
from typing import Generator, Union

import netifaces  # type: ignore[import]
import psutil
from opsicommon.logging import logger  # type: ignore[import]

__version__ = "4.2.0.17"
KEY = "ahmaiweepheeVee5Eibieshai4tei7nohhochudae7show0phahmujai9ahk6eif"
THIS_OCA_VERSION_FILE = Path("files/opsi-client-agent.version")
WINDOWS_OCA_VERSION_FILE = Path(os.path.expandvars("%programfiles%")) / "opsi.org" / "opsi-client-agent" / "opsi-client-agent.version"
POSIX_OCA_VERSION_FILE = Path("/etc/opsi-client-agent/opsi-client-agent.version")
VERSION_PATTERN = re.compile(r"[0-9.]+-[0-9.~]+")


def encode_password(cleartext):
	cipher = ""
	for num, char in enumerate(cleartext):
		key_c = KEY[num % len(KEY)]
		cipher += chr((ord(char) + ord(key_c)) % 256)
	return base64.urlsafe_b64encode(cipher.encode("utf-8")).decode("ascii")


def decode_password(cipher):
	cipher = cipher.replace("{crypt}", "")
	cleartext = ""
	cipher = base64.urlsafe_b64decode(cipher).decode("utf-8")
	for num, char in enumerate(cipher):
		key_c = KEY[num % len(KEY)]
		cleartext += chr((ord(char) - ord(key_c) + 256) % 256)
	return cleartext


def monkeypatch_subprocess_for_frozen():
	from subprocess import Popen as Popen_orig  # pylint: disable=import-outside-toplevel

	class PopenPatched(Popen_orig):
		def __init__(self, *args, **kwargs):
			if kwargs.get("env") is None:
				kwargs["env"] = os.environ.copy()
			lp_orig = kwargs["env"].get("LD_LIBRARY_PATH_ORIG")
			if lp_orig is not None:
				# Restore the original, unmodified value
				kwargs["env"]["LD_LIBRARY_PATH"] = lp_orig
			else:
				# This happens when LD_LIBRARY_PATH was not set.
				# Remove the env var as a last resort
				kwargs["env"].pop("LD_LIBRARY_PATH", None)

			super().__init__(*args, **kwargs)

	subprocess.Popen = PopenPatched


def get_resource_path(relative_path):
	"""Get absolute path to resource, works for dev and for PyInstaller"""
	try:
		# PyInstaller creates a temp folder and stores path in _MEIPASS
		base_path = sys._MEIPASS  # pylint: disable=protected-access,no-member
	except Exception:  # pylint: disable=broad-except
		base_path = Path(".").absolute()

	return os.path.join(base_path, relative_path)


def get_mac_address():
	gateways = netifaces.gateways()  # pylint: disable=c-extension-no-member
	logger.debug("Gateways: %s", gateways)
	if "default" not in gateways:
		return None
	default_if = list(gateways["default"].values())[0][1]
	logger.info("Default interface: %s", default_if)
	addrs = netifaces.ifaddresses(default_if)  # pylint: disable=c-extension-no-member
	mac = addrs[netifaces.AF_LINK][0]["addr"]  # pylint: disable=c-extension-no-member
	logger.info("Default mac address: %s", mac)
	return mac


def get_ip_interfaces() -> Generator[Union[ipaddress.IPv4Interface, ipaddress.IPv6Interface], None, None]:
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


def get_versionfile_content(version_file):
	if not version_file.exists():
		return None
	content = version_file.read_text(encoding="utf-8")
	if re.search(VERSION_PATTERN, content):
		return content
	return None


def get_installed_oca_version():
	if platform.system().lower() == "windows":
		version_file = WINDOWS_OCA_VERSION_FILE
	elif platform.system().lower() in ("linux", "darwin"):
		version_file = POSIX_OCA_VERSION_FILE
	else:
		raise ValueError(f"Invalid system {platform.system()}")
	return get_versionfile_content(version_file)


def get_this_oca_version():
	return get_versionfile_content(THIS_OCA_VERSION_FILE)


def show_message(message: str, message_type: str = "stdout") -> None:
	if platform.system().lower() == "windows":
		from .gui import show_message as _show_message  # pylint: disable=import-outside-toplevel

		_show_message(message)
	else:
		if message_type == "stdout":
			sys.stdout.write(message)
		elif message_type == "stderr":
			sys.stdout.write(message)
		else:
			raise ValueError(f"Invalid type {message_type} for show_message")
