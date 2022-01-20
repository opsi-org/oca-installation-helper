# -*- coding: utf-8 -*-

# opsiclientd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2010-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsi-client-agent installation_helper
"""

import os
import sys
import base64
import subprocess
import netifaces

from opsicommon.logging import logger

__version__ = "4.2.0.11"
KEY = "ahmaiweepheeVee5Eibieshai4tei7nohhochudae7show0phahmujai9ahk6eif"

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
	from subprocess import Popen as Popen_orig		# pylint: disable=import-outside-toplevel
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
	""" Get absolute path to resource, works for dev and for PyInstaller """
	try:
		# PyInstaller creates a temp folder and stores path in _MEIPASS
		base_path = sys._MEIPASS  # pylint: disable=protected-access,no-member
	except Exception:  # pylint: disable=broad-except
		base_path = os.path.abspath(".")

	return os.path.join(base_path, relative_path)

def get_mac_address():
	gateways = netifaces.gateways()  # pylint: disable=c-extension-no-member
	logger.debug("Gateways: %s", gateways)
	if not "default" in gateways:
		return None
	default_if = list(gateways["default"].values())[0][1]
	logger.info("Default interface: %s", default_if)
	addrs = netifaces.ifaddresses(default_if)  # pylint: disable=c-extension-no-member
	mac = addrs[netifaces.AF_LINK][0]["addr"]  # pylint: disable=c-extension-no-member
	logger.info("Default mac address: %s", mac)
	return mac
