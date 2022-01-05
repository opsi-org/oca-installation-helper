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
import logging
import subprocess

__version__ = "4.2.0.11"

logger = logging
logger.notice = logger.info

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
