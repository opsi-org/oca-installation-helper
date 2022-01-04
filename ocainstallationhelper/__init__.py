# -*- coding: utf-8 -*-

# opsiclientd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2010-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

import os
import sys
import logging

__version__ = "4.2.0.10"

logger = logging
logger.notice = logger.info

def get_resource_path(relative_path):
	""" Get absolute path to resource, works for dev and for PyInstaller """
	try:
		# PyInstaller creates a temp folder and stores path in _MEIPASS
		base_path = sys._MEIPASS  # pylint: disable=protected-access,no-member
	except Exception:  # pylint: disable=broad-except
		base_path = os.path.abspath(".")

	return os.path.join(base_path, relative_path)
