"""
oca-installation-helper tests

test for utility functions
"""

import re

from ocainstallationhelper import (
	encode_password,
	decode_password,
	get_mac_address,
	get_resource_path,
	get_installed_oca_version,
	get_this_oca_version,
)


def test_encode_decode_password():
	text = r"asdf1234.,+-!'§$%&/()=?{[]}"
	assert text != encode_password(text)
	assert text == decode_password(encode_password(text))


def test_get_mac_address():
	address = get_mac_address()
	assert re.match("^" + r"[a-fA-F0-9]{2}:" * 5 + "[a-fA-F0-9]{2}$", address)


def test_get_resource_path():
	assert "oca-installation-helper" in get_resource_path(".")


def test_version_files():
	assert get_installed_oca_version() is None
	assert get_this_oca_version() is None
