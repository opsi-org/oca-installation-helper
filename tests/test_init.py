"""
oca-installation-helper tests

test for utility functions
"""

import re

from ocainstallationhelper import (
	decode_password,
	encode_password,
	get_installed_oca_version,
	get_mac_address,
	get_resource_path,
	get_this_oca_version,
)


def test_encode_decode_password() -> None:
	text = r"asdf1234.,+-!'§$%&/()=?{[]}"
	assert text != encode_password(text)
	assert text == decode_password(encode_password(text))


def test_get_mac_address() -> None:
	address = get_mac_address()
	assert address is not None
	assert re.match("^" + r"[a-fA-F0-9]{2}:" * 5 + "[a-fA-F0-9]{2}$", address)


def test_get_resource_path() -> None:
	assert "oca-installation-helper" in get_resource_path(".")


def test_version_files() -> None:
	get_installed_oca_version()
	assert get_this_oca_version() is None
