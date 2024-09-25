"""
oca-installation-helper tests

test for utility functions
"""

import re

import pytest
from pytest import CaptureFixture

from ocainstallationhelper.utils import (
	decode_password,
	encode_password,
	get_installed_oca_version,
	get_ip_interfaces,
	get_mac_address,
	get_resource_path,
	get_this_oca_version,
	show_message,
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


def test_show_message(capsys: CaptureFixture) -> None:
	show_message("test out")
	out, err = capsys.readouterr()
	assert out == "test out"
	assert err == ""
	show_message("test err", "stderr")
	out, err = capsys.readouterr()
	assert out == ""
	assert err == "test err"
	with pytest.raises(ValueError):
		show_message("test", "invalid")


def test_get_ip_interfaces() -> None:
	interfaces = list(get_ip_interfaces())
	assert interfaces
	for interface in interfaces:
		assert interface.ip
		assert interface.network
