# This file is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2023-2026 uib GmbH <info@uib.de>
# This code is owned by the uib GmbH, Mainz, Germany (uib.de). All rights reserved.
# License: AGPL-3.0-only

"""
oca-installation-helper tests

config tests
"""

import ipaddress
from argparse import Namespace
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ocainstallationhelper.__main__ import parse_args
from ocainstallationhelper.config import determine_use_gui

from .utils import get_installation_helper


def test_determine_use_gui(monkeypatch: pytest.MonkeyPatch) -> None:
	monkeypatch.setattr("ocainstallationhelper.config.platform.system", lambda: "Linux")
	monkeypatch.delenv("DISPLAY", raising=False)
	cmdline_args = Namespace(gui=False, no_gui=False)

	assert not determine_use_gui(cmdline_args)

	monkeypatch.setenv("DISPLAY", ":0")
	assert determine_use_gui(cmdline_args)

	monkeypatch.delenv("DISPLAY")
	cmdline_args.gui = True
	assert determine_use_gui(cmdline_args)

	cmdline_args.no_gui = True
	assert not determine_use_gui(cmdline_args)


def test_fill_config_from_params(tmp_path: Path) -> None:
	with get_installation_helper(
		[
			"--client-id",
			"client.domain.local",
			"--service-address",
			"https://server.domain.local:4447",
			"--no-gui",
			"--no-set-mac-address",
			"--setup-after-install",
			"product1,product2",
			"--set-product-actions",
			"product1:setup,product2,product3:uninstall",
			"--oca-package-source",
			str(tmp_path),
			"--opsi-script-package-source",
			str(tmp_path),
		]
	) as installation_helper:
		assert installation_helper.config.client_id == "client.domain.local"
		assert installation_helper.config.service_address == "https://server.domain.local:4447"
		assert not installation_helper.config.set_mac_address
		assert installation_helper.config.setup_after_install == ["product1", "product2"]
		assert installation_helper.config.set_product_actions == {"product1": "setup", "product2": "setup", "product3": "uninstall"}
		assert installation_helper.config.oca_package_source == tmp_path
		assert installation_helper.config.opsi_script_package_source == tmp_path
		installation_helper.config.check_values(with_host_key=False)


def test_check_values_rejects_missing_oca_package_source(tmp_path: Path) -> None:
	missing_source = tmp_path / "missing"
	with (
		get_installation_helper(["--oca-package-source", str(missing_source)]) as installation_helper,
		pytest.raises(ValueError, match="does not exist"),
	):
		installation_helper.config.check_values(with_host_key=False)


def test_check_values_rejects_missing_opsi_script_package_source(tmp_path: Path) -> None:
	missing_package = tmp_path / "missing"
	with (
		get_installation_helper(["--opsi-script-package-source", str(missing_package)]) as installation_helper,
		pytest.raises(ValueError, match="does not exist"),
	):
		installation_helper.config.check_values(with_host_key=False)


def test_fill_config_from_default() -> None:
	with get_installation_helper() as installation_helper:
		assert not installation_helper.config.client_id
		installation_helper.config.fill_config_from_default()
		assert installation_helper.config.client_id


def test_fill_config_from_files(tmp_path: Path) -> None:
	install_conf = tmp_path / "install.conf"
	install_conf.write_text(
		"client_id = dummy.domain.local\n"
		"client_key = dummykey\n"
		"service_address = https://192.168.0.1:4447/rpc\n"
		"service_username = dummyuser\n"
		"service_password = dummypassword\n"
		"dns_domain = should.be.ignored\n"
		"interactive = no\n",
		encoding="utf-8",
	)
	for conf in ((install_conf,), ("install.conf",)):
		with get_installation_helper() as installation_helper:
			installation_helper.config.read_conf_files = conf
			installation_helper.config.fill_config_from_files(tmp_path)
			assert installation_helper.config.client_id == "dummy.domain.local"
			assert installation_helper.config.service_address == "https://192.168.0.1:4447/rpc"
			assert installation_helper.config.service_username == "dummyuser"
			assert installation_helper.config.service_password == "dummypassword"


# default < zeroconf < file < registry < params


def test_priority_of_sources(tmp_path: Path) -> None:
	with get_installation_helper(["--service-username", "from_param"]) as installation_helper:
		install_conf = tmp_path / "install.conf"
		install_conf.write_text("service_address = from_file\nservice_username = from_file\n", encoding="utf-8")
		installation_helper.config.read_conf_files = (install_conf,)
		installation_helper.config.fill_config_from_files(tmp_path)
		installation_helper.config.fill_config_from_default()

		assert installation_helper.config.client_id  # assembled from hostname
		assert installation_helper.config.service_address == "from_file"
		assert installation_helper.config.service_username == "from_param"


def test_cmdline_flags_are_not_overridden_by_config_file(tmp_path: Path) -> None:
	install_conf = tmp_path / "install.conf"
	install_conf.write_text("interactive = yes\nsso = no\n", encoding="utf-8")
	with get_installation_helper(["--non-interactive", "--sso"]) as installation_helper:
		installation_helper.config.read_conf_files = (install_conf,)
		installation_helper.config.fill_config_from_files(tmp_path)
		assert installation_helper.config.interactive is False
		assert installation_helper.config.sso is True


def test_config_file_can_set_flags_not_given_on_cmdline(tmp_path: Path) -> None:
	install_conf = tmp_path / "install.conf"
	install_conf.write_text("interactive = no\nsso = yes\n", encoding="utf-8")
	with get_installation_helper() as installation_helper:
		assert installation_helper.config.interactive is True
		installation_helper.config.read_conf_files = (install_conf,)
		installation_helper.config.fill_config_from_files(tmp_path)
		assert installation_helper.config.interactive is False
		assert installation_helper.config.sso is True


@pytest.mark.parametrize(
	("cmdline", "install_params", "expected_interactive", "expected_sso"),
	[
		(["--non-interactive", "--sso"], "--client-id=foo.domain.local", False, True),  # registry must not reset cmdline flags
		([], "--client-id=foo.domain.local", True, False),
		([], "--non-interactive --sso", False, True),
	],
)
def test_registry_does_not_override_cmdline_flags(
	cmdline: list[str], install_params: str, expected_interactive: bool, expected_sso: bool
) -> None:
	winreg = MagicMock()
	winreg.QueryValueEx.return_value = (install_params, 1)
	with (
		get_installation_helper(cmdline) as installation_helper,
		patch("ocainstallationhelper.config.platform.system", return_value="Windows"),
		patch("ocainstallationhelper.config.winreg", winreg, create=True),
	):
		installation_helper.config.fill_config_from_registry(parse_args)
		assert installation_helper.config.interactive is expected_interactive
		assert installation_helper.config.sso is expected_sso


def _zeroconf_info(addresses: list[str], port: int = 4447) -> MagicMock:
	info = MagicMock()
	info.server = "server.domain.local."
	info.port = port
	info.properties = {b"version": b"4.3"}
	info.parsed_addresses.return_value = addresses
	return info


def test_zeroconf_handler_sets_service_address_of_matching_network() -> None:
	zeroconf = MagicMock()
	zeroconf.get_service_info.return_value = _zeroconf_info(["not-an-ip", "10.0.0.5", "192.168.1.5"])
	with (
		get_installation_helper() as installation_helper,
		patch("ocainstallationhelper.config.get_ip_interfaces", return_value=[ipaddress.ip_interface("192.168.1.20/24")]),
	):
		installation_helper.config.zeroconf_handler(zeroconf, "_opsics._tcp.local.", "server", None)
		assert installation_helper.config.zeroconf_addresses == ["https://192.168.1.5:4447"]
		assert installation_helper.config.service_address == "https://192.168.1.5:4447"


def test_zeroconf_handler_ignores_service_without_matching_network() -> None:
	zeroconf = MagicMock()
	zeroconf.get_service_info.return_value = _zeroconf_info(["10.0.0.5", "invalid"])
	with (
		get_installation_helper() as installation_helper,
		patch("ocainstallationhelper.config.get_ip_interfaces", return_value=[ipaddress.ip_interface("192.168.1.20/24")]),
	):
		installation_helper.config.zeroconf_handler(zeroconf, "_opsics._tcp.local.", "server", None)
		assert installation_helper.config.zeroconf_addresses == []
		assert installation_helper.config.service_address is None
