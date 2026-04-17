# This file is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2023-2026 uib GmbH <info@uib.de>
# This code is owned by the uib GmbH, Mainz, Germany (uib.de). All rights reserved.
# License: AGPL-3.0-only

"""
oca-installation-helper tests

config tests
"""

from pathlib import Path

from .utils import get_installation_helper


def test_fill_config_from_params() -> None:
	with get_installation_helper(
		["--client-id", "client.domain.local", "--service-address", "https://server.domain.local:4447", "--no-gui", "--no-set-mac-address"]
	) as installation_helper:
		assert installation_helper.config.client_id == "client.domain.local"
		assert installation_helper.config.service_address == "https://server.domain.local:4447"
		assert not installation_helper.config.set_mac_address
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
