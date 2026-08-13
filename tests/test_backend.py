# This file is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2023-2026 uib GmbH <info@uib.de>
# This code is owned by the uib GmbH, Mainz, Germany (uib.de). All rights reserved.
# License: AGPL-3.0-only

import ipaddress
from unittest.mock import patch

import pytest
from opsi.logging import use_logging_config
from opsi.opsi.service.model.object import OpsiConfigserver, OpsiDepotserver

from ocainstallationhelper.backend import Backend

from .utils import fake_get_service_client


@pytest.mark.parametrize(
	("my_ip_address", "expected_depot_id"),
	[
		("128.0.0.1", "configserver.domain.local"),  # matches none, should fallback to configserver
		("1.1.1.1", "depot1.domain.local"),  # matches depot1 only
		("1.0.1.1", "depot2.domain.local"),  # matches depot1 and depot2, should take depot2
		("1.0.0.1", "depot3.domain.local"),  # matches all depots, should take the most specific one
	],
)
def test_get_depot_id_by_network(my_ip_address: str, expected_depot_id: str) -> None:
	depots = [
		OpsiConfigserver(id="configserver.domain.local", networkAddress="1.0.0.0/32"),  # should never match
		OpsiDepotserver(id="depot1.domain.local", networkAddress="1.0.0.0/8"),
		OpsiDepotserver(id="depot2.domain.local", networkAddress="1.0.0.0/16"),
		OpsiDepotserver(id="depot3.domain.local", networkAddress="1.0.0.0/24"),
	]
	with (
		patch(
			"ocainstallationhelper.backend.get_service_client",
			fake_get_service_client,
		),
		use_logging_config(stderr_level=7),
	):
		backend = Backend("foo", "bar", "baz")
		with (
			patch.object(backend.service, "jsonrpc", return_value=depots),
			patch("ocainstallationhelper.backend.get_ip_interfaces", return_value=[ipaddress.IPv4Interface(my_ip_address)]),
			patch("ocainstallationhelper.backend.Backend.get_configserver_id", return_value="configserver.domain.local"),
		):
			assert backend.get_depot_id_by_network() == expected_depot_id
