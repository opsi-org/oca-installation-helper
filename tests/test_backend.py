# This file is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2023-2026 uib GmbH <info@uib.de>
# This code is owned by the uib GmbH, Mainz, Germany (uib.de). All rights reserved.
# License: AGPL-3.0-only

import ipaddress
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from opsi.exception import BackendAuthenticationError, OpsiServiceConnectionError
from opsi.logging import use_logging_config
from opsi.opsi.service.model.object import OpsiConfigserver, OpsiDepotserver

from ocainstallationhelper.backend import Backend, InstallationUnsuccessful

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


def _get_backend() -> Backend:
	with patch("ocainstallationhelper.backend.get_service_client", fake_get_service_client):
		return Backend("foo", "bar", "baz")


def test_get_available_oca_version_prefers_depot() -> None:
	backend = _get_backend()
	queried: list[str] = []

	def jsonrpc(method: str, params: list) -> list[SimpleNamespace]:
		queried.append(params[1]["depotId"])
		return [SimpleNamespace(productVersion="4.3-1")]

	with patch.object(backend.service, "jsonrpc", side_effect=jsonrpc):
		assert backend.get_available_oca_version("configserver", "depot") == ("depot", "4.3-1")
	assert queried == ["depot"]


def test_get_available_oca_version_falls_back_to_configserver() -> None:
	backend = _get_backend()

	def jsonrpc(method: str, params: list) -> list[SimpleNamespace]:
		if params[1]["depotId"] == "configserver":
			return [SimpleNamespace(productVersion="4.3-2")]
		return []

	with patch.object(backend.service, "jsonrpc", side_effect=jsonrpc):
		assert backend.get_available_oca_version("configserver", "depot") == ("configserver", "4.3-2")


def test_get_available_oca_version_not_available() -> None:
	backend = _get_backend()
	with patch.object(backend.service, "jsonrpc", return_value=[]), pytest.raises(InstallationUnsuccessful):
		backend.get_available_oca_version("configserver", "depot")


def test_connect_does_not_retry_on_authentication_error() -> None:
	backend = _get_backend()
	with (
		patch.object(backend.service, "connect", side_effect=BackendAuthenticationError("denied")) as connect,
		patch("ocainstallationhelper.backend.time.sleep") as sleep,
		pytest.raises(BackendAuthenticationError),
	):
		backend.connect()
	assert connect.call_count == 1
	sleep.assert_not_called()


def test_connect_retries_on_connection_error() -> None:
	backend = _get_backend()
	with (
		patch.object(backend.service, "connect", side_effect=[OpsiServiceConnectionError("down"), None]) as connect,
		patch("ocainstallationhelper.backend.time.sleep"),
	):
		backend.connect()
	assert connect.call_count == 2


@pytest.mark.parametrize(("set_mac_address", "expected_mac"), [(True, "aa:bb:cc:dd:ee:ff"), (False, None)])
def test_get_or_create_client_respects_set_mac_address(set_mac_address: bool, expected_mac: str | None) -> None:
	backend = _get_backend()
	client = SimpleNamespace(id="client.domain.local", hardwareAddress=None)
	calls: list[tuple[str, list]] = []

	def jsonrpc(method: str, params: list) -> list[SimpleNamespace] | None:
		calls.append((method, params))
		if method == "host_getObjects":
			return [client] if any(m == "host_createOpsiClient" for m, _ in calls) else []
		return None

	with (
		patch.object(backend.service, "jsonrpc", side_effect=jsonrpc),
		patch("ocainstallationhelper.backend.get_mac_address", return_value="aa:bb:cc:dd:ee:ff") as get_mac,
	):
		backend.get_or_create_client("client.domain.local", set_mac_address=set_mac_address)

	create_params = next(params for method, params in calls if method == "host_createOpsiClient")
	assert create_params[4] == expected_mac
	assert get_mac.called is set_mac_address
