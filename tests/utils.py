# This file is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2023-2026 uib GmbH <info@uib.de>
# This code is owned by the uib GmbH, Mainz, Germany (uib.de). All rights reserved.
# License: AGPL-3.0-only

"""
oca-installation-helper tests

main tests
"""

from __future__ import annotations

import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from opsi.exception import OpsiServiceConnectionError
from opsi.opsi.service.client import ServiceClient, ServiceVerificationFlags

from ocainstallationhelper.__main__ import InstallationHelper, parse_args


@contextmanager
def get_installation_helper(args: list[str] | None = None) -> Generator[InstallationHelper]:
	args = args or []
	with tempfile.TemporaryDirectory() as tempdir:
		tempdir_path = Path(tempdir)
		(tempdir_path / "setup.opsiscript").touch()
		# oca_installation_helper searches for a (parent) directory of full_path with setup.opsiscript
		yield InstallationHelper(parse_args(args))


def fake_get_service_client(
	address: str,
	username: str | None,
	password: str | None,
	verify: ServiceVerificationFlags,
	sso: bool = False,
	connect_timeout: int = 10,
	auto_connect: bool = True,
	session_lifetime: int = 3600,
) -> ServiceClient:
	service_client = ServiceClient(
		address=address,
		username=username,
		password=password,
		verify=verify,
		connect_timeout=connect_timeout,
		session_lifetime=session_lifetime,
	)
	attempt = 0

	def connect() -> None:
		nonlocal attempt
		attempt += 1
		if attempt == 1:
			raise OpsiServiceConnectionError("Simulated connection error")

	service_client.connect = connect  # ty: ignore[invalid-assignment]
	return service_client
