"""
oca-installation-helper tests

main tests
"""

from __future__ import annotations

import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from opsicommon.client.opsiservice import ServiceClient, ServiceVerificationFlags

from ocainstallationhelper.__main__ import InstallationHelper, parse_args


@contextmanager
def get_installation_helper(args: list[str] | None = None) -> Generator[InstallationHelper, None, None]:
	args = args or []
	with tempfile.TemporaryDirectory() as tempdir:
		tempdir_path = Path(tempdir)
		(tempdir_path / "setup.opsiscript").touch()
		# oca_installation_helper searches for a (parent) directory of full_path with setup.opsiscript
		yield InstallationHelper(parse_args(args))


def fake_get_service_client(
	address: str, username: str | None, password: str | None, verify: ServiceVerificationFlags, sso: bool = False
) -> ServiceClient:
	return ServiceClient(address=address, username=username, password=password, verify=verify)
