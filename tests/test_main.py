"""
oca-installation-helper tests

main tests
"""

from __future__ import annotations

import platform
from pathlib import Path
from typing import Any
from unittest.mock import patch

from opsicommon.client.opsiservice import ServiceClient, ServiceVerificationFlags
from opsicommon.objects import OpsiClient, ProductOnClient

from .utils import get_installation_helper


class PopenLog:
	entries: list[list[str]] = []

	def write(self, entry: list[str]) -> None:
		self.entries.append(entry)


popen_log = PopenLog()


class FakePopen:
	def __init__(self, command: list[str], **kwargs: dict[str, Any]) -> None:
		self.command = command
		self.returncode = 0
		self.stdout = None
		self.stderr = None
		popen_log.write(self.command)

	def __enter__(self) -> FakePopen:
		return self

	def __exit__(self, *args: tuple[Any]) -> None:
		pass

	async def communicate(self, input: Any = None, timeout: float | None = None) -> tuple[bytes, bytes]:
		return (b"", b"")


async def fake_create_subprocess_exec(*args: str, **kwargs: dict[str, Any]) -> FakePopen:
	return FakePopen(list(args), kwargs=kwargs)


def fake_get_service_client(
	address: str, username: str | None, password: str | None, verify: ServiceVerificationFlags, sso: bool = False
) -> ServiceClient:
	return ServiceClient(address=address, username=username, password=password, verify=verify)


def fake_get_pocs(self, package: str, client: str) -> list[ProductOnClient]:
	return [ProductOnClient(package, "LocalbootProduct", client, actionProgress="", installationStatus="installed")]


def test_helper_object() -> None:
	with get_installation_helper() as installation_helper:
		assert installation_helper.config.opsiclientd_conf.name == "opsiclientd.conf"
		assert installation_helper.config.oca_package.endswith("-client-agent")
		assert installation_helper.config.opsi_script_path.name.startswith("opsi-script")


def test_run(tmp_path: Path) -> None:
	host_key = "00000000000000000000000000000000"
	with get_installation_helper(
		[
			"--non-interactive",
			"--read-conf-files",
			"install.conf",
			"--client-id",
			"client.domain.local",
			"--service-address",
			"https://server.domain.local:4447",
			"--service-password",
			host_key,
			"--service-username",
			"client.domain.local",
		]
	) as installation_helper:
		with (
			patch("ocainstallationhelper.__main__.InstallationHelper.ensure_root"),
			patch("ocainstallationhelper.__main__.InstallationHelper.copy_installation_files", return_value=tmp_path),
			patch(
				"ocainstallationhelper.backend.Backend.get_or_create_client",
				return_value=OpsiClient(opsiHostKey=host_key, id="client.domain.local"),
			),
			patch(
				"ocainstallationhelper.backend.get_service_client",
				fake_get_service_client,
			),
			patch("ocainstallationhelper.backend.Backend.set_poc_to_installing"),
			patch("ocainstallationhelper.backend.Backend.get_pocs", fake_get_pocs),
			patch("ocainstallationhelper.__main__.asyncio.create_subprocess_exec", fake_create_subprocess_exec),
			patch("ocainstallationhelper.backend.Backend.get_available_oca_version"),
		):
			installation_helper.run()
		if platform.system().lower() == "windows":
			return
		assert popen_log.entries[0] == [
			"None",  # opsi-script bin path is set during copy_installation_files
			str(tmp_path / "setup.opsiscript"),
			"/var/log/opsi-script/opsi-client-agent.log",
			"-servicebatch",
			"-productid",
			installation_helper.config.oca_package,
			"-opsiservice",
			"https://server.domain.local:4447",
			"-clientid",
			"client.domain.local",
			"-username",
			"client.domain.local",
			"-password",
			host_key,
			"-parameter",
			"noreboot",
		]
