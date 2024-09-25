"""
oca-installation-helper tests

main tests
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

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

	def __enter__(self) -> FakePopen:
		return self

	def __exit__(self, *args: tuple[Any]) -> None:
		pass

	def communicate(self, input: Any, timeout: float | None = None) -> tuple[str, str]:
		popen_log.write(self.command)
		return ("", "")


def test_helper_object() -> None:
	with get_installation_helper() as installation_helper:
		assert installation_helper.config.opsiclientd_conf.name == "opsiclientd.conf"
		assert installation_helper.config.oca_package.endswith("-client-agent")
		assert installation_helper.config.opsi_script_path.name.startswith("opsi-script")


def test_run(tmp_path: Path) -> None:
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
			"foo",
			"--service-username",
			"client.domain.local",
		]
	) as installation_helper:
		with (
			patch("ocainstallationhelper.__main__.InstallationHelper.ensure_admin"),
			patch("ocainstallationhelper.__main__.InstallationHelper.copy_installation_files", return_value=tmp_path),
			patch(
				"ocainstallationhelper.backend.Backend.get_or_create_client",
				return_value={"opsiHostKey": "foo", "id": "client.domain.local"},
			),
			patch("ocainstallationhelper.backend.Backend.set_poc_to_installing"),
			patch("ocainstallationhelper.__main__.subprocess.Popen", FakePopen),
			patch("ocainstallationhelper.backend.Backend.evaluate_success"),
		):
			installation_helper.run()
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
			"foo",
			"-parameter",
			"noreboot",
		]
