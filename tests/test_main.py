# This file is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2023-2026 uib GmbH <info@uib.de>
# This code is owned by the uib GmbH, Mainz, Germany (uib.de). All rights reserved.
# License: AGPL-3.0-only

"""
oca-installation-helper tests

main tests
"""

from __future__ import annotations

import platform
from pathlib import Path
from unittest.mock import patch

from opsi.opsi.service.model.object import OpsiClient, ProductOnClient

from .utils import fake_get_service_client, get_installation_helper


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
			patch("ocainstallationhelper.backend.Backend.get_configserver_id", return_value="server.domain.local"),
			patch("ocainstallationhelper.backend.Backend.get_depot_id", return_value="server.domain.local"),
			patch("ocainstallationhelper.backend.Backend.set_poc_to_installing"),
			patch("ocainstallationhelper.backend.Backend.get_pocs", fake_get_pocs),
			patch("ocainstallationhelper.__main__.run_command") as run_command_mock,
			patch("ocainstallationhelper.backend.Backend.get_available_oca_version", return_value=("server.domain.local", "4.3.0.0")),
		):
			installation_helper.run()
		if platform.system().lower() == "windows":
			return
		assert run_command_mock.call_args[0][0] == [
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
