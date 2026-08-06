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
import tarfile
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest
from opsi.opsi.service.model.object import OpsiClient, ProductOnClient

from ocainstallationhelper.__main__ import InstallationHelper
from ocainstallationhelper.backend import Backend
from ocainstallationhelper.config import SETUP_SCRIPT_NAME

from .utils import fake_get_service_client, get_installation_helper


def fake_get_pocs(self, package: str, client: str) -> list[ProductOnClient]:
	return [ProductOnClient(package, "LocalbootProduct", client, actionProgress="", installationStatus="installed")]


def test_helper_object() -> None:
	with get_installation_helper() as installation_helper:
		assert installation_helper.config.opsiclientd_conf.name == "opsiclientd.conf"
		assert installation_helper.config.oca_package.endswith("-client-agent")
		assert installation_helper.config.opsi_script_path.name.startswith("opsi-script")


def prepare_download(installation_helper: InstallationHelper, product: str, destination: Path) -> None:
	config = installation_helper.config
	if product == config.oca_package:
		package_dir = destination / config.oca_package
		package_dir.mkdir(parents=True)
		(package_dir / SETUP_SCRIPT_NAME).touch()
		return

	opsi_script_dir = destination / "opsi-script"
	(opsi_script_dir / config.opsi_script_path).parent.mkdir(parents=True)
	(opsi_script_dir / config.opsi_script_path).touch()
	(opsi_script_dir / "common" / "skin").mkdir(parents=True)
	(opsi_script_dir / "common" / "lib").mkdir(parents=True)


def prepare_opsi_script_package_source(installation_helper: InstallationHelper, package_dir: Path) -> None:
	(package_dir / installation_helper.config.opsi_script_path).parent.mkdir(parents=True)
	(package_dir / installation_helper.config.opsi_script_path).touch()
	(package_dir / "common" / "skin").mkdir(parents=True)
	(package_dir / "common" / "lib").mkdir(parents=True)
	(package_dir / "local-file").touch()


@pytest.mark.asyncio
async def test_copy_installation_files_uses_local_directory_for_oca_package(tmp_path: Path) -> None:
	source = tmp_path / "source"
	source.mkdir()
	(source / SETUP_SCRIPT_NAME).touch()
	(source / "local-file").touch()

	with get_installation_helper(["--client-id", "client.domain.local", "--oca-package-source", str(source)]) as installation_helper:
		installation_helper.tmp_dir = tmp_path / "work"
		backend = MagicMock(spec=Backend)
		backend.get_configserver_id.return_value = "depot.domain.local"
		backend.get_from_depot.side_effect = lambda product, destination: prepare_download(installation_helper, product, destination)
		installation_helper.backend = backend

		base_dir = await installation_helper.copy_installation_files("depot.domain.local")

		assert base_dir == installation_helper.tmp_dir / installation_helper.config.oca_package
		assert (base_dir / "local-file").is_file()
		assert (source / "local-file").is_file()
		assert backend.get_from_depot.call_args_list == [call("opsi-script", installation_helper.tmp_dir)]


@pytest.mark.asyncio
async def test_copy_installation_files_extracts_local_archive(tmp_path: Path) -> None:
	archive_contents = tmp_path / "archive-contents"
	with get_installation_helper(["--client-id", "client.domain.local"]) as installation_helper:
		package_dir = archive_contents / installation_helper.config.oca_package
		package_dir.mkdir(parents=True)
		(package_dir / SETUP_SCRIPT_NAME).touch()
		(package_dir / "archive-file").touch()
		archive = tmp_path / "oca-package.tar.gz"
		with tarfile.open(archive, "w:gz") as tar:
			tar.add(package_dir, arcname=package_dir.name)
		installation_helper.config.oca_package_source = archive
		installation_helper.tmp_dir = tmp_path / "work"
		backend = MagicMock(spec=Backend)
		backend.get_configserver_id.return_value = "depot.domain.local"
		backend.get_from_depot.side_effect = lambda product, destination: prepare_download(installation_helper, product, destination)
		installation_helper.backend = backend

		base_dir = await installation_helper.copy_installation_files("depot.domain.local")

		assert (base_dir / "archive-file").is_file()
		assert archive.is_file()
		assert backend.get_from_depot.call_args_list == [call("opsi-script", installation_helper.tmp_dir)]


@pytest.mark.asyncio
async def test_copy_installation_files_downloads_oca_package_without_local_source(tmp_path: Path) -> None:
	with get_installation_helper(["--client-id", "client.domain.local"]) as installation_helper:
		installation_helper.tmp_dir = tmp_path / "work"
		backend = MagicMock(spec=Backend)
		backend.get_configserver_id.return_value = "depot.domain.local"
		backend.get_from_depot.side_effect = lambda product, destination: prepare_download(installation_helper, product, destination)
		installation_helper.backend = backend

		await installation_helper.copy_installation_files("depot.domain.local")

		assert backend.get_from_depot.call_args_list == [
			call(installation_helper.config.oca_package, installation_helper.tmp_dir),
			call("opsi-script", installation_helper.tmp_dir),
		]


@pytest.mark.asyncio
async def test_copy_installation_files_uses_local_directory_for_opsi_script(tmp_path: Path) -> None:
	source = tmp_path / "source"
	with get_installation_helper(["--client-id", "client.domain.local"]) as installation_helper:
		prepare_opsi_script_package_source(installation_helper, source)
		(source / "common" / "skin" / "common-file").touch()
		platform_skin = source / installation_helper.config.opsi_script_path.parent / "skin"
		platform_skin.mkdir()
		(platform_skin / "platform-file").touch()
		installation_helper.config.opsi_script_package_source = source
		installation_helper.tmp_dir = tmp_path / "work"
		backend = MagicMock(spec=Backend)
		backend.get_configserver_id.return_value = "depot.domain.local"
		backend.get_from_depot.side_effect = lambda product, destination: prepare_download(installation_helper, product, destination)
		installation_helper.backend = backend

		await installation_helper.copy_installation_files("depot.domain.local")

		assert (installation_helper.tmp_dir / "opsi-script" / "local-file").is_file()
		assert isinstance(installation_helper.config.opsi_script, Path)
		assert (installation_helper.config.opsi_script.parent / "skin" / "common-file").is_file()
		assert (installation_helper.config.opsi_script.parent / "skin" / "platform-file").is_file()
		assert (source / "local-file").is_file()
		assert backend.get_from_depot.call_args_list == [call(installation_helper.config.oca_package, installation_helper.tmp_dir)]


@pytest.mark.asyncio
async def test_copy_installation_files_extracts_local_opsi_script_archive(tmp_path: Path) -> None:
	archive_contents = tmp_path / "archive-contents"
	with get_installation_helper(["--client-id", "client.domain.local"]) as installation_helper:
		package_dir = archive_contents / "opsi-script"
		prepare_opsi_script_package_source(installation_helper, package_dir)
		archive = tmp_path / "opsi-script.tar.gz"
		with tarfile.open(archive, "w:gz") as tar:
			tar.add(package_dir, arcname=package_dir.name)
		installation_helper.config.opsi_script_package_source = archive
		installation_helper.tmp_dir = tmp_path / "work"
		backend = MagicMock(spec=Backend)
		backend.get_configserver_id.return_value = "depot.domain.local"
		backend.get_from_depot.side_effect = lambda product, destination: prepare_download(installation_helper, product, destination)
		installation_helper.backend = backend

		await installation_helper.copy_installation_files("depot.domain.local")

		assert (installation_helper.tmp_dir / "opsi-script" / "local-file").is_file()
		assert archive.is_file()
		assert backend.get_from_depot.call_args_list == [call(installation_helper.config.oca_package, installation_helper.tmp_dir)]


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
