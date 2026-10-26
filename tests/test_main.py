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

from ocainstallationhelper.__main__ import InstallationHelper, main
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


@pytest.mark.asyncio
async def test_service_setup_masks_client_key_in_logs() -> None:
	with get_installation_helper(["--non-interactive", "--client-id", "client.domain.local"]) as installation_helper:
		installation_helper.backend = MagicMock()
		installation_helper.backend.get_or_create_client.return_value = OpsiClient(id="client.domain.local", opsiHostKey="a" * 32)
		with patch("ocainstallationhelper.__main__.secret_filter") as secret_filter:
			await installation_helper.service_setup()
		secret_filter.add_secrets.assert_called_once_with("a" * 32)


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
async def test_copy_installation_files_extracts_oca_package_archive(tmp_path: Path) -> None:
	client_data = tmp_path / "client-data"
	client_data.mkdir()
	(client_data / SETUP_SCRIPT_NAME).touch()
	(client_data / "archive-file").touch()
	client_data_archive = tmp_path / "CLIENT_DATA.tar.gz"
	with tarfile.open(client_data_archive, "w:gz") as tar:
		tar.add(client_data / SETUP_SCRIPT_NAME, arcname=SETUP_SCRIPT_NAME)
		tar.add(client_data / "archive-file", arcname="archive-file")
	package_archive = tmp_path / "opsi-client-agent.opsi"
	with tarfile.open(package_archive, "w") as tar:
		tar.add(client_data_archive, arcname=client_data_archive.name)

	with get_installation_helper(["--client-id", "client.domain.local"]) as installation_helper:
		installation_helper.config.oca_package_source = package_archive
		installation_helper.tmp_dir = tmp_path / "work"
		backend = MagicMock(spec=Backend)
		backend.get_configserver_id.return_value = "depot.domain.local"
		backend.get_from_depot.side_effect = lambda product, destination: prepare_download(installation_helper, product, destination)
		installation_helper.backend = backend

		base_dir = await installation_helper.copy_installation_files("depot.domain.local")

		assert (base_dir / SETUP_SCRIPT_NAME).is_file()
		assert (base_dir / "archive-file").is_file()
		assert package_archive.is_file()
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
		if installation_helper.config.oca_package != "opsi-mac-client-agent":
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


@pytest.mark.asyncio
@pytest.mark.parametrize(
	"args",
	[
		["--service-address", "https://s:4447", "--client-id", "c.d", "--service-password", "pw"],  # no username
		["--service-address", "https://s:4447", "--client-id", "c.d", "--service-username", "", "--service-password", "pw"],
		["--service-address", "https://s:4447", "--client-id", "c.d", "--service-username", "user"],  # no password
		["--service-address", "https://s:4447", "--client-id", "c.d", "--service-username", "user", "--service-password", ""],
		["--client-id", "c.d", "--service-username", "user", "--service-password", "pw"],  # no address
	],
)
async def test_install_rejects_incomplete_credentials(args: list[str]) -> None:
	with get_installation_helper(args) as installation_helper, patch("ocainstallationhelper.__main__.Backend") as backend_mock:
		with pytest.raises(ValueError, match="Incomplete data"):
			await installation_helper.install()
		backend_mock.assert_not_called()


@pytest.mark.asyncio
async def test_install_with_sso_does_not_require_credentials() -> None:
	args = ["--service-address", "https://s:4447", "--client-id", "c.d", "--sso"]
	with get_installation_helper(args) as installation_helper, patch("ocainstallationhelper.__main__.Backend") as backend_mock:
		backend_mock.return_value.connect.side_effect = ConnectionError("stop here")
		with pytest.raises(ConnectionError, match="stop here"):
			await installation_helper.install()
		backend_mock.assert_called_once()


def test_main_ensures_root_before_creating_log_file(tmp_path: Path) -> None:
	log_file = tmp_path / "oca.log"
	events: list[str] = []

	def fake_ensure_root() -> None:
		events.append("ensure_root")
		assert not log_file.exists()

	def fake_run(self: InstallationHelper) -> None:
		events.append("run")

	with (
		patch("ocainstallationhelper.__main__.sys.argv", ["oca-installation-helper", "--log-file", str(log_file)]),
		patch("ocainstallationhelper.__main__.platform.system", return_value="Linux"),
		patch("ocainstallationhelper.__main__.ensure_root", fake_ensure_root),
		patch("ocainstallationhelper.__main__.InstallationHelper.run", fake_run),
		patch("ocainstallationhelper.__main__.logging_config"),
	):
		main()
	assert events == ["ensure_root", "run"]


def test_main_encode_password_does_not_require_root() -> None:
	with (
		patch("ocainstallationhelper.__main__.sys.argv", ["oca-installation-helper", "--encode-password", "secret"]),
		patch("ocainstallationhelper.__main__.ensure_root") as ensure_root,
		patch("ocainstallationhelper.__main__.show_message") as show_message,
	):
		main()
	ensure_root.assert_not_called()
	show_message.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("download_fails", [False, True])
async def test_copy_installation_files_stops_depot_backend(tmp_path: Path, download_fails: bool) -> None:
	with (
		get_installation_helper(["--client-id", "client.domain.local"]) as installation_helper,
		patch("ocainstallationhelper.__main__.Backend") as backend_class,
	):
		installation_helper.tmp_dir = tmp_path / "work"
		backend = MagicMock(spec=Backend)
		backend.get_configserver_id.return_value = "configserver.domain.local"
		installation_helper.backend = backend
		depot_backend = backend_class.return_value
		if download_fails:
			depot_backend.get_from_depot.side_effect = RuntimeError("download failed")
		else:
			depot_backend.get_from_depot.side_effect = lambda product, destination: prepare_download(
				installation_helper, product, destination
			)

		if download_fails:
			with pytest.raises(RuntimeError, match="download failed"):
				await installation_helper.copy_installation_files("depot.domain.local")
		else:
			await installation_helper.copy_installation_files("depot.domain.local")

		depot_backend.connect.assert_called_once()
		depot_backend.stop.assert_called_once()
		backend.stop.assert_not_called()


@pytest.mark.asyncio
async def test_install_stops_previous_backend() -> None:
	args = ["--service-address", "https://s:4447", "--client-id", "c.d", "--service-username", "user", "--service-password", "pw"]
	with get_installation_helper(args) as installation_helper, patch("ocainstallationhelper.__main__.Backend") as backend_class:
		previous_backend = MagicMock()
		installation_helper.backend = previous_backend
		backend_class.return_value.connect.side_effect = ConnectionError("stop here")
		with pytest.raises(ConnectionError, match="stop here"):
			await installation_helper.install()
		previous_backend.stop.assert_called_once()
