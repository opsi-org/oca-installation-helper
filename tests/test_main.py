"""
oca-installation-helper tests

main tests
"""
# pylint: disable=redefined-outer-name

from pathlib import Path
import pytest


from ocainstallationhelper.__main__ import InstallationHelper, parse_args


@pytest.fixture
def installation_helper():
	args = []
	return InstallationHelper(parse_args(args))


def test_helper_object(installation_helper):  # pylint: disable=redefined-outer-name
	ocdconf = installation_helper.config.opsiclientd_conf
	assert ocdconf.name == "opsiclientd.conf"


def test_without_config(installation_helper):  # pylint: disable=redefined-outer-name
	base_dir = Path() / "tests" / "no_data"
	base_dir.mkdir(exist_ok=True)
	installation_helper.config.base_dir = base_dir

	installation_helper.get_config()
	assert installation_helper.config.client_id
	base_dir.rmdir()


def test_get_config(installation_helper):  # pylint: disable=redefined-outer-name
	base_dir = Path() / "tests" / "test_data"
	installation_helper.config.base_dir = base_dir
	installation_helper.get_config()
	print(installation_helper.config.client_id, installation_helper.config.service_address)
	assert installation_helper.config.client_id == "dummy.domain.local"
	assert installation_helper.config.service_address == "https://192.168.0.1:4447/rpc"
	assert installation_helper.config.service_username == "dummyuser"
	assert installation_helper.config.service_password == "dummypassword"
	installation_helper.config.check_values()


def test_copy_files(installation_helper):
	base_dir = Path() / "tests" / "test_data"
	base_dir.mkdir(exist_ok=True)
	installation_helper.config.base_dir = base_dir
	installation_helper.get_config()
	installation_helper.copy_installation_files()
	assert (installation_helper.tmp_dir / "install.conf").exists()
	installation_helper.cleanup()
	assert not (installation_helper.tmp_dir / "install.conf").exists()


# starts zeroconf in asyncio loop - doesnt find anything in test
# def test_zeroconf(installation_helper):
# 	installation_helper.start_zeroconf()
# 	print(installation_helper.service_address)
