"""
oca-installation-helper tests

main tests
"""

from pathlib import Path
import pytest


from ocainstallationhelper.__main__ import InstallationHelper, parse_args


@pytest.fixture
def installation_helper():
	args = []
	return InstallationHelper(parse_args(args))


def test_helper_object(installation_helper):  # pylint: disable=redefined-outer-name
	ocdconf = installation_helper.opsiclientd_conf
	assert ocdconf.name == "opsiclientd.conf"


def test_get_config(installation_helper):  # pylint: disable=redefined-outer-name
	with pytest.raises(RuntimeError):
		installation_helper.find_setup_script()
	base_dir = Path(".") / "tests" / "no_data"
	base_dir.mkdir(exist_ok=True)
	installation_helper.base_dir = base_dir

	installation_helper.get_config()
	assert installation_helper.client_id
	base_dir = Path(".") / "tests" / "no_data"
	base_dir.rmdir()

	base_dir = Path(".") / "tests" / "test_data"
	base_dir.mkdir(exist_ok=True)
	installation_helper.base_dir = base_dir
	installation_helper.get_config()
	assert installation_helper.client_id
	assert installation_helper.service_address
	assert installation_helper.service_username
	assert installation_helper.service_password
	installation_helper.check_values()


def test_copy_files(installation_helper):
	base_dir = Path(".") / "tests" / "test_data"
	base_dir.mkdir(exist_ok=True)
	installation_helper.base_dir = base_dir
	installation_helper.get_config()
	installation_helper.copy_installation_files()
	assert (installation_helper.tmp_dir / "install.conf").exists()
	installation_helper.cleanup()
	assert not (installation_helper.tmp_dir / "install.conf").exists()


# starts zeroconf in asyncio loop - doesnt find anything in test
# def test_zeroconf(installation_helper):
# 	installation_helper.start_zeroconf()
# 	print(installation_helper.service_address)
