"""
oca-installation-helper tests

config tests
"""

from pathlib import Path

from .utils import get_installation_helper


def test_helper_object():  # pylint: disable=redefined-outer-name
	with get_installation_helper() as installation_helper:
		ocdconf = installation_helper.config.opsiclientd_conf
		assert ocdconf.name == "opsiclientd.conf"


def test_without_config():  # pylint: disable=redefined-outer-name
	with get_installation_helper() as installation_helper:
		base_dir = Path() / "tests" / "no_data"
		base_dir.mkdir(exist_ok=True)
		installation_helper.config.base_dir = base_dir

		installation_helper.get_config()
		assert installation_helper.config.client_id
		base_dir.rmdir()


def test_get_config():  # pylint: disable=redefined-outer-name
	with get_installation_helper() as installation_helper:
		base_dir = Path() / "tests" / "test_data"
		installation_helper.config.base_dir = base_dir
		installation_helper.get_config()
		print(installation_helper.config.client_id, installation_helper.config.service_address)
		assert installation_helper.config.client_id == "dummy.domain.local"
		assert installation_helper.config.service_address == "https://192.168.0.1:4447/rpc"
		assert installation_helper.config.service_username == "dummyuser"
		assert installation_helper.config.service_password == "dummypassword"
		installation_helper.config.check_values()


# starts zeroconf in asyncio loop - doesnt find anything in test
# def test_zeroconf(installation_helper):
# 	installation_helper.start_zeroconf()
# 	print(installation_helper.service_address)
