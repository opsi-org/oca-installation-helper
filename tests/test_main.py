"""
oca-installation-helper tests

main tests
"""
# pylint: disable=redefined-outer-name

from contextlib import contextmanager
from pathlib import Path
import tempfile


from ocainstallationhelper.__main__ import InstallationHelper, parse_args


@contextmanager
def get_installation_helper():
	args = []
	with tempfile.TemporaryDirectory() as tempdir:
		tempdir_path = Path(tempdir)
		(tempdir_path / "setup.opsiscript").touch()
		# oca_installation_helper searches for a (parent) directory of full_path with setup.opsiscript
		yield InstallationHelper(parse_args(args), full_path=tempdir_path)


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


def test_copy_files():
	with get_installation_helper() as installation_helper:
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
