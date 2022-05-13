"""
oca-installation-helper tests

main tests
"""
# pylint: disable=redefined-outer-name

from pathlib import Path

from .utils import get_installation_helper


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
