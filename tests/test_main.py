"""
oca-installation-helper tests

main tests
"""

import tempfile
from pathlib import Path

from .utils import get_installation_helper


def test_helper_object() -> None:
	with get_installation_helper() as installation_helper:
		ocdconf = installation_helper.config.opsiclientd_conf
		assert ocdconf.name == "opsiclientd.conf"


def test_copy_files() -> None:
	with get_installation_helper() as installation_helper:
		with tempfile.TemporaryDirectory() as tempdir:
			base_dir = Path(tempdir)
			installconf = base_dir / "install.conf"
			installconf.write_text(
				"client_id = dummy.domain.local\n"
				"service_address = https://192.168.0.1:4447/rpc\n"
				"service_username = dummyuser\n"
				"service_password = dummypassword\n"
				"dns_domain = should.be.ignored\n"
				"interactive =\n",
				encoding="utf-8",
			)

			installation_helper.config.base_dir = base_dir
			installation_helper.configure_from_reg_file()
			installation_helper.configure_from_zeroconf_default()
			installation_helper.copy_installation_files()
			assert (installation_helper.tmp_dir / "install.conf").exists()
			installation_helper.cleanup()
			assert not (installation_helper.tmp_dir / "install.conf").exists()
