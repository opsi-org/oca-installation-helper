"""
oca-installation-helper tests

config tests
"""

from pathlib import Path
import tempfile

from .utils import get_installation_helper


def test_fill_config_from_params():
	with get_installation_helper(
		["--client-id", "client.domain.local", "--service-address", "https://server.domain.local:4447"]
	) as installation_helper:
		assert installation_helper.config.client_id == "client.domain.local"
		assert installation_helper.config.service_address == "https://server.domain.local:4447"


def test_fill_config_from_default():
	with get_installation_helper() as installation_helper:
		assert not installation_helper.config.client_id
		installation_helper.config.fill_config_from_default()
		assert installation_helper.config.client_id


def test_fill_config_from_files():
	with get_installation_helper() as installation_helper:
		with tempfile.TemporaryDirectory() as tempdir:
			installconf = Path(tempdir) / "install.conf"
			installconf.write_text(
				"client_id = dummy.domain.local\n"
				"service_address = https://192.168.0.1:4447/rpc\n"
				"service_username = dummyuser\n"
				"service_password = dummypassword\n"
				"dns_domain = should.be.ignored\n"
				"interactive =\n",
				encoding="utf-8",
			)
			installation_helper.config.fill_config_from_files(config_files=[installconf])
			assert installation_helper.config.client_id == "dummy.domain.local"
			assert installation_helper.config.service_address == "https://192.168.0.1:4447/rpc"
			assert installation_helper.config.service_username == "dummyuser"
			assert installation_helper.config.service_password == "dummypassword"
			installation_helper.config.check_values()


# default < zeroconf < registry < file < params


def test_priority_of_sources():
	with get_installation_helper(["--service-username", "from_param"]) as installation_helper:
		with tempfile.TemporaryDirectory() as tempdir:
			installconf = Path(tempdir) / "install.conf"
			installconf.write_text("service_address = from_file\nservice_username = from_file\n", encoding="utf-8")
			installation_helper.config.fill_config_from_files(config_files=[Path(installconf)])
			installation_helper.config.fill_config_from_default()

			assert installation_helper.config.client_id  # assembled from hostname
			assert installation_helper.config.service_address == "from_file"
			assert installation_helper.config.service_username == "from_param"
