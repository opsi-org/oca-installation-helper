"""
main tests
"""

import os
import pytest

from ocainstallationhelper.__main__ import InstallationHelper, parse_args

@pytest.fixture
def installation_helper():
	args = []
	return InstallationHelper(parse_args(args))


def test_helper_object(installation_helper):
	ocdconf = installation_helper.opsiclientd_conf
	assert ocdconf.endswith("opsiclientd.conf")

def test_get_config(installation_helper):
	with pytest.raises(RuntimeError):
		installation_helper.find_setup_script()
	os.makedirs(os.path.join(os.path.abspath("."), "tests", "no_data"), exist_ok=True)
	installation_helper.base_dir = os.path.join(os.path.abspath("."), "tests", "no_data")

	installation_helper.get_config()
	assert installation_helper.client_id
	os.rmdir(os.path.join(os.path.abspath("."), "tests", "no_data"))

	installation_helper.base_dir = os.path.join(os.path.abspath("."), "tests", "test_data")
	installation_helper.get_config()
	assert installation_helper.client_id
	assert installation_helper.service_address
	assert installation_helper.service_username
	assert installation_helper.service_password
