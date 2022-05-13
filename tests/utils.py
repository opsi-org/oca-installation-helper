"""
oca-installation-helper tests

main tests
"""

import tempfile

from contextlib import contextmanager
from pathlib import Path

from ocainstallationhelper.__main__ import InstallationHelper, parse_args


@contextmanager
def get_installation_helper(args=None):
	args = args or []
	with tempfile.TemporaryDirectory() as tempdir:
		tempdir_path = Path(tempdir)
		(tempdir_path / "setup.opsiscript").touch()
		# oca_installation_helper searches for a (parent) directory of full_path with setup.opsiscript
		yield InstallationHelper(parse_args(args), full_path=tempdir_path)
