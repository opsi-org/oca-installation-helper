# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import re
import types
import socket
import threading
from urllib.parse import urlparse
import gzip
import ipaddress
import requests
import logging
from requests.adapters import HTTPAdapter
from requests.packages import urllib3
from urllib3.util.retry import Retry
import json

from . import __version__, logger

urllib3.disable_warnings()

_GZIP_COMPRESSION = 'gzip'
_DEFAULT_HTTP_PORT = 4444
_DEFAULT_HTTPS_PORT = 4447

class OpsiRpcError(Exception):
	ExceptionShortDescription = "Opsi rpc error"

class BackendAuthenticationError(Exception):
	ExceptionShortDescription = "Backend authentication error"

class BackendPermissionDeniedError(Exception):
	ExceptionShortDescription = "Backend permission denied error"

class TimeoutHTTPAdapter(HTTPAdapter):
	def __init__(self, *args, **kwargs):
		self.timeout = None
		if "timeout" in kwargs:
			self.timeout = kwargs["timeout"]
			del kwargs["timeout"]
		super().__init__(*args, **kwargs)

	def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):  # pylint: disable=too-many-arguments
		if timeout is None:
			timeout = self.timeout
		return super().send(request, stream, timeout, verify, cert, proxies)


class JSONRPCClient:  # pylint: disable=too-many-instance-attributes

	def __init__(self, address, **kwargs):  # pylint: disable=too-many-branches,too-many-statements
		"""
		JSONRPC client
		"""

		self._application = f"oca-installation-helper/{__version__}"
		self._compression = False
		self._connect_on_init = True
		self._connected = False
		self._interface = None
		self._rpc_id = 0
		self._rpc_id_lock = threading.Lock()
		self._ca_cert_file = None
		self._verify_server_cert = False
		self._proxy_url = None
		self._username = None
		self._password = None
		self._serialization = "auto"
		self._ip_version = "auto"
		self._connect_timeout = 10
		self._read_timeout = 60
		self._http_pool_maxsize = 10
		self._http_max_retries = 1
		self.server_name = None
		self.base_url = None

		session_id = None
		for option, value in kwargs.items():
			option = option.lower().replace("_", "")
			if option == 'application':
				self._application = str(value)
			elif option == 'username':
				self._username = str(value or "")
			elif option == 'password':
				self._password = str(value or "")
			elif option == 'sessionid':
				session_id = str(value)
			elif option == 'compression':
				self.setCompression(value)
			elif option == 'connectoninit':
				self._connectOnInit = bool(value)
			elif option == 'connectionpoolsize' and value not in (None, ""):
				self._connection_pool_size = int(value)
			elif option == 'retry':
				if not value:
					self._http_max_retries = 0
			elif option == 'connecttimeout' and value not in (None, ""):
				self._connect_timeout = int(value)
			elif option in ('readtimeout', 'timeout', 'sockettimeout') and value not in (None, ""):
				self._read_timeout = int(value)
			elif option == 'verifyservercert':
				self._verify_server_cert = bool(value)
			elif option == 'cacertfile' and value not in (None, ""):
				self._ca_cert_file = str(value)
			elif option == 'proxyurl' and value not in (None, ""):
				self._proxy_url = str(value)
			elif option == 'ipversion' and value not in (None, ""):
				if str(value) in ("auto", "4", "6"):
					self._ip_version = str(value)
				else:
					logger.error("Invalid ip version '%s', using %s", value, self._ip_version)
			elif option == 'serialization' and value not in (None, ""):
				if value in ("auto", "json", "msgpack"):
					self._serialization = value
				else:
					logger.error("Invalid serialization '%s', using %s", value, self._serialization)

		self._set_address(address)

		self._session = requests.Session()
		self._session.auth = (self._username or '', self._password or '')
		self._session.headers.update({
			'User-Agent': self._application
		})
		if session_id:
			cookie_name, cookie_value = session_id.split("=")
			self._session.cookies.set(
				cookie_name, cookie_value, domain=self.hostname
			)
		if self._proxy_url:
			self._session.proxies.update({
				'http': self._proxy_url,
				'https': self._proxy_url,
			})
		if self._verify_server_cert:
			self._session.verify = self._ca_cert_file or True
		else:
			self._session.verify = False

		self._http_adapter = TimeoutHTTPAdapter(
			timeout=(self._connect_timeout, self._read_timeout),
			pool_maxsize=self._http_pool_maxsize,
			max_retries=0 # No retry on connect
		)
		self._session.mount('http://', self._http_adapter)
		self._session.mount('https://', self._http_adapter)

		try:
			address = ipaddress.ip_address(self.hostname)
			if isinstance(address, ipaddress.IPv6Address) and self._ip_version != "6":
				logger.info("%s is an ipv6 address, forcing ipv6", self.hostname)
				self._ip_version = 6
			elif isinstance(address, ipaddress.IPv4Address) and self._ip_version != "4":
				logger.info("%s is an ipv4 address, forcing ipv4", self.hostname)
				self._ip_version = 4
		except ValueError:
			pass

		urllib3.util.connection.allowed_gai_family = self._allowed_gai_family

		if self._connect_on_init:
			self.connect()

	def _allowed_gai_family(self):
		"""This function is designed to work in the context of
		getaddrinfo, where family=socket.AF_UNSPEC is the default and
		will perform a DNS search for both IPv6 and IPv4 records."""
		# https://github.com/urllib3/urllib3/blob/main/src/urllib3/util/connection.py

		logger.debug("Using ip version %s", self._ip_version)
		if self._ip_version == "4":
			return socket.AF_INET
		if self._ip_version == "6":
			return socket.AF_INET6
		if urllib3.util.connection.HAS_IPV6:
			return socket.AF_UNSPEC
		return socket.AF_INET

	@property
	def hostname(self):
		return urlparse(self.base_url).hostname

	@property
	def session(self):
		if not self._connected:
			self.connect()
		return self._session

	@property
	def server_version(self):
		try:
			if self.server_name:
				match = re.search(r"^opsi\D+(\d+\.\d+\.\d+\.\d+)", self.server_name)
				if match:
					return [int(v) for v in match.group(1).split('.')]
		except Exception as err:  # pylint: disable=broad-except
			logger.warning("Failed to parse server version '%s': %s", self.server_name, err)
		return None

	serverVersion = server_version

	@property
	def serverName(self):
		return self.server_name

	@property
	def interface(self):
		if not self._connected:
			self.connect()
		return self._interface

	def getInterface(self):
		return self.interface

	def set_compression(self, compression):
		if isinstance(compression, bool):
			self._compression = compression
		else:
			compression = str(compression).strip().lower()
			if compression in ('true', 'false'):
				self._compression = compression == "true"
			elif compression == _GZIP_COMPRESSION:
				self._compression = _GZIP_COMPRESSION
			else:
				self._compression = False

	def setCompression(self, compression):
		return self.set_compression(compression)

	def get(self, path, headers=None):
		url = self.base_url
		if path.startswith("/"):
			url = f"{'/'.join(url.split('/')[:3])}{path}"
		else:
			url = f"{url.rstrip('/')}/{path}"

		response = self.session.get(url, headers=headers)
		response.raise_for_status()
		return response

	def _set_address(self, address):
		if "://" not in address:
			address = f"https://{address}"
		url = urlparse(address)
		if url.scheme not in ('http', 'https'):
			raise ValueError(f"Protocol {url.scheme} not supported")

		port = url.port
		if not port:
			port = _DEFAULT_HTTP_PORT if url.scheme == "http" else _DEFAULT_HTTPS_PORT

		path = url.path
		if not path or path == "/":
			path = "/rpc"

		hostname = url.hostname
		if ":" in hostname:
			hostname = f"[{hostname}]"
		self.base_url = f"{url.scheme}://{hostname}:{port}{path}"
		if url.username and not self._username:
			self._username = url.username
		if url.password and not self._password:
			self._password = url.password

	def execute_rpc(self, method, params=None):  # pylint: disable=too-many-branches,too-many-statements
		params = params or []

		rpc_id = 0
		with self._rpc_id_lock:
			self._rpc_id += 1
			rpc_id = self._rpc_id

		headers = {
			'Accept-Encoding': 'gzip, lz4'
		}

		data = {
			"jsonrpc": "2.0",
			"id": rpc_id,
			"method": method,
			"params": params
		}

		headers['Accept'] = headers['Content-Type'] = 'application/json'
		headers['Content-Encoding'] = 'gzip'
		headers['Accept-Encoding'] = 'gzip'
		data = gzip.compress(json.dumps(data).encode("utf-8"))

		logger.info(
			"JSONRPC request to %s: ip_version=%s, id=%d, method=%s, Content-Type=%s, Content-Encoding=%s",
			self.base_url, self._ip_version, rpc_id, method, headers.get('Content-Type', ''), headers.get('Content-Encoding', '')
		)
		response = self._session.post(self.base_url, headers=headers, data=data, stream=True)
		content_type = response.headers.get("Content-Type", "")
		content_encoding = response.headers.get("Content-Encoding", "")
		logger.info(
			"Got response status=%s, Content-Type=%s, Content-Encoding=%s",
			response.status_code, content_type, content_encoding
		)

		if 'server' in response.headers:
			self.server_name = response.headers.get('server')

		data = response.json()

		error_cls = None
		error_msg = None
		if response.status_code != 200:
			error_cls = OpsiRpcError
			error_msg = str(response.status_code)
			if response.status_code == 401:
				error_cls = BackendAuthenticationError
			if response.status_code == 403:
				error_cls = BackendPermissionDeniedError

		if data.get('error'):
			logger.debug('JSONRPC-response contains error')
			if not error_cls:
				error_cls = OpsiRpcError
			if isinstance(data['error'], dict) and data['error'].get('message'):
				error_msg = data['error']['message']
			else:
				error_msg = str(data['error'])

		if error_cls:
			raise error_cls(f"{error_msg} (error on server)")

		return data.get('result')

	def connect(self):
		logger.info("Connecting to service %s", self.base_url)
		self._interface = self.execute_rpc('backend_getInterface')
		self._http_adapter.max_retries = Retry.from_int(self._http_max_retries)
		logger.debug("Connected to service %s", self.base_url)
		self._connected = True

	def disconnect(self):
		if self._connected:
			try:
				self.execute_rpc('backend_exit')
			except Exception:  # pylint: disable=broad-except
				pass
			self._connected = False


