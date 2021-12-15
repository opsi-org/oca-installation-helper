# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
This file is part of opsi - https://www.opsi.org
"""

import os
import re
import time
import types
import socket
import threading
from urllib.parse import urlparse
import gzip
import ipaddress
import requests
from requests.adapters import HTTPAdapter
from requests.packages import urllib3
from urllib3.util.retry import Retry
import msgpack
try:
	# pyright: reportMissingModuleSource=false
	import orjson as json  # pylint: disable=import-error
except ModuleNotFoundError:
	try:
		import ujson as json
	except ModuleNotFoundError:
		import json
import lz4.frame

from . import __version__, logger

urllib3.disable_warnings()

_GZIP_COMPRESSION = 'gzip'
_LZ4_COMPRESSION = 'lz4'
_DEFAULT_HTTP_PORT = 4444
_DEFAULT_HTTPS_PORT = 4447


class OpsiRpcError(Exception):
	ExceptionShortDescription = "Opsi rpc error"

class BackendAuthenticationError(Exception):
	ExceptionShortDescription = "Backend authentication error"

class BackendPermissionDeniedError(Exception):
	ExceptionShortDescription = "Backend permission denied error"

def no_export(func):
	func.no_export = True
	return func

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
		self._create_methods = True
		self._connected = False
		self._interface = None
		self._rpc_id = 0
		self._rpc_id_lock = threading.Lock()
		self._ca_cert_file = None
		self._verify_server_cert = False
		self._proxy_url = "system" # Use system proxy by default
		self._username = None
		self._password = None
		self._serialization = "auto"
		self._ip_version = "auto"
		self._connect_timeout = 10
		self._read_timeout = 60
		self._http_pool_maxsize = 10
		self._http_max_retries = 1
		self._session_lifetime = 150 # In seconds
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
			elif option == 'createmethods':
				self._create_methods = bool(value)
			elif option == 'connectionpoolsize' and value not in (None, ""):
				self._connection_pool_size = int(value)
			elif option == 'retry':
				if isinstance(value, int):
					self._http_max_retries = max(value, 0)
				elif not value:
					self._http_max_retries = 0
			elif option == 'connecttimeout' and value not in (None, ""):
				self._connect_timeout = int(value)
			elif option in ('readtimeout', 'timeout', 'sockettimeout') and value not in (None, ""):
				self._read_timeout = int(value)
			elif option == 'verifyservercert':
				self._verify_server_cert = bool(value)
			elif option == 'cacertfile' and value not in (None, ""):
				self._ca_cert_file = str(value)
			elif option == 'proxyurl':
				self._proxy_url = str(value) if value else None
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
			elif option == 'sessionlifetime' and value:
				self._session_lifetime = int(value)

		self._set_address(address)

		self._session = requests.Session()
		self._session.auth = (self._username or '', self._password or '')
		self._session.headers.update({
			"User-Agent": self._application
		})
		if session_id:
			if "=" in session_id:
				logger.confidential("Using session id passed: %s", session_id)
				cookie_name, cookie_value = session_id.split("=")
				self._session.cookies.set(
					cookie_name, cookie_value, domain=self.hostname
				)
			else:
				logger.warning("Invalid session id passed: %s", session_id)

		if self._proxy_url:
			# Use a proxy
			if self._proxy_url.lower() != "system":
				self._session.proxies.update({
					"http": self._proxy_url,
					"https": self._proxy_url,
				})
				for key in ("http_proxy", "https_proxy"):
					if key in os.environ:
						del os.environ[key]
			no_proxy = [x.strip() for x in os.environ.get("no_proxy", "").split(",") if x.strip()]
			if no_proxy != ["*"]:
				no_proxy.extend(["localhost", "127.0.0.1", "ip6-localhost", "::1"])
			os.environ["no_proxy"] = ",".join(set(no_proxy))
			logger.info(
				"Using proxy settings: http_proxy='%s', https_proxy='%s', no_proxy='%s'",
				os.environ.get("http_proxy"),
				os.environ.get("https_proxy"),
				os.environ.get("no_proxy")
			)
		else:
			# Do not use a proxy
			os.environ['no_proxy'] = '*'

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
	def session_id(self):
		if not self._session.cookies or not self._session.cookies._cookies:  # pylint: disable=protected-access
			return None
		for tmp1 in self._session.cookies._cookies.values():  # pylint: disable=protected-access
			for tmp2 in tmp1.values():
				for cookie in tmp2.values():
					return f"{cookie.name}={cookie.value}"
		return None

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
		if not self._interface and self._create_methods:
			self.connect()
		return self._interface

	def backend_getInterface(self):
		return self.interface

	@no_export
	def getInterface(self):
		return self.interface

	@no_export
	def set_compression(self, compression):
		if isinstance(compression, bool):
			self._compression = compression
		else:
			compression = str(compression).strip().lower()
			if compression in ('true', 'false'):
				self._compression = compression == "true"
			elif compression == _GZIP_COMPRESSION:
				self._compression = _GZIP_COMPRESSION
			elif compression == _LZ4_COMPRESSION:
				self._compression = _LZ4_COMPRESSION
			else:
				self._compression = False

	setCompression = set_compression

	@no_export
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

		hostname = str(url.hostname)
		if ":" in hostname:
			hostname = f"[{hostname}]"
		self.base_url = f"{url.scheme}://{hostname}:{port}{path}"
		if url.username and not self._username:
			self._username = url.username
		if url.password and not self._password:
			self._password = url.password

	@no_export
	def execute_rpc(self, method, params=None):  # pylint: disable=too-many-branches,too-many-statements,too-many-locals
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

		serialization = self._serialization
		if serialization == "auto":
			serialization = "json"
			sv = self.server_version
			if sv and (sv[0] > 4 or (sv[0] == 4 and sv[1] > 1)):
				serialization = "msgpack"

		if serialization == "msgpack":
			headers['Accept'] = headers['Content-Type'] = 'application/msgpack'
			data = msgpack.dumps(data)
		else:
			headers['Accept'] = headers['Content-Type'] = 'application/json'
			data = json.dumps(data)

		if not isinstance(data, bytes):
			data = data.encode("utf-8")

		if self._compression:
			compression = self._compression
			if compression is True:
				# Auto choose by server version
				# Do not compress if opsi server version < 4.2
				# opsiconfd 4.2.0.96 (uvicorn)
				compression = None
				sv = self.server_version
				if sv and (sv[0] > 4 or (sv[0] == 4 and sv[1] > 1)):
					compression = _LZ4_COMPRESSION

			if compression == _LZ4_COMPRESSION:
				logger.trace("Compressing data with lz4")
				headers['Content-Encoding'] = 'lz4'
				headers['Accept-Encoding'] = 'lz4'
				data = lz4.frame.compress(data, compression_level=0, block_linked=True)
			elif compression == _GZIP_COMPRESSION:
				logger.trace("Compressing data with gzip")
				headers['Content-Encoding'] = 'gzip'
				headers['Accept-Encoding'] = 'gzip'
				data = gzip.compress(data)

		timeout = self._read_timeout

		logger.info(
			"JSONRPC request to %s: ip_version=%s, id=%d, method=%s, Content-Type=%s, Content-Encoding=%s, timeout=%d",
			self.base_url, self._ip_version, rpc_id, method,
			headers.get('Content-Type', ''), headers.get('Content-Encoding', ''), timeout
		)
		start_time = time.time()
		response = self._session.post(self.base_url, headers=headers, data=data, stream=True, timeout=timeout)

		content_type = response.headers.get("Content-Type", "")
		content_encoding = response.headers.get("Content-Encoding", "")
		logger.info(
			"Got response status=%s, Content-Type=%s, Content-Encoding=%s, duration=%0.3fs",
			response.status_code, content_type, content_encoding, (time.time() - start_time)
		)

		if 'server' in response.headers:
			self.server_name = response.headers.get('server')

		data = response.content
		# gzip and deflate transfer-encodings are automatically decoded
		if "lz4" in content_encoding:
			logger.trace("Decompressing data with lz4")
			data = lz4.frame.decompress(data)

		if content_type == "application/msgpack":
			data = msgpack.loads(data)
		else:
			data = json.loads(data)

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

	def _create_instance_methods(self):
		for method in self._interface:
			try:
				method_name = method['name']

				if method_name in ('backend_exit', 'backend_getInterface', 'jsonrpc_getSessionId'):
					continue

				logger.debug("Creating instance method: %s", method_name)

				args = method['args']
				varargs = method['varargs']
				keywords = method['keywords']
				defaults = method['defaults']

				arg_string = []
				call_string = []
				for i, argument in enumerate(args):
					if argument == 'self':
						continue

					if isinstance(defaults, (tuple, list)) and len(defaults) + i >= len(args):
						default = defaults[len(defaults) - len(args) + i]
						if isinstance(default, str):
							default = "{0!r}".format(default).replace('"', "'")  # pylint: disable=consider-using-f-string
						arg_string.append(f'{argument}={default}')
					else:
						arg_string.append(argument)
					call_string.append(argument)

				if varargs:
					for vararg in varargs:
						arg_string.append(f'*{vararg}')
						call_string.append(vararg)

				if keywords:
					arg_string.append(f'**{keywords}')
					call_string.append(keywords)

				arg_string = ', '.join(arg_string)
				call_string = ', '.join(call_string)

				logger.trace("%s: arg string is: %s", method_name, arg_string)
				logger.trace("%s: call string is: %s", method_name, call_string)
				exec(f'def {method_name}(self, {arg_string}): return self.execute_rpc("{method_name}", [{call_string}])')  # pylint: disable=exec-used
				setattr(self, method_name, types.MethodType(eval(method_name), self))  # pylint: disable=eval-used
			except Exception as err:  # pylint: disable=broad-except
				logger.critical("Failed to create instance method '%s': %s", method, err)

	@no_export
	def connect(self):
		logger.info("Connecting to service %s", self.base_url)
		if self._create_methods:
			self._interface = self.execute_rpc('backend_getInterface')
			self._create_instance_methods()
		self._http_adapter.max_retries = Retry.from_int(self._http_max_retries)
		logger.debug("Connected to service %s", self.base_url)
		self._connected = True

	@no_export
	def disconnect(self):
		if self._connected:
			try:
				self.execute_rpc('backend_exit')
			except Exception:  # pylint: disable=broad-except
				pass
			self._connected = False
