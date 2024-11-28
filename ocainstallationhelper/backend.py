"""
opsi-client-agent installation_helper backend class
"""

import platform

from opsicommon.client.opsiservice import ServiceClient, ServiceVerificationFlags, get_service_client

from ocainstallationhelper import get_mac_address, logger


class InstallationUnsuccessful(Exception):
	pass


class Backend:
	def __init__(self, address: str, username: str | None, password: str | None, sso: bool = False) -> None:
		self.service: ServiceClient = get_service_client(
			address=address,
			username=username,
			password=password,
			verify=ServiceVerificationFlags.ACCEPT_ALL,
			sso=sso,
			jsonrpc_create_objects=False,
		)

		self.service_address: str | None = self.service.base_url
		if platform.system().lower() == "windows":
			self.product_id = "opsi-client-agent"
		elif platform.system().lower() == "linux":
			self.product_id = "opsi-linux-client-agent"
		elif platform.system().lower() == "darwin":
			self.product_id = "opsi-mac-client-agent"
		else:
			raise ValueError(f"Platform {platform.system().lower()} unknown. Aborting.")

	def get_domain(self) -> str:
		return self.service.jsonrpc("getDomain")

	def put_client_into_group(self, client_id: str, group: str) -> None:
		try:
			found_group = self.service.jsonrpc("group_getObjects", [[], {"id": group, "type": "HostGroup"}])
			if not found_group:
				logger.warning("HostGroup %s not found. Creating...", group)
				self.service.jsonrpc("group_createHostGroup", [group])
			self.service.jsonrpc(
				"objectToGroup_createObjects",
				[
					{
						"type": "ObjectToGroup",
						"groupType": "HostGroup",
						"groupId": group,
						"objectId": client_id,
					}
				],
			)
			logger.notice("Added %s to group %s", client_id, group)
		except Exception as err:
			logger.warning("Adding %s to group %s failed: %s", client_id, group, err)

	def assign_client_to_depot(self, client_id: str, depot: str) -> None:
		try:
			self.service.jsonrpc(
				"configState_createObjects",
				[
					{
						"configId": "clientconfig.depot.id",
						"values": [depot],
						"objectId": client_id,
						"type": "ConfigState",
					}
				],
			)
			logger.notice("Assigned %s to depot %s", client_id, depot)
		except Exception as err:
			logger.warning("Assigning %s to depot %s failed: %s", client_id, depot, err)

	def set_poc_to_installing(self, product_id: str, client_id: str) -> None:
		self.service.jsonrpc(
			"productOnClient_createObjects",
			[
				[
					{
						"type": "ProductOnClient",
						"productType": "LocalbootProduct",
						"clientId": client_id,
						"productId": product_id,
						"installationStatus": "unknown",
						"actionRequest": "none",
						"actionProgress": "installing",
					}
				]
			],
		)

	def set_product_property(self, client_id: str, property_id: str, value: list[str] | str | bool) -> None:
		self.service.jsonrpc(
			"productPropertyState_createObjects",
			[
				[
					{
						"type": "ProductPropertyState",
						"productId": self.product_id,
						"propertyId": property_id,
						"objectId": client_id,
						"values": value if isinstance(value, list) else [value],  # type: ignore
					}
				]
			],
		)

	def evaluate_success(self, client_id: str) -> None:
		product_on_client = self.service.jsonrpc("productOnClient_getObjects", [[], {"productId": self.product_id, "clientId": client_id}])
		if not product_on_client or not product_on_client[0]:
			raise InstallationUnsuccessful(f"Product {self.product_id} not found on client {client_id}")
		if not product_on_client[0]["installationStatus"] == "installed":
			raise InstallationUnsuccessful(f"Installation of {self.product_id} on client {client_id} unsuccessful")

	def get_or_create_client(self, client_id: str, force_create: bool = False, set_mac_address: bool = True) -> dict[str, str]:
		clients = self.service.jsonrpc("host_getObjects", [[], {"id": client_id}])
		logger.debug("Got client objects: %r", clients)
		if not clients or force_create:
			# id, opsiHostKey, description, notes, hardwareAddress, ipAddress,
			# inventoryNumber, oneTimePassword, created, lastSeen
			client_args = [client_id, None, None, None, get_mac_address()]
			logger.info("Creating client: %s", client_args)
			self.service.jsonrpc("host_createOpsiClient", client_args)
			clients = self.service.jsonrpc("host_getObjects", [[], {"id": client_id}])
			logger.debug("Got client objects: %r", clients)
			if not clients:
				raise RuntimeError(f"Failed to create client {clients}")
			logger.info("Client created")

		# If no hardwareAddress is set on client object, add it
		if set_mac_address and not clients[0]["hardwareAddress"]:
			logger.info("Setting mac address to fill previously empty entry.")
			clients[0]["hardwareAddress"] = get_mac_address()
			self.service.jsonrpc("host_updateObjects", clients)

		return clients[0]
