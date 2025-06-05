"""
opsi-client-agent installation_helper backend class
"""

import platform
from pathlib import Path

from opsicommon.client.opsiservice import ServiceClient, ServiceVerificationFlags, get_service_client
from opsicommon.objects import OpsiClient, ProductOnClient

from ocainstallationhelper import logger
from ocainstallationhelper.utils import get_mac_address


class InstallationUnsuccessful(Exception):
	pass


class Backend:
	def __init__(self, address: str, username: str | None, password: str | None, sso: bool = False) -> None:
		logger.debug("Creating service connection to %s (sso=%s)", address, sso)
		self.service: ServiceClient = get_service_client(
			address=address,
			username=username,
			password=password,
			verify=ServiceVerificationFlags.ACCEPT_ALL,
			sso=sso,
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
						"installationStatus": "not_installed",
						"actionRequest": "setup",
						"actionProgress": "installing",
					}
				]
			],
		)

	def get_pocs(self, product_id: str, client_id: str) -> list[ProductOnClient]:
		return self.service.jsonrpc("productOnClient_getObjects", [[], {"clientId": client_id, "productId": product_id}])

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
		product_on_client = self.get_pocs(self.product_id, client_id)
		if not product_on_client or not product_on_client[0]:
			raise InstallationUnsuccessful(f"Product {self.product_id} not found on client {client_id}")
		if not product_on_client[0].installationStatus == "installed":
			raise InstallationUnsuccessful(f"Installation of {self.product_id} on client {client_id} unsuccessful")

	def get_or_create_client(self, client_id: str, force_create: bool = False, set_mac_address: bool = True) -> OpsiClient:
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
		if set_mac_address and not clients[0].hardwareAddress:
			logger.info("Setting mac address to fill previously empty entry.")
			clients[0].hardwareAddress = get_mac_address()
			self.service.jsonrpc("host_updateObjects", clients)

		return clients[0]

	def get_from_depot(self, product: str, destination: Path) -> None:
		logger.notice("Downloading product '%s' to '%s' from depot", product, destination)
		self.service.download(f"/depot/{product}", destination)

	def get_configserver_id(self) -> str:
		return self.service.jsonrpc("host_getObjects", [[], {"type": "OpsiConfigserver"}])[0].id

	def get_available_oca_version(self) -> str:
		"""
		Get the available OCA version from the service.
		"""
		try:
			configserver = self.get_configserver_id()
			version = self.service.jsonrpc("productOnDepot_getObjects", [[], {"productId": self.product_id, "depotId": configserver}])[
				0
			].productVersion
			logger.info("Available OCA version: %s", version)
			return version
		except Exception as e:
			logger.error("No %s package available on depot: %s", self.product_id, e)
			raise InstallationUnsuccessful(f"No {self.product_id} package available on depot: {e}") from e

	def get_depot_id(self, client_id: str) -> str:
		"""
		Get the depot ID for a given client.
		"""
		try:
			depot_id = self.service.jsonrpc("configState_getClientToDepotserver", [[], [client_id]])[0]["depotId"]
			logger.debug("Depot ID for client %s: %s", client_id, depot_id)
			return depot_id
		except Exception as e:
			logger.error("Failed to get depot ID for client %s: %s", client_id, e)
			raise InstallationUnsuccessful(f"Failed to get depot ID for client {client_id}: {e}") from e
