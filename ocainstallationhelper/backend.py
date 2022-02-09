"""
opsi-client-agent installation_helper backend class
"""

import platform
from typing import Dict

from opsicommon.client.jsonrpc import JSONRPCClient  # type: ignore[import]

from ocainstallationhelper import logger, get_mac_address


class Backend:
	def __init__(self, address: str = None, username: str = None, password: str = None) -> None:
		self.service: JSONRPCClient = JSONRPCClient(address=address, username=username, password=password)
		self.service_address: str = self.service.base_url

	def get_domain(self) -> str:
		return self.service.execute_rpc("getDomain")

	def put_client_into_group(self, client_id: str, group: str) -> None:
		try:
			self.service.execute_rpc(
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
		except Exception as err:  # pylint: disable=broad-except
			logger.warning("Adding %s to group %s failed: %s", client_id, group, err)

	def assign_client_to_depot(self, client_id: str, depot: str) -> None:
		try:
			self.service.execute_rpc(
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
		except Exception as err:  # pylint: disable=broad-except
			logger.warning("Assigning %s to depot %s failed: %s", client_id, depot, err)

	def set_poc_to_installing(self, product_id: str, client_id: str) -> None:
		self.service.execute_rpc(
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

	def evaluate_success(self, client_id: str) -> None:
		if platform.system().lower() == "windows":
			product_id = "opsi-client-agent"
		elif platform.system().lower() == "linux":
			product_id = "opsi-linux-client-agent"
		elif platform.system().lower() == "darwin":
			product_id = "opsi-mac-client-agent"
		else:
			raise ValueError(f"Platform {platform.system().lower()} unknown. Aborting.")

		product_on_client = self.service.execute_rpc("productOnClient_getObjects", [[], {"productId": product_id, "clientId": client_id}])
		if not product_on_client or not product_on_client[0]:
			raise ValueError(f"Product {product_id} not found on client {client_id}")
		if not product_on_client[0].installationStatus == "installed":
			raise ValueError(f"Installation of {product_id} on client {client_id} unsuccessful")

	def get_or_create_client(self, client_id: str, force_create: bool = False) -> Dict[str, str]:
		client = self.service.execute_rpc("host_getObjects", [[], {"id": client_id}])
		if not client or force_create:
			# id, opsiHostKey, description, notes, hardwareAddress, ipAddress,
			# inventoryNumber, oneTimePassword, created, lastSeen
			client_config = [client_id, None, None, None, get_mac_address()]
			logger.info("Creating client: %s", client_config)
			self.service.execute_rpc("host_createOpsiClient", client_config)
			client = self.service.execute_rpc("host_getObjects", [[], {"id": client_id}])
			if not client:
				raise RuntimeError(f"Failed to create client {client}")
			logger.info("Client created")

		logger.debug("got client objects %s", client)
		return client[0]
