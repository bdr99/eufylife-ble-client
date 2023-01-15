import asyncio
import base64
import hashlib
import logging
import uuid

from . import util

_LOGGER = logging.getLogger(__name__)

IV = b"0000000000000000"

class AuthHandler:
    _c1_data = bytearray()

    def __init__(self, address: str, loop: asyncio.AbstractEventLoop) -> None:
        self._address = address
        self._c1_future = loop.create_future()
        self._c3_future = loop.create_future()

    @property
    def encrypted_uuid(self) -> str:
        encrypted_bytes = util.encrypt_aes128cbc(bytes(self._uuid, "utf-8"), self._key, IV)
        return base64.b64encode(encrypted_bytes).hex()

    @property
    def encrypted_combined_uuid(self) -> str:
        combined_uuid = f"{self._uuid}_{self._device_uuid}"
        encrypted_bytes = util.encrypt_aes128cbc(bytes(combined_uuid, "utf-8"), self._key, IV)
        return base64.b64encode(encrypted_bytes).hex()

    @property
    def auth_successful(self) -> bool:
        return self._auth_successful

    @property
    def c1_future(self) -> str:
        return self._c1_future

    @property
    def c3_future(self) -> str:
        return self._c3_future

    def generate_key(self):
        self._key = hashlib.md5(self._address.replace(":", "").upper().encode("utf-8")).digest()
        _LOGGER.debug(f"key: {self._key}")

        self._uuid = str(uuid.uuid4())[0:15]
        _LOGGER.debug(f"uuid: {self._uuid}")

    def handle_c1(self, data: bytes):
        if data[0] != 0xC1:
            return

        total_segments = data[1]
        current_segment = data[2]
        payload = data[4:-1]

        self._c1_data.extend(payload)

        if current_segment == total_segments - 1:
            self._device_uuid = util.decrypt_aes128cbc(base64.b64decode(self._c1_data), self._key, IV).decode("utf-8")
            self._c1_future.set_result(self._device_uuid)

    def handle_c3(self, data: bytes):
        if data[0] != 0xC3 or len(data) < 5:
            return

        self._auth_successful = (data[4] == 0)
        self._c3_future.set_result(self._auth_successful)
