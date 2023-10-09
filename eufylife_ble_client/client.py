from __future__ import annotations

import asyncio
from collections.abc import Callable
import logging
from typing import Any, TypeVar

from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from bleak.backends.service import BleakGATTCharacteristic, BleakGATTServiceCollection
from bleak.exc import BleakDBusError
from bleak_retry_connector import BleakClientWithServiceCache, establish_connection

from .auth_handler import AuthHandler
from .models import DeviceModel, EufyLifeBLEState
from . import util

MODEL_TO_NAME = {
    "eufy T9140": "Smart Scale",
    "eufy T9146": "Smart Scale C1",
    "eufy T9147": "Smart Scale P1",
    "eufy T9148": "Smart Scale P2",
    "eufy T9149": "Smart Scale P2 Pro",
}

MODELS: dict[str, DeviceModel] = {
    "eufy T9140": DeviceModel(
        name="Smart Scale",
        advertisement_data_contains_state=False,
        auth_characteristics=[],
        notify_characteristics=["4143f7b2-5300-4900-4700-414943415245", "4143f6b2-5300-4900-4700-414943415245", "0000ffb2-0000-1000-8000-00805f9b34fb"],
        write_characteristics=["4143f7b1-5300-4900-4700-414943415245", "4143f6b1-5300-4900-4700-414943415245", "0000ffb1-0000-1000-8000-00805f9b34fb"],
        battery_characteristics=["00002A19-0000-1000-8000-00805f9b34fb"]
    ),
    "eufy T9146": DeviceModel(
        name="Smart Scale C1",
        advertisement_data_contains_state=True,
        auth_characteristics=[],
        notify_characteristics=["0000FFF4-0000-1000-8000-00805f9b34fb"],
        write_characteristics=["0000FFF1-0000-1000-8000-00805f9b34fb"],
        battery_characteristics=["00002A19-0000-1000-8000-00805f9b34fb"]
    ),
    "eufy T9147": DeviceModel(
        name="Smart Scale P1",
        advertisement_data_contains_state=True,
        auth_characteristics=[],
        notify_characteristics=["0000FFF4-0000-1000-8000-00805f9b34fb"],
        write_characteristics=["0000FFF1-0000-1000-8000-00805f9b34fb"],
        battery_characteristics=["00002A19-0000-1000-8000-00805f9b34fb"]
    ),
    "eufy T9148": DeviceModel(
        name="Smart Scale P2",
        advertisement_data_contains_state=True,
        auth_characteristics=["0000FFF4-0000-1000-8000-00805f9b34fb"],
        notify_characteristics=["0000FFF2-0000-1000-8000-00805f9b34fb"],
        write_characteristics=["0000FFF1-0000-1000-8000-00805f9b34fb"],
        battery_characteristics=["00002A19-0000-1000-8000-00805f9b34fb"]
    ),
    "eufy T9149": DeviceModel(
        name="Smart Scale P2 Pro",
        advertisement_data_contains_state=True,
        auth_characteristics=["0000FFF4-0000-1000-8000-00805f9b34fb"],
        notify_characteristics=["0000FFF2-0000-1000-8000-00805f9b34fb"],
        write_characteristics=["0000FFF1-0000-1000-8000-00805f9b34fb"],
        battery_characteristics=["00002A19-0000-1000-8000-00805f9b34fb"]
    )
}

BLEAK_BACKOFF_TIME = 0.25

WrapFuncType = TypeVar("WrapFuncType", bound=Callable[..., Any])

DISCONNECT_DELAY = 120

RETRY_BACKOFF_EXCEPTIONS = (BleakDBusError,)

_LOGGER = logging.getLogger(__name__)
DEFAULT_ATTEMPTS = 3

class EufyLifeBLEDevice:
    _operation_lock = asyncio.Lock()
    _state = EufyLifeBLEState()
    _connect_lock: asyncio.Lock = asyncio.Lock()
    _auth_char: BleakGATTCharacteristic | None = None
    _notify_char: BleakGATTCharacteristic | None = None
    _write_char: BleakGATTCharacteristic | None = None
    _battery_char: BleakGATTCharacteristic | None = None
    _disconnect_timer: asyncio.TimerHandle | None = None
    _client: BleakClientWithServiceCache | None = None
    _callbacks: list[Callable[[EufyLifeBLEState], None]] = []
    _battery_level: int | None = None

    def __init__(self, model: str) -> None:
        """Initialize the EufyLifeBLEDevice."""
        self._model_id = model
        self._model = MODELS[model]

        self._loop = asyncio.get_running_loop()

    def set_ble_device_and_advertisement_data(
        self, ble_device: BLEDevice, advertisement_data: AdvertisementData
    ) -> None:
        """Set the BLE device and advertisement data."""
        self._ble_device = ble_device
        if self._model.advertisement_data_contains_state:
            self.update_state_from_advertisement_data(advertisement_data)

    @property
    def advertisement_data_contains_state(self) -> bool:
        """Return whether the advertisement data contains the state for this model."""
        return self._model.advertisement_data_contains_state

    @property
    def supports_heart_rate(self) -> bool:
        """Return whether the device supports heart rate measurements."""
        return self._model_id == "eufy T9149"

    @property
    def is_connected(self) -> bool:
        """Return whether the device is connected."""
        return self._client and self._client.is_connected

    @property
    def address(self) -> str:
        """Return the address."""
        return self._ble_device.address

    @property
    def state(self) -> EufyLifeBLEState:
        """Return the state."""
        return self._state

    @property
    def battery_level(self) -> int | None:
        """Return the battery level as a percentage (0 - 100), if known."""
        return self._battery_level

    async def connect(self) -> None:
        await self._ensure_connected()
        await self._read_battery_level()

    async def stop(self) -> None:
        """Stop the client."""
        _LOGGER.debug("%s: Stop", self._model_id)
        await self._execute_disconnect()

    def _set_state_and_fire_callbacks(self, state: EufyLifeBLEState) -> None:
        if self._state != state:
            self._state = state
            self._fire_callbacks()

    def _fire_callbacks(self) -> None:
        """Fire the callbacks."""
        for callback in self._callbacks:
            callback(self._state)

    def register_callback(
        self, callback: Callable[[EufyLifeBLEState], None]
    ) -> Callable[[], None]:
        """Register a callback to be called when the state changes."""

        def unregister_callback() -> None:
            self._callbacks.remove(callback)

        self._callbacks.append(callback)
        return unregister_callback

    async def _ensure_connected(self) -> None:
        """Ensure connection to device is established."""
        if self._connect_lock.locked():
            _LOGGER.debug(
                "%s: Connection already in progress, waiting for it to complete",
                self._model_id
            )
        if self.is_connected:
            self._reset_disconnect_timer()
            return
        async with self._connect_lock:
            # Check again while holding the lock
            if self.is_connected:
                self._reset_disconnect_timer()
                return
            _LOGGER.debug("%s: Connecting", self._model_id)
            client = await establish_connection(
                BleakClientWithServiceCache,
                self._ble_device,
                self._model_id,
                self._disconnected_callback,
                use_services_cache=True,
                ble_device_callback=lambda: self._ble_device,
            )
            _LOGGER.debug("%s: Connected", self._model_id)
            resolved = self._resolve_characteristics(client.services)
            if not resolved:
                # Try to handle services failing to load
                resolved = self._resolve_characteristics(await client.get_services())

            self._client = client
            self._reset_disconnect_timer()

            _LOGGER.debug(
                "%s: Subscribe to notifications", self._model_id
            )
            await client.start_notify(self._notify_char, self._notification_handler)
            if self._auth_char is not None:
                await client.start_notify(self._auth_char, self._notification_handler_auth)

            await self._authenticate_if_needed()

    async def _authenticate_if_needed(self):
        if self._model_id not in ["eufy T9148", "eufy T9149"]:
            return

        self._auth_handler = AuthHandler(self._ble_device.address, self._loop)
        self._auth_handler.generate_key()

        c0_sub_contract_bytes = util.get_sub_contract_bytes(self._auth_handler.encrypted_uuid, "C0")
        for hex_str in c0_sub_contract_bytes:
            _LOGGER.debug(f"writing {hex_str}")
            await self._client.write_gatt_char(self._write_char, bytearray.fromhex(hex_str))
            await asyncio.sleep(1)

        _LOGGER.debug("waiting for c1 reply")
        device_uuid = await self._auth_handler.c1_future
        _LOGGER.debug(f"got device_uuid: {device_uuid}")

        c2_sub_contract_bytes = util.get_sub_contract_bytes(self._auth_handler.encrypted_combined_uuid, "C2")
        for hex_str in c2_sub_contract_bytes:
            _LOGGER.debug(f"writing {hex_str}")
            await self._client.write_gatt_char(self._write_char, bytearray.fromhex(hex_str))

        _LOGGER.debug("waiting for C3 reply")
        await self._auth_handler.c3_future
        if not self._auth_handler.auth_successful:
            _LOGGER.error("Auth failure")
        else:
            _LOGGER.debug("Auth successful")

    def update_state_from_advertisement_data(self, advertisement_data: AdvertisementData) -> None:
        manufacturer_data = advertisement_data.manufacturer_data
        if not manufacturer_data:
            return

        data = list(manufacturer_data.values())[-1]

        if self._model_id in ["eufy T9146", "eufy T9147"]:
            if len(data) == 18 and data[4] == 0xCF:
                data_range = data[4:15]
                if util.validate_checksum(data_range):
                    self._handle_weight_update_t9146_t9147(data_range)
        elif self._model_id in ["eufy T9148", "eufy T9149"]:
            if len(data) == 19 and data[6] == 0xCF:
                self._handle_advertisement_weight_update_t9148_t9149(data[6:])

    def _handle_advertisement_weight_update_t9148_t9149(self, data: bytearray) -> None:
        weight_kg = ((data[4] << 8) | data[3]) / 100
        is_final = data[9] == 0x00
        final_weight_kg = weight_kg if is_final else None
        has_heart_rate = (data[2] >> 6 == 0b11)
        heart_rate = data[1] if has_heart_rate else None
        if heart_rate == 0:
            heart_rate = None

        self._set_state_and_fire_callbacks(EufyLifeBLEState(weight_kg, final_weight_kg, heart_rate, False))

    def _handle_weight_update_t9140(self, data: bytearray) -> None:
        if len(data) < 7 or data[6] not in [0xCA, 0xCE]:
            return

        weight_kg = ((data[2] << 8) | data[3]) / 10
        is_final = data[6] == 0xCA
        final_weight_kg = weight_kg if is_final else None

        self._set_state_and_fire_callbacks(EufyLifeBLEState(weight_kg, final_weight_kg, None, False))

    def _handle_weight_update_t9146_t9147(self, data: bytearray) -> None:
        if len(data) != 11 or data[0] != 0xCF:
            return

        weight_kg = ((data[4] << 8) | data[3]) / 100
        is_final = data[9] == 0x00
        final_weight_kg = weight_kg if is_final else None
        weight_limit_exceeded = data[9] == 0x02

        self._set_state_and_fire_callbacks(EufyLifeBLEState(weight_kg, final_weight_kg, None, weight_limit_exceeded))

    def _handle_weight_update_t9148_t9149(self, data: bytearray) -> None:
        if len(data) != 16 or data[0] != 0xCF or data[2] != 0x00:
            return

        weight_kg = ((data[7] << 8) | data[6]) / 100
        #impedance = (data[10] << 16) | (data[9] << 8) | data[8]
        is_final = data[12] == 0x00
        final_weight_kg = weight_kg if is_final else None

        self._set_state_and_fire_callbacks(EufyLifeBLEState(weight_kg, final_weight_kg, None, False))

    def _notification_handler_auth(self, _sender: int, data: bytearray) -> None:
        """Handle notification responses on the auth characteristic."""
        _LOGGER.debug("%s: Auth notification received: %s", self._model_id, data.hex())

        if self._model_id in ["eufy T9148", "eufy T9149"]:
            if data[0] == 0xC1:
                self._auth_handler.handle_c1(data)
            elif data[0] == 0xC3:
                self._auth_handler.handle_c3(data)

    def _notification_handler(self, _sender: int, data: bytearray) -> None:
        """Handle notification responses."""
        _LOGGER.debug("%s: Notification received: %s", self._model_id, data.hex())

        if self._model_id == "eufy T9140":
            if len(data) >= 2 and data[0] == 0xAC and data[1] == 0x02:
                if len(data) == 16:
                    self._notification_handler(_sender, data[8:15])
                    self._notification_handler(_sender, data[0:8])
                elif len(data) == 17:
                    self._notification_handler(_sender, data[9:16])
                    self._notification_handler(_sender, data[0:9])
                else:
                    if len(data) >= 7 and data[6] in [0xCA, 0xCE]:
                        self._handle_weight_update_t9140(data)
        elif self._model_id in ["eufy T9146", "eufy T9147"]:
            if not util.validate_checksum(data):
                _LOGGER.debug("Checksum mismatch.")
                return
            if len(data) == 11 and data[0] == 0xCF:
                self._handle_weight_update_t9146_t9147(data)
        elif self._model_id in ["eufy T9148", "eufy T9149"]:
            if len(data) == 16 and data[0] == 0xCF and data[2] == 0x00:
                self._handle_weight_update_t9148_t9149(data)

    async def _read_battery_level(self):
        battery_bytes = await self._client.read_gatt_char(self._battery_char)
        if len(battery_bytes) == 1:
            self._battery_level = battery_bytes[0]
            self._fire_callbacks()

    def _reset_disconnect_timer(self) -> None:
        """Reset disconnect timer."""
        if self._disconnect_timer:
            self._disconnect_timer.cancel()
        self._disconnect_timer = self._loop.call_later(
            DISCONNECT_DELAY, self._disconnect
        )

    def _disconnected_callback(self, client: BleakClientWithServiceCache) -> None:
        """Disconnected callback."""
        self._state = None
        _LOGGER.debug(
            "%s: Disconnected from device", self._model_id
        )
        self._fire_callbacks()

    def _disconnect(self) -> None:
        """Disconnect from device."""
        self._disconnect_timer = None
        asyncio.create_task(self._execute_timed_disconnect())

    async def _execute_timed_disconnect(self) -> None:
        """Execute timed disconnection."""
        _LOGGER.debug(
            "%s: Disconnecting after timeout of %s",
            self._model_id,
            DISCONNECT_DELAY,
        )
        await self._execute_disconnect()

    async def _execute_disconnect(self) -> None:
        """Execute disconnection."""
        async with self._connect_lock:
            client = self._client
            auth_char = self._auth_char
            notify_char = self._notify_char
            self._expected_disconnect = True
            self._client = None
            self._auth_char = None
            self._notify_char = None
            self._write_char = None
            if client and client.is_connected:
                await client.stop_notify(notify_char)
                if auth_char is not None:
                    await client.stop_notify(auth_char)
                await client.disconnect()

    def _resolve_characteristics(self, services: BleakGATTServiceCollection) -> bool:
        """Resolve characteristics."""
        self._auth_char = self._resolve_characteristic(services, self._model.auth_characteristics)
        self._notify_char = self._resolve_characteristic(services, self._model.notify_characteristics)
        self._write_char = self._resolve_characteristic(services, self._model.write_characteristics)
        self._battery_char = self._resolve_characteristic(services, self._model.battery_characteristics)

        return bool((self._auth_char or len(self._model.auth_characteristics) == 0) and self._notify_char and self._write_char and self._battery_char)

    def _resolve_characteristic(self, services: BleakGATTServiceCollection, candidate_characteristics: list[str]):
        for characteristic in candidate_characteristics:
            if char := services.get_characteristic(characteristic):
                return char
