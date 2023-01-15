from __future__ import annotations

from dataclasses import dataclass

@dataclass
class DeviceModel:
    """Class to describe a device model."""
    name: str
    advertisement_data_contains_state: bool

    notify_characteristic: str
    write_characteristic: str
    battery_characteristic: str

    auth_characteristic: str | None = None

@dataclass(frozen=True)
class EufyLifeBLEState:
    weight_kg: float = 0
    heart_rate: float = 0
    is_final: bool = False
    max_weight_exceeded: bool = False
