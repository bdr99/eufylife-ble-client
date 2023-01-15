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
    weight_kg: float
    final_weight_kg: float
    heart_rate: float
    max_weight_exceeded: bool
