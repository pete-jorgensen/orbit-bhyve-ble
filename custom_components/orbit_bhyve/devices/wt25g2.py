"""WT25G2 (B-hyve Indoor/Outdoor sprinkler controller) device class.

A DIFFERENT PRODUCT LINE from the HT hose timers, despite the near-identical
model string. `WT` is Orbit's mains-powered multi-station controller, sold as
57946 (6-station) and 57950 (12-station) — and the cloud
record reports `type=sprinkler_timer` with `num_stations` of 6 or 12, where the
hose timers report 1-4. `HT25G2` (a single hose valve) and `WT25G2` (this) are
unrelated products; only the sticker rhymes.

Protocol: the SAME protobuf-over-CRC16 family as the HT34A XD and HT25G2 Gen2 —
frame magic 0x11, `aa775a0f` inner header, `OrbitPbApi_Message` schema. That is
hardware-verified, not inferred (WT25G2-0001, firmware 0096, 12 stations):

  * The GATT surface is byte-identical to `const.py`: service `fe32` with
    `6c71`/`6c72`/`6c73`/`6c76`.
  * The 20-byte challenge on `6c71` is answered with a real nonce, deriving a
    valid IV and CTR pair — the same handshake `connection.py` already does.
  * A `#15 getDeviceStatus {}` (`7a00`) sent on `6c72` returns a six-frame
    status burst on `6c73` that decrypts under the cloud `ble_network_key`
    with the CTR stream staying in sync across every frame. Frame 1 carries
    `aa775a0f` and the device's own MAC in protobuf field 1; later frames
    carry ASCII timestamps whose next-start value matched what the cloud
    reported for the same device.

Station count flows from the cloud record via `self.stations`, so a 12-station
controller needs no addressing override — the same reason the 4-port class
drives the 1- and 2-port HT31/HT32A unchanged.

⚠️ `has_flow` is deliberately left False. The Gen2 hose valve exposes an inline
flow sensor (#57/#59); whether a sprinkler controller does is unknown and
unprobed, and a stray #57 subscribe has wedged a valve before.
Prove it on hardware before turning it on.
"""
from __future__ import annotations

from .protobuf import BHyveProtobufDevice


class BHyveWT25G2Device(BHyveProtobufDevice):
    """Multi-station sprinkler controller (fw0096), protobuf protocol family."""

    log_label = "WT25G2"
