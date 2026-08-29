"""Device-class registry + dispatcher.

Adding a future model: drop a new module under devices/ exposing a subclass
of BHyveBleDeviceBase with the right frame_magic / trailer_const / actuation
methods, then add a clause to resolve_device_class().
"""
from __future__ import annotations

from .base import BHyveBleDeviceBase, DeviceState, UnsupportedModel
from .hub import BHyveHubDevice
from .ht25 import BHyveHT25Device
from .ht25_fw0085 import BHyveHT25Fw0085Device
from .ht25g2 import BHyveHT25G2Device
from .ht34a import BHyveHT34ADevice
from .wt25g2 import BHyveWT25G2Device

__all__ = [
    "BHyveBleDeviceBase",
    "DeviceState",
    "UnsupportedModel",
    "BHyveHubDevice",
    "BHyveHT25Device",
    "BHyveHT25Fw0085Device",
    "BHyveHT25G2Device",
    "BHyveHT34ADevice",
    "BHyveWT25G2Device",
    "resolve_device_class",
    "build_device",
]


def resolve_device_class(*, hardware: str, firmware: str, type_: str) -> type[BHyveBleDeviceBase]:
    if type_ == "bridge":
        return BHyveHubDevice
    if (hardware or "").startswith("WT25"):
        # WT is a SEPARATE PRODUCT LINE from HT: the mains-powered multi-station
        # sprinkler controller (type=sprinkler_timer, 6 or 12 stations), not a
        # hose valve. Note WT25G2 vs HT25G2 — one letter, unrelated products. The
        # two prefixes cannot both match, so this clause needs no ordering against
        # the HT ones; it matches on its own prefix.
        #
        # Hardware-verified on WT25G2-0001 / fw0096 / 12 stations:
        # identical GATT surface, the 6c71 handshake answers, and a #15
        # getDeviceStatus returns a protobuf status burst that decrypts with the
        # CTR stream in sync. So the WT line speaks the same magic-0x11 protobuf
        # protocol as the XD family; station count flows from the cloud record.
        #
        # WT25-0001 (Gen1) routes here too, on the same basis upstream routes the
        # untested HT32A/HT34 siblings — same family, unverified. WT24 is
        # deliberately NOT matched: an older generation with no evidence either
        # way, and guessing there risks driving a controller with the wrong
        # protocol.
        return BHyveWT25G2Device
    if (hardware or "").startswith("HT25"):
        # Mesh d7-47 hose timers are the only HT25 devices ever observed
        # reporting the "-0000" hardware suffix — treat that as the
        # authoritative signal rather than pinning to a firmware whitelist,
        # which drifts every time Orbit ships a new build (e.g. a fw0098
        # HT25A-0001 unit, upstream issue #47). Everything else under the
        # HT25 prefix — HT25G2-0001, the bare HT25-0001 variant, or any
        # future firmware on either — speaks the protobuf protocol (frame
        # magic 0x11) like the HT34A XD. The explicit "HT25G2" prefix is
        # checked first since it's the strongest signal and should win over
        # the suffix heuristic even for an (unobserved) "HT25G2-0000".
        if (hardware or "").startswith("HT25G2"):
            return BHyveHT25G2Device
        if (hardware or "").endswith("-0000"):
            # fw0085 keeps upstream's thin subclass (retains
            # _rebind_sid_delta=3, community-verified); fw0041 and any other
            # fw use the parameterized base, which builds frames from the
            # device's own mesh_device_id (not a hardcoded identity).
            if firmware == "0085":
                return BHyveHT25Fw0085Device
            return BHyveHT25Device
        return BHyveHT25G2Device
    if (hardware or "").startswith("HT34"):
        # Both HT34A-0001 and HT34-0001 (fw0058) use the protobuf XD protocol.
        # The older HT34 sharing it is the stuartdenne fork's claim (2026-06-27),
        # not independently verified on hardware here.
        return BHyveHT34ADevice
    if (hardware or "").startswith("HT32"):
        # HT32A-0001 (fw0107) is the 2-port XD sibling of the HT34A: same
        # firmware, same protobuf-over-CRC16 protocol (magic 0x11), fewer
        # stations. Station count flows from the cloud record, so the 4-port
        # class handles a 2-port unit unchanged. Untested on hardware here
        # (issue #13) — same caveat as HT34A.
        return BHyveHT34ADevice
    if (hardware or "").startswith("HT31"):
        # HT31-0001 "Smart Hose Tap Timer" (fw0058): single-port sibling of
        # the XD family — same fw0058 protobuf-over-CRC16 protocol (magic
        # 0x11) as HT34-0001. Hardware-verified end-to-end (status/battery
        # polling + valve actuation with water observed) on five fw0058
        # units, 2026-07-12. Station count flows from the cloud record, so
        # the 4-port class handles the 1-port unit unchanged.
        return BHyveHT34ADevice
    raise UnsupportedModel(hardware or "?", firmware or "?")


def build_device(hass, record, **kwargs) -> BHyveBleDeviceBase:
    cls = resolve_device_class(
        hardware=record.get("hardware", ""),
        firmware=record.get("firmware", ""),
        type_=record.get("type", ""),
    )
    return cls(hass, record, **kwargs)
