"""set_program must not cost a slot its program.

A stored #19 body can hold fields a ProgramSpec does not model (the app writes
dates, last-change stamps and delays) and a PACKED #8. A WT25G2 (fw0096) stores
a spec-only body that carries the slot's own values as an empty slot. These
tests pin the two guards: a merging class sends an unchanged program back as the
device's own bytes, and any class puts a slot back when a write emptied it.
"""
from __future__ import annotations

import asyncio

from orbit_bhyve.devices import protobuf as tx
from orbit_bhyve.devices import status as rx
from orbit_bhyve.devices.base import DeviceState, ProgramSpec
from orbit_bhyve.devices.ht25g2 import BHyveHT25G2Device
from orbit_bhyve.devices.wt25g2 import BHyveWT25G2Device

ANCHOR = "2026-01-01T00:00:00+00:00"


def _stored_body_a() -> bytes:
    """A #19 body in the shape the app stores: slot A, every 3 days from
    ANCHOR, 06:00 as a PACKED #8, station 1 (0-indexed) for 600 s, budget 100,
    plus fields the spec does not model (#11 start date, #13 last change, #14
    last-change id, #21 origin date)."""
    return (
        tx._pb_field_varint(1, 1)
        + tx._pb_field_bytes(4, tx._pb_field_varint(1, 3) + tx._pb_field_bytes(2, ANCHOR.encode()))
        + tx._pb_field_bytes(8, tx._pb_varint(360))
        + tx._pb_field_bytes(9, tx._pb_field_varint(1, 1) + tx._pb_field_varint(2, 600))
        + tx._pb_field_varint(10, 100)
        + tx._pb_field_varint(11, 1767225600)
        + tx._pb_field_varint(13, 1767228834)
        + tx._pb_field_varint(14, 2)
        + tx._pb_field_varint(21, 1767225600)
    )


def _spec_a(minutes: int = 10) -> ProgramSpec:
    """A one-zone every-3-days program for slot A, as _spec_from_call builds it."""
    return ProgramSpec(
        slot=1, day_mode="interval", interval_days=3, interval_anchor=ANCHOR,
        start_mins=(360,), zones=((1, minutes * 60),), name="", budget=100, enabled=False,
    )


def _dump(*program_pbs: bytes, mask: int = 0) -> bytes:
    parts = [tx._build_message(p) for p in program_pbs]
    parts.append(tx._build_message(tx._build_set_active_programs_pb(mask)))
    return b"".join(parts)


class _Conn:
    """Records sends; each send_stream (a #10 read) returns the next canned dump."""

    def __init__(self, dumps):
        self._dumps = list(dumps)
        self.sent: list[bytes] = []

    async def send(self, frame: bytes, drain_ms: int = 1500):
        self.sent.append(frame)
        return [b"\x01"]

    async def send_stream(self, frame: bytes, drain_ms: int = 4000):
        return self._dumps.pop(0) if len(self._dumps) > 1 else self._dumps[0]

    async def disconnect(self):
        pass

    @property
    def is_connected(self):
        return True


def _make(cls):
    dev = object.__new__(cls)  # bypass the HA-heavy __init__
    dev.mac = "AA:BB:CC:DD:EE:FF"
    dev.state = DeviceState()
    dev.flow_counts_per_gallon = 433
    return dev


def _sent_bodies(sent: list[bytes]) -> list[bytes]:
    """The #19 body of every #19 write, in order."""
    out = []
    for f in sent:
        p19 = rx._pb_field(rx.pb_parse(rx.decode_inner(f) or b""), 19)
        if p19 is not None:
            out.append(bytes(p19))
    return out


def _ops(sent: list[bytes]) -> list[int]:
    return [rx.pb_parse(rx.decode_inner(f) or b"")[0][0] for f in sent]


# --- the encoder --------------------------------------------------------------

def test_spec_only_bytes_are_unchanged():
    # The classes that do not merge keep the exact bytes they had.
    assert tx._build_program_pb(_spec_a()).hex() == (
        "9a012d0801221d08031219323032362d30312d30315430303a30303a30302b30303a3030"
        "40e8024a05080110d8045064"
    )


def test_merge_of_an_unchanged_program_is_the_device_body():
    body = _stored_body_a()
    assert rx._pb_field(rx.pb_parse(tx._build_program_pb(_spec_a(), base=body)), 19) == body


def test_merge_changes_only_the_spec_fields():
    body = _stored_body_a()
    merged = rx.parse_program_body(rx._pb_field(rx.pb_parse(tx._build_program_pb(_spec_a(11), base=body)), 19))
    assert merged.zones == ((1, 660),) and merged.start_mins == (360,)
    kept = {n: raw for n, _w, raw in rx.pb_split_raw(merged.raw) if n in (11, 13, 14, 21)}
    assert kept == {n: raw for n, _w, raw in rx.pb_split_raw(body) if n in (11, 13, 14, 21)}


def test_split_raw_round_trips():
    body = _stored_body_a()
    assert b"".join(raw for _n, _w, raw in rx.pb_split_raw(body)) == body


# --- set_program --------------------------------------------------------------

def test_wt25g2_resends_an_unchanged_program_as_its_own_body():
    body = _stored_body_a()
    stored = tx._pb_field_bytes(19, body)
    dev = _make(BHyveWT25G2Device)
    dev.connection = _Conn([_dump(stored), _dump(stored)])
    assert asyncio.run(dev.set_program(_spec_a())) is True
    assert _sent_bodies(dev.connection.sent) == [body]


def test_hose_valve_keeps_the_spec_only_write():
    body = _stored_body_a()
    stored = tx._pb_field_bytes(19, body)
    dev = _make(BHyveHT25G2Device)
    dev.connection = _Conn([_dump(stored), _dump(tx._build_program_pb(_spec_a()))])
    assert asyncio.run(dev.set_program(_spec_a())) is True
    assert _sent_bodies(dev.connection.sent) == [rx._pb_field(rx.pb_parse(tx._build_program_pb(_spec_a())), 19)]


def test_a_write_that_empties_the_slot_puts_the_program_back():
    # The read-back after the store shows the slot empty.
    body = _stored_body_a()
    stored = tx._pb_field_bytes(19, body)
    emptied = tx._build_program_delete_pb(1)
    for cls in (BHyveWT25G2Device, BHyveHT25G2Device):
        dev = _make(cls)
        dev.connection = _Conn([_dump(stored), _dump(emptied), _dump(stored)])
        assert asyncio.run(dev.set_program(_spec_a())) is False
        bodies = _sent_bodies(dev.connection.sent)
        assert len(bodies) == 2 and bodies[1] == body   # the device's own body, verbatim
        # Nothing else is sent: no enable-mask or controller-mode write after a failed store.
        assert _ops(dev.connection.sent) == [19, 19]
        assert not dev.state.programs[1].empty


def test_an_empty_slot_is_not_restored():
    # Writing into a slot that was empty has nothing to put back.
    emptied = tx._build_program_delete_pb(1)
    dev = _make(BHyveWT25G2Device)
    dev.connection = _Conn([_dump(emptied), _dump(emptied)])
    assert asyncio.run(dev.set_program(_spec_a())) is False
    assert len(_sent_bodies(dev.connection.sent)) == 1
