"""Pooled BLE connection layer shared by all device classes.

Owns: AES handshake, keystream cipher, frame I/O, write lock, idle disconnect.
Per-device-class knobs: frame_magic, trailer_const, post_handshake_hook.

Cipher (verified against 257 captured frames + actuated commands):
  AES-128-ECB used as a CTR-style keystream — block = IV(12B) || ctr_LE(4B),
  encrypted, XORed with plaintext.
  IV = init_rx[0:4] || init_tx[4:12].
  TX counter = uint32_LE(init_tx[12:16]); RX counter = init_tx[16:20].
  Frame = [magic][len][ciphertext (len bytes)][trailer u16_LE].
  Trailer = sum(plaintext) + trailer_const + len.
Commands use WRITE_REQ (response=True) for its ATT delivery ack; char 6c72 also
advertises write-without-response, and both modes have been observed to actuate
the HT34A (fw0107), so WRITE_REQ is a safe default across device classes. The
device's higher-level ack is a NOTIFICATION, not an ATT Write Response — the
ESPHome BLE proxy never relays the (absent) write response, so writes wait only
a capped WRITE_ACK_TIMEOUT_SEC and the notification drain is the real ack.
"""
from __future__ import annotations

import asyncio
import logging
import os
import struct
from collections.abc import Awaitable, Callable

from bleak import BleakClient
from bleak.exc import BleakError
from bleak_retry_connector import establish_connection
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .const import AES_CHAR, READ_CHAR, WRITE_CHAR

_LOGGER = logging.getLogger(__name__)

# A connect can succeed on a weak/proxy link while the post-connect handshake
# (subscribe + AES write/read) stalls with no natural timeout — wedging the
# pooled connection for ~30s and leaking it. Bound the handshake and retry the
# whole open, disconnecting between tries; healthy links pass on attempt 1.
HANDSHAKE_TIMEOUT_SEC = 10.0
OPEN_MAX_ATTEMPTS = 3

# The device acks a command via NOTIFICATION, not an ATT Write Response. Over a
# direct link the (unused) write response still arrives in <200ms, but over an
# ESPHome BLE proxy it is never relayed — so a response=True write would block
# ~30s. Cap the wait; the notification drain in send() is the real ack.
WRITE_ACK_TIMEOUT_SEC = 0.8

# Event-driven drain: the reply usually lands in 50-150ms and a status burst
# arrives as a few frames, but an ack-then-status reply can gap ~150ms between
# the small ack and the richer #16 status (observed 147ms in a live capture).
# So after the first frame, keep the drain window open only until no new frame
# has arrived for this long — returning ~4x faster than sleeping the full
# drain_ms, without truncating a multi-frame reply. drain_ms remains the hard cap.
NOTIF_QUIET_SEC = 0.35

PostHandshakeHook = Callable[["BHyveBleConnection"], Awaitable[None]]
PlaintextObserver = Callable[[bytes], None]


def advertised_name_for(cloud_mac: str) -> str:
    """The BLE local name a B-Hyve advertises, derived from its CLOUD mac.

    Orbit builds the name from the last three octets of the address the cloud
    reports: 44:67:55:0A:1B:2C -> "bhyve_0A1B2C".
    """
    return "bhyve_" + cloud_mac.replace(":", "").replace("-", "")[-6:].upper()


def match_advertised(cloud_mac: str, infos) -> str | None:
    """Find the BLE address of the device advertising this cloud MAC's name.

    WHY THIS EXISTS. `_open` looks up `self._ble_address or self.mac` and calls
    this whenever that resolves to no connectable adapter — for any device. On a
    BLE-only hose timer the cloud address IS the BLE address, so a failed lookup
    means out of range and this finds nothing either. A mains, Wi-Fi-native
    controller (the WT25 sprinkler line) has TWO radios with TWO addresses and the
    cloud reports the WI-FI one, so the first open of one always misses and this
    is the path that connects: on a WT25G2-0001, cloud/Wi-Fi 44:67:55:0A:1B:2C
    answers to BLE 44:67:55:1A:1B:2C, and without this the device is unreachable —
    "not in range of any connectable BLE adapter" — while sitting right there,
    advertising. The address it returns is cached in `_ble_address`, so later opens
    go straight to it and come back here only if it goes stale.

    The two addresses differed only in the 4th octet, but ONE sample is not a
    rule and a wrong guess dials a stranger's device, so this deliberately
    does NOT extrapolate an offset. It matches on the advertised local name,
    which the device derives from the last three octets of its Wi-Fi MAC — a
    link to the cloud record rather than a guess at an offset, though only the
    last three octets of it. A second device advertising the same name would be
    resolved by iteration order — and NOT rejected at handshake time: `_handshake`
    derives the IV and both counters from the nonce exchange alone and never
    consults the network key, so it succeeds against any B-Hyve. The backstop is
    the CTR-desync self-heal, which fires when the wrong device's replies fail the
    header check; the resolved address is dropped with it, so the next open
    re-resolves rather than returning to the same wrong device.

    `infos` is any iterable of objects with `.name` and `.address`.
    """
    want = advertised_name_for(cloud_mac).lower()
    for info in infos:
        if (getattr(info, "name", None) or "").lower() == want:
            return getattr(info, "address", None)
    return None


class BHyveBleConnection:
    """One per physical device. Reused across commands within an idle window."""

    def __init__(
        self,
        hass,
        mac: str,
        network_key: str,
        *,
        frame_magic: int = 0x10,
        trailer_const: int = 0x10,
        reply_header: bytes | None = None,
        idle_disconnect_sec: int = 60,
        gatt_settle_ms: int = 300,
    ):
        self.hass = hass
        self.mac = mac
        self._key = bytes.fromhex(network_key)
        self._frame_magic = frame_magic & 0xFF
        self._trailer_const = trailer_const & 0xFF
        # First-frame plaintext header used to detect a CTR desync. Protobuf
        # classes reply with the inner-message header b"\xaa\x77\x5a\x0f"; the
        # d7-47 mesh classes use a different frame shape ([mesh:2][type][seq]
        # [routing]...) that legitimately never starts with it, so they pass
        # None here to skip the header-based desync self-heal entirely.
        self._reply_header = reply_header
        self._idle_sec = idle_disconnect_sec
        self._gatt_settle_ms = gatt_settle_ms

        # Resolved lazily when the cloud MAC is not the BLE MAC (see match_advertised).
        self._ble_address: str | None = None
        self._client: BleakClient | None = None
        self._iv: bytes | None = None
        self._tx_ctr: int = 0
        self._rx_ctr: int = 0
        self._lock = asyncio.Lock()
        self._notif_buf: list[bytes] = []
        # Decrypted plaintext of each notification in the current burst, in arrival
        # order — parallel to _notif_buf. send_stream() concatenates these into one
        # CTR stream so a multi-frame reply (a #19 program body that spans frames)
        # can be reassembled. Populated in _on_notify right after a successful
        # decrypt; cleared by _reset_rx() before every write.
        self._notif_pt: list[bytes] = []
        self._notif_event = asyncio.Event()  # set on every notification; drives _drain
        self._last_rx_frame: bytes | None = None  # last raw RX frame, for de-dup
        # Partial inner message being reassembled from a multi-frame reply. See
        # _on_notify: a reply too long for one CTR block arrives as several outer
        # frames and only the FIRST carries the inner header. Reset by _reset_rx()
        # with the rest of the RX state — a partial reply must never be joined to
        # the next exchange's frames.
        self._assembly = bytearray()
        self._handshaken = False
        self._post_handshake_hook: PostHandshakeHook | None = None
        self._plaintext_observer: PlaintextObserver | None = None
        self._idle_timer: asyncio.TimerHandle | None = None
        # Session hold. While held the idle timer stays disarmed, so a link that
        # is only *receiving* isn't closed under it: _arm_idle_timer fires only
        # on writes, and the Gen1 flow subscription writes nothing after the
        # initial subscribe. See hold_open()/release().
        self._held = False
        self._hold_expiry: asyncio.TimerHandle | None = None

    @property
    def is_held(self) -> bool:
        """True while a caller is holding the session open. Callers that would
        otherwise tear the link down check this before disconnecting."""
        return self._held

    @property
    def is_connected(self) -> bool:
        return self._client is not None and self._client.is_connected

    def set_post_handshake_hook(self, hook: PostHandshakeHook | None) -> None:
        """Run a per-device-class init sequence right after the AES handshake.
        Used by HT25 for its 8-step bind-status-info dance."""
        self._post_handshake_hook = hook

    def set_plaintext_observer(self, observer: PlaintextObserver | None) -> None:
        """Receive every successfully decrypted notification plaintext.
        Lets a device class parse responses (battery, status, etc.) without
        re-decrypting — re-decrypt would advance the rx counter and desync
        subsequent frames."""
        self._plaintext_observer = observer

    async def ensure_connected(self) -> None:
        """Connect + handshake if not already pooled. _open() retries the whole
        connect+handshake OPEN_MAX_ATTEMPTS times internally: on a marginal proxy
        link the connect succeeds but the handshake GATT exchange can stall, and
        a clean retry usually gets through while the bounded handshake means we
        fail cleanly rather than wedging. Call inside a lock if you need
        exclusive access; idempotent otherwise."""
        if self.is_connected and self._handshaken:
            return
        # _open() already retries OPEN_MAX_ATTEMPTS times internally; don't wrap
        # it in a second retry loop or the attempts multiply (3x3=9 handshakes,
        # ~90-150s on a stalling device). One call = one bounded retry budget.
        try:
            await self._open()
        except (BleHandshakeError, asyncio.TimeoutError) as err:
            raise BleHandshakeError(f"{self.mac}: handshake failed: {err}") from err

    def _resolve_by_advertised_name(self):
        """Second chance when the cloud MAC is not the BLE MAC — see match_advertised."""
        from homeassistant.components.bluetooth import (
            async_ble_device_from_address,
            async_discovered_service_info,
        )

        address = match_advertised(self.mac, async_discovered_service_info(self.hass,
                                                                          connectable=True))
        if address is None:
            return None
        ble_device = async_ble_device_from_address(self.hass, address, connectable=True)
        if ble_device is not None and address != self._ble_address:
            _LOGGER.info(
                "%s: cloud MAC is not on the air; using BLE address %s, matched by the "
                "advertised name %s (a Wi-Fi-capable model advertises on a different "
                "radio than the cloud reports)",
                self.mac, address, advertised_name_for(self.mac),
            )
            self._ble_address = address
        return ble_device

    async def _open(self) -> None:
        from homeassistant.components.bluetooth import async_ble_device_from_address

        address = self._ble_address or self.mac
        ble_device = async_ble_device_from_address(self.hass, address, connectable=True)
        if ble_device is None:
            ble_device = self._resolve_by_advertised_name()
        if ble_device is None:
            raise BleNotConnectable(
                f"{self.mac}: not in range of any connectable BLE adapter "
                f"(and nothing is advertising as {advertised_name_for(self.mac)})")

        last_err: Exception | None = None
        for attempt in range(1, OPEN_MAX_ATTEMPTS + 1):
            try:
                _LOGGER.debug("%s: connecting (attempt %d/%d)", self.mac, attempt, OPEN_MAX_ATTEMPTS)
                self._client = await establish_connection(
                    BleakClient, ble_device, self.mac, max_attempts=3
                )
                _LOGGER.debug("%s: connected", self.mac)
                if self._gatt_settle_ms > 0:
                    await asyncio.sleep(self._gatt_settle_ms / 1000.0)
                # Bound the handshake: on a marginal link the connect succeeds
                # but the GATT exchange below can hang indefinitely.
                await asyncio.wait_for(self._handshake(), timeout=HANDSHAKE_TIMEOUT_SEC)
            except (asyncio.TimeoutError, BleakError, OSError, BleHandshakeError) as err:
                last_err = err
                _LOGGER.debug(
                    "%s: open attempt %d/%d failed: %s", self.mac, attempt, OPEN_MAX_ATTEMPTS, err
                )
                await self.disconnect()  # clean slate so the retry gets a fresh GATT window
                if attempt < OPEN_MAX_ATTEMPTS:
                    await asyncio.sleep(0.5)  # space out retries on a marginal link
                continue
            # Handshake succeeded — run the per-device-class init, then we're open.
            if self._post_handshake_hook is not None:
                await self._post_handshake_hook(self)
            return

        raise BleHandshakeError(
            f"{self.mac}: open failed after {OPEN_MAX_ATTEMPTS} attempts: {last_err}"
        )

    async def _handshake(self) -> None:
        """Subscribe + AES handshake. Bounded by a timeout in _open() because
        these GATT reads/writes are what stall on a weak link. The
        post-handshake hook and open-retry are driven by _open()."""
        # Subscribe BEFORE writing — device may stay silent otherwise.
        self._reset_rx()
        self._last_rx_frame = None  # fresh CTR stream — don't dedup across sessions
        await self._client.start_notify(READ_CHAR, self._on_notify)

        # AES handshake. Phone forces init_tx[11]=0x00.
        init_tx = bytearray(os.urandom(20))
        init_tx[11] = 0x00
        init_tx = bytes(init_tx)
        await self._client.write_gatt_char(AES_CHAR, init_tx)
        rx = bytes(await self._client.read_gatt_char(AES_CHAR))
        if rx[:4] == b"\x00\x00\x00\x00" or any(rx[4:]):
            raise BleHandshakeError(f"{self.mac}: invalid handshake rx={rx.hex()}")

        buf = rx[:4] + init_tx[4:]
        self._iv = buf[:12]
        self._tx_ctr = struct.unpack("<I", buf[12:16])[0]
        self._rx_ctr = struct.unpack("<I", buf[16:20])[0]
        self._handshaken = True
        _LOGGER.debug("%s: handshake ok, iv=%s tx_ctr=0x%08x", self.mac, self._iv.hex(), self._tx_ctr)

    def _reset_rx(self) -> None:
        """Clear the RX state at an exchange boundary — before a write, after a drain.

        The raw frames, their decrypted plaintexts and the partial inner message
        being reassembled are one unit, so they move together: a frame belonging to
        a finished exchange must never be joined to the next one. Split them and a
        stale fragment survives to be spliced onto a later reply, or to absorb the
        bad-header frame that should have tripped the CTR self-heal.

        They move together HERE. `disconnect()` deliberately does not use this: it
        can run unlocked inside another coroutine's drain, so it leaves `_notif_buf`
        for the in-flight `send()` that is about to read it. `_last_rx_frame` is not
        reset here either — it de-dups repeats WITHIN a session, so it is cleared
        only where the CTR stream restarts (the handshake) or ends (disconnect).
        """
        self._notif_buf.clear()
        self._notif_pt.clear()
        self._assembly = bytearray()

    def _on_notify(self, _sender, data) -> None:
        """Bleak notification callback. Buffers the raw frame for the
        command drain, then best-effort decrypts + logs the plaintext so
        we can reverse-engineer the status response (for battery, etc.).
        Decryption advances the rx counter — necessary for the next
        notification's plaintext to be correct."""
        frame = bytes(data)
        # Drop an exact re-delivery of the previous frame. A proxy/link can
        # re-emit the same notification (observed: dozens of identical frames in
        # a burst while the vendor app held the device's single BLE session). We
        # decrypt every delivery, so a re-delivery would advance the RX counter
        # and desync the CTR stream — poisoning every subsequent frame until the
        # next handshake. Same plaintext at a new counter yields different
        # ciphertext, so byte-identical consecutive frames are always dupes.
        if frame == self._last_rx_frame:
            _LOGGER.debug("%s: dropped duplicate rx frame %s", self.mac, frame.hex())
            return
        self._last_rx_frame = frame
        self._notif_buf.append(frame)
        self._notif_event.set()  # wake any in-flight drain (see _drain)
        if not self._handshaken or self._iv is None:
            return
        try:
            pt = self.decrypt(frame)
            _LOGGER.info(
                "%s: notif pt=%s (ct=%s)",
                self.mac, pt.hex(), frame.hex(),
            )
            # Accumulate the decrypted plaintext for send_stream's multi-frame
            # reassembly. Do this BEFORE the header check below returns early on a
            # continuation frame — a long reply's continuation blocks legitimately
            # don't carry the inner-message header but ARE part of the stream.
            self._notif_pt.append(pt)
            # A plaintext shorter than a header cannot be judged against one. Upstream
            # gated the desync check on len(pt) >= 4 and passed such frames to the
            # observer — the device sends a small ack ahead of the richer #16 — so they
            # skip reassembly entirely rather than being read as a bad header. A short
            # CONTINUATION is different and still belongs to the reply in flight: the
            # WT25G2 burst's own last frame is 3 bytes.
            if self._reply_header is not None and (len(pt) >= 4 or self._assembly):
                # Reassemble multi-frame replies before handing anything to the
                # observer. decode_inner() needs the WHOLE inner message — header,
                # declared length and trailing CRC — in one buffer, so feeding it a
                # 16-byte fragment silently returns None and the status is never
                # parsed. A WT25G2 sprinkler controller's #16 status is 83 bytes
                # across six frames, so every poll looked healthy while updating
                # nothing. A single-frame reply completes on its first frame, so
                # short-reply devices behave exactly as before.
                if len(pt) >= 4 and pt[:4] == self._reply_header:
                    self._assembly = bytearray(pt)
                elif self._assembly:
                    self._assembly.extend(pt)
                else:
                    # Neither a first frame nor a continuation of one: the branch
                    # above takes every frame that arrives while a reply is in
                    # flight, and a frame too short to hold a header never gets
                    # here, so what reaches this point has a BAD header and no
                    # assembly to belong to. _notif_buf is cleared before each write, so
                    # len<=1 means it is the first frame of this exchange — a real
                    # CTR desync, worth tearing the session down to re-base the
                    # counter. Later than that, it is stray or a mid-stream desync
                    # we recover on the next reply, so leave the session alone.
                    if len(self._notif_buf) <= 1:
                        _LOGGER.warning(
                            "%s: CTR desync detected (bad header %s) — scheduling disconnect to self-heal",
                            self.mac, pt[:4].hex(),
                        )
                        # Drop any address resolved by advertised name. A desync is
                        # also what a WRONG device looks like — the handshake cannot
                        # tell them apart, since it never consults the key — and a
                        # cached wrong address would send every retry back to it.
                        self._ble_address = None
                        self.hass.add_job(self.disconnect)
                    return

                # pt[4] declares the byte count from the length field to the CRC, so
                # the whole message is header(4) + pt[4] + crc(2). It is a single byte,
                # so `need` is at most 261.
                if len(self._assembly) < 5:
                    return
                need = self._assembly[4] + 6
                if len(self._assembly) < need:
                    return                      # wait for the continuation frames
                pt = bytes(self._assembly[:need])
                self._assembly = bytearray()
        except Exception as err:  # noqa: BLE001
            _LOGGER.warning(
                "%s: CTR desync detected (decrypt failed: %s) — scheduling disconnect to self-heal",
                self.mac, err,
            )
            self.hass.add_job(self.disconnect)
            return
        if self._plaintext_observer is not None:
            try:
                self._plaintext_observer(pt)
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("%s: plaintext observer raised: %s", self.mac, err)

    async def disconnect(self) -> None:
        # A hold refers to a live session; once the link is going down it means
        # nothing. Clearing it here stops a stale hold surviving into the next
        # connection and suppressing its idle timer indefinitely.
        self._held = False
        if self._hold_expiry is not None:
            self._hold_expiry.cancel()
            self._hold_expiry = None
        if self._idle_timer is not None:
            self._idle_timer.cancel()
            self._idle_timer = None
        if self._client is not None:
            try:
                await self._client.stop_notify(READ_CHAR)
            except Exception:
                pass
            try:
                await self._client.disconnect()
            except Exception:
                pass
        self._client = None
        self._handshaken = False
        self._iv = None
        self._last_rx_frame = None
        self._notif_pt.clear()
        # NOT _reset_rx(): disconnect is scheduled without the lock from _on_notify,
        # so it runs inside an in-flight drain, and clearing _notif_buf would empty
        # the frames that send() is about to return.
        self._assembly = bytearray()

    def hold_open(self, max_sec: float) -> None:
        """Keep this session open past the idle timeout until release().

        The idle timer is armed only by a write, so a feature that consumes
        unsolicited notifications has its link closed under it mid-stream at the
        default 60 s regardless of how much data is arriving. Holding disarms
        the timer and stops later writes re-arming it.

        Idempotent: calling again refreshes the expiry rather than nesting.
        `max_sec` is a backstop, not the mechanism — if every release path is
        missed the hold lapses on its own and hands the link back to the normal
        idle machinery, so a leak costs one run rather than the cells.
        """
        if self._idle_timer is not None:
            self._idle_timer.cancel()
            self._idle_timer = None
        if self._hold_expiry is not None:
            self._hold_expiry.cancel()
        self._held = True
        loop = asyncio.get_running_loop()
        self._hold_expiry = loop.call_later(max_sec, self._expire_hold)

    def _expire_hold(self) -> None:
        _LOGGER.warning(
            "%s: session hold hit its backstop and was released — a release "
            "path was missed", self.mac,
        )
        self.release()

    def release(self) -> None:
        """Hand the session back to the normal idle machinery.

        Never disconnects: release means "stop pinning this open", leaving the
        existing idle path as the only place that closes a session. Safe when no
        hold is active and safe to call repeatedly — six paths release this
        hold, so a double release must be harmless.
        """
        if self._hold_expiry is not None:
            self._hold_expiry.cancel()
            self._hold_expiry = None
        if not self._held:
            return
        self._held = False
        self._arm_idle_timer()

    def _arm_idle_timer(self) -> None:
        if self._held:
            return
        if self._idle_sec <= 0:
            return
        if self._idle_timer is not None:
            self._idle_timer.cancel()
        loop = asyncio.get_running_loop()
        self._idle_timer = loop.call_later(
            self._idle_sec, lambda: asyncio.create_task(self._idle_close()),
        )

    async def _idle_close(self) -> None:
        async with self._lock:
            if not self.is_connected:
                return
            _LOGGER.debug("%s: idle disconnect", self.mac)
            await self.disconnect()

    def _aes_keystream(self, counter: int, n_blocks: int) -> tuple[bytes, int]:
        out = bytearray()
        c = counter & 0xFFFFFFFF
        encryptor = Cipher(algorithms.AES(self._key), modes.ECB()).encryptor()
        for _ in range(n_blocks):
            out.extend(encryptor.update(self._iv + struct.pack("<I", c)))
            c = (c + 1) & 0xFFFFFFFF
        return bytes(out), c

    def _aes_xor(self, counter: int, plaintext: bytes) -> tuple[bytes, int]:
        n_blocks = (len(plaintext) + 15) // 16
        keystream, next_ctr = self._aes_keystream(counter, n_blocks)
        return bytes(b ^ k for b, k in zip(plaintext, keystream[:len(plaintext)])), next_ctr

    def encrypt(self, plaintext: bytes) -> bytes:
        if self._iv is None:
            # A disconnect scheduled via hass.add_job (e.g. a desync self-heal)
            # can interleave with an in-flight handshake/init sequence across its
            # awaits and null the session mid-write. Fail cleanly with a typed
            # error the open-retry can catch, not a TypeError from _aes_keystream.
            raise BleHandshakeError(
                f"{self.mac}: cannot encrypt — session cleared (disconnected mid-handshake)"
            )
        ct, self._tx_ctr = self._aes_xor(self._tx_ctr, plaintext)
        trailer = (sum(plaintext) + self._trailer_const + len(plaintext)) & 0xFFFF
        return bytes([self._frame_magic, len(ct)]) + ct + struct.pack("<H", trailer)

    def decrypt(self, frame: bytes) -> bytes:
        """Decrypt a notification frame (advances RX counter). For status decoding."""
        if len(frame) < 4 or frame[0] != self._frame_magic:
            raise ValueError(f"{self.mac}: bad frame magic in {frame.hex()}")
        ct_len = frame[1]
        ct = frame[2:2 + ct_len]
        pt, self._rx_ctr = self._aes_xor(self._rx_ctr, ct)
        return pt

    @property
    def max_write_len(self) -> int:
        """Bytes that fit in ONE ATT write: negotiated MTU minus the 3-byte header."""
        mtu = getattr(self._client, "mtu_size", None) if self._client else None
        return (mtu - 3) if isinstance(mtu, int) and mtu > 3 else 20

    async def _write_locked(self, plaintext: bytes) -> None:
        """Encrypt + write. Caller MUST already hold self._lock and have
        an established connection. Used by send()/send_raw() and by the
        post-handshake hook (which runs inside _open() inside the lock)."""
        assert self._client is not None
        # A message longer than one ATT write is SPLIT ACROSS FRAMES, not sent as a
        # long write. The device already answers this way — an 83-byte status comes
        # back as six frames of <=16 ciphertext bytes — so the framing is built for
        # it; and it refuses the ATT long write outright (Request Not Supported,
        # HW-verified on a WT25G2 at MTU 23), which through a proxy
        # presents as "Not connected" and can leave a half-open link. On a roomy
        # link the whole message still goes in one frame, exactly as before.
        pieces = self._split(plaintext)
        for piece in pieces:
            try:
                await self._write_frame(self.encrypt(piece))
            except Exception:
                if len(pieces) > 1:
                    # A split write that stopped partway has advanced _tx_ctr past
                    # what the device consumed and left it holding a truncated inner
                    # message. Nothing arrives on the RX side to look wrong, so the
                    # desync self-heal never fires and the next command would go out
                    # at a counter the device never reached. Close the session: the
                    # next open re-handshakes and re-bases both counters. It has to
                    # be a real disconnect, not just clearing _handshaken — this
                    # device holds ONE BLE session, so a link left open and
                    # abandoned can refuse the reconnect that replaces it.
                    await self.disconnect()
                raise

    def _split(self, plaintext: bytes) -> list[bytes]:
        """Cut a message into pieces that each fit one ATT write.

        A frame is [magic][len] + ciphertext + [trailer:2], so the ciphertext
        budget is four bytes under the write limit, and never more than 255 because
        `len` is a single byte.

        It is also rounded DOWN to a whole AES block. encrypt/decrypt advance the
        CTR counter by whole blocks per frame, so a piece that is not block-aligned
        burns the rest of its last block: we resume the keystream at the next block
        boundary while a device that concatenated the bytes would resume where they
        ended. At MTU 23 the budget is 16 and the question never arises — which is
        why every frame ever captured from this family is aligned, and why the
        evidence cannot say which model the device follows. Aligning costs nothing
        (16 at MTU 23 and 240 at MTU 247 are unchanged) and removes the exposure at
        the MTUs in between, where a 126-byte #19 program write would otherwise be
        cut 121+5.
        """
        budget = max(1, min(self.max_write_len - 4, 255))
        if budget >= 16:                  # never round a tiny link up past its limit
            budget -= budget % 16
        return [plaintext[i:i + budget] for i in range(0, len(plaintext), budget)] or [b""]

    async def _write_frame(self, frame: bytes) -> None:
        # WRITE_CHAR (6c72) uses a Write Request (response=True). Over some
        # transports (notably the ESPHome Bluetooth proxy), the ATT Write
        # Response is never relayed back, so a plain response=True write blocks
        # ~30s. Issue the Write Request but cap the wait; the notification drain
        # in send() is the real ack. Over a direct link the response arrives in
        # <200ms so this returns immediately.
        try:
            await asyncio.wait_for(
                self._client.write_gatt_char(WRITE_CHAR, frame, response=True),
                timeout=WRITE_ACK_TIMEOUT_SEC,
            )
        except asyncio.TimeoutError:
            pass

    async def _drain(self, drain_ms: int) -> None:
        """Collect the device's reply, returning as soon as it goes quiet
        instead of always sleeping the full drain window. Wake on the first
        notification, then hold the window open only while frames keep arriving
        (NOTIF_QUIET_SEC between them), hard-capped at drain_ms so a silent
        device still returns on time. Call with _notif_buf freshly cleared."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + drain_ms / 1000.0
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return
            # Clear before snapshotting the buffer: a frame arriving from here
            # on re-sets the event and wakes us; a frame already buffered means
            # we're settling and should wait only a short quiet window for more.
            self._notif_event.clear()
            timeout = min(NOTIF_QUIET_SEC, remaining) if self._notif_buf else remaining
            try:
                await asyncio.wait_for(self._notif_event.wait(), timeout)
            except asyncio.TimeoutError:
                return  # no new frame within the window -> reply complete (or silent)

    async def _write_and_drain(self, plaintext: bytes, drain_ms: int) -> list[bytes]:
        """Write a command and collect its reply. Caller MUST hold self._lock and
        have an established, initialised session."""
        self._reset_rx()
        await self._write_locked(plaintext)
        await self._drain(drain_ms)
        received = list(self._notif_buf)
        self._reset_rx()
        self._arm_idle_timer()
        return received

    async def send(self, plaintext: bytes, *, drain_ms: int = 1500) -> list[bytes]:
        """Encrypt + WRITE_REQ + drain notifications until the reply goes quiet
        (bounded by `drain_ms`). Returns the raw notification frames received."""
        async with self._lock:
            await self.ensure_connected()
            return await self._write_and_drain(plaintext, drain_ms)

    async def send_stream(self, plaintext: bytes, *, drain_ms: int = 4000) -> bytes:
        """Send a request and return the concatenated decrypted plaintext of the
        WHOLE reply burst, for multi-frame reassembly by the caller.

        A long inner message (a #19 program body in a #10 sync dump) streams as
        consecutive 16-byte CTR blocks, each in its own outer frame, the RX counter
        advancing per block across all of them. _on_notify decrypts each frame at
        the running counter, so joining the per-frame plaintexts reproduces the
        original stream; the caller (status.split_inner_messages / parse_sync_dump)
        scans it for the aa775a0f-headed inner messages. Single-frame fast paths
        (#16/#30/#59) are untouched — they still flow through send()/the observer."""
        async with self._lock:
            await self.ensure_connected()
            self._reset_rx()
            await self._write_locked(plaintext)
            await self._drain(drain_ms)
            stream = b"".join(self._notif_pt)
            self._reset_rx()
            self._arm_idle_timer()
            return stream

    async def send_raw(self, plaintext: bytes) -> None:
        """Encrypt + WRITE_REQ with no notification drain. For init-step
        sequences where the caller batches drain after the last step."""
        async with self._lock:
            await self.ensure_connected()
            self._reset_rx()
            await self._write_locked(plaintext)

    async def send_actuation(self, plaintext: bytes, *, drain_ms: int = 1500) -> list[bytes]:
        """Re-run the per-device init sequence, then send a command — atomically.

        Some devices only honour a watering command in a freshly-initialised
        session: a pooled connection's per-class bind/init goes stale, so the
        command is ack'd but SILENTLY IGNORED (no actuation). Re-run the init
        hook before the command rather than trusting the pooled session. For a
        device class with no post-handshake hook this is just ensure_connected
        + send."""
        async with self._lock:
            if self.is_connected and self._handshaken:
                # Pooled connection — refresh the (possibly stale) bind in place.
                # But over an ESPHome proxy the pooled link can already be dead at
                # the GATT layer while is_connected still reads True, so the refresh
                # writes fail with BleakError ("Not connected"). Don't let that
                # surface as a failed actuation: drop the stale session and reopen
                # a fresh one (ensure_connected re-runs the hook). HW-observed on a
                # mesh HT25 STOP over a proxy — the very next fresh connect landed.
                try:
                    if self._post_handshake_hook is not None:
                        await self._post_handshake_hook(self)
                except (BleakError, OSError, asyncio.TimeoutError) as err:
                    _LOGGER.debug(
                        "%s: pooled bind refresh failed (%s) — reopening a fresh session",
                        self.mac, err,
                    )
                    await self.disconnect()
                    await self.ensure_connected()
            else:
                # Cold — ensure_connected() retries the open and runs the hook.
                await self.ensure_connected()
            self._reset_rx()
            await self._write_locked(plaintext)
            await self._drain(drain_ms)
            received = list(self._notif_buf)
            self._reset_rx()
            self._arm_idle_timer()
            return received


class BleNotConnectable(Exception):
    """Device not in range of any connectable BLE adapter."""


class BleHandshakeError(Exception):
    """AES handshake failed (bad key, bad device, or device in weird state)."""
