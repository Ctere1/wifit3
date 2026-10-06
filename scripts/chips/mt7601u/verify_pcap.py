"""Single-cursor verify_pcap for the MT7601U (MediaTek vendor-request USB).

Drives the port's real MT7601UDriver._bringup over one cursor via mt76_verify_replay.py and
reports coverage plus every named waiver. The Linux driver is the oracle this compares
against: a divergence here is a question to answer from the C, never a byte to copy back.

Run: uv run python scripts/chips/mt7601u/verify_pcap.py [<pcap>] [--verbose]
"""
from __future__ import annotations

import asyncio
import logging
import struct
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "scripts" / "porting"))

import mt76_verify_replay as E
from wifit3.chips.mt7601u.constants import (
    MT_RX_FILTR_CFG,
    MT_RX_FILTR_CFG_ACK,
    MT_RX_FILTR_CFG_BA,
    MT_RX_FILTR_CFG_CFACK,
    MT_RX_FILTR_CFG_CFEND,
    MT_RX_FILTR_CFG_CRC_ERR,
    MT_RX_FILTR_CFG_CTRL_RSV,
    MT_RX_FILTR_CFG_CTS,
    MT_RX_FILTR_CFG_DUP,
    MT_RX_FILTR_CFG_PHY_ERR,
    MT_RX_FILTR_CFG_PROMISC,
    MT_RX_FILTR_CFG_PSPOLL,
    MT_RX_FILTR_CFG_RTS,
    MT_RX_FILTR_CFG_VER_ERR,
)
from wifit3.chips.mt7601u.driver import MT7601UDriver
from wifit3.chips.mt7601u.eeprom import MT7601UEepromParams
from wifit3.chips.mt7601u.rx import (
    MT_FCE_INFO_LEN,
    iter_frames,
    next_segment_len,
)
from wifit3.dot11.parser import WlanFrameParser

DEFAULT_CAP = "driver_captures/captures_mt7601u_superwang/capture-1.pcap"

_XFER_CTRL, _XFER_BULK = 0x02, 0x03
_URB_SUBMIT, _URB_COMPLETE = 0x53, 0x43
_GET_DESCRIPTOR = 0x06
_DESC_CONFIGURATION, _DESC_ENDPOINT = 0x02, 0x05

# in_eps[MT_EP_IN_PKT_RX] (usb.c:243): the ambient 802.11 stream, not a port output.
EP_PKT_RX_IN = 0x84
_USBMON_LEN = 32
"""mon_bin's urb length field. It exceeds LEN_CAP where usbmon truncated."""


# init.c:238-244, the managed-STA default the kernel programs during bring-up. Built from
# the bit list rather than the recorded value so it stays a statement about the C.
MANAGED_RXFILTER = (
    MT_RX_FILTR_CFG_CRC_ERR | MT_RX_FILTR_CFG_PHY_ERR | MT_RX_FILTR_CFG_PROMISC
    | MT_RX_FILTR_CFG_VER_ERR | MT_RX_FILTR_CFG_DUP | MT_RX_FILTR_CFG_CFACK
    | MT_RX_FILTR_CFG_CFEND | MT_RX_FILTR_CFG_ACK | MT_RX_FILTR_CFG_CTS
    | MT_RX_FILTR_CFG_RTS | MT_RX_FILTR_CFG_PSPOLL | MT_RX_FILTR_CFG_BA
    | MT_RX_FILTR_CFG_CTRL_RSV)


def _is_filter_write(op) -> bool:
    return (op.cls == "ctrl" and not op.is_in
            and op.widx in (MT_RX_FILTR_CFG, MT_RX_FILTR_CFG + 2))


def _carries_managed_default(op) -> bool:
    """True when this half-write carries the init.c:238-244 value."""
    if op.widx == MT_RX_FILTR_CFG:
        return op.wval == MANAGED_RXFILTER & 0xFFFF
    return op.wval == MANAGED_RXFILTER >> 16


def _rx_filter_substituted(port, op) -> bool:
    reg = port.addr & 0xFFFF
    return (not port.is_bulk and not port.is_in
            and reg in (MT_RX_FILTR_CFG, MT_RX_FILTR_CFG + 2)
            and _is_filter_write(op) and op.widx == reg
            and _carries_managed_default(op))


def _rx_filter_reconfigured(op) -> bool:
    return _is_filter_write(op) and not _carries_managed_default(op)


def waivers() -> E.WaiverSet:
    """Named, counted waivers for the mt7601u captures."""
    return E.WaiverSet(
        E.Waiver(
            "RX filter: monitor, not managed STA",
            "init.c:238-245 programs MT_RX_FILTR_CFG = 0x00017f97 for a managed STA inside "
            "mac_start. The register drops on set -- main.c:107 sets each bit only when "
            "mac80211 did NOT ask for that class -- so main.c:116-125 reconfigures it per "
            "interface, and this port writes the monitor result (0x00001093) where mac_start "
            "writes the managed default. Same value the capture reconfigures to; the only "
            "difference is that the port does not pass through the managed default first.",
            sub=_rx_filter_substituted,
            match=_rx_filter_reconfigured,
        ),
        E.Waiver(
            "USB enumeration",
            "GET_DESCRIPTOR / SET_CONFIGURATION / SET_INTERFACE and friends: standard-type "
            "control requests usbcore issues while enumerating. No mt7601u code path emits "
            "them -- the driver only ever sends vendor requests (usb.c:88).",
            match=lambda op: op.cls == "ctrl" and op.reqtype == "standard",
        ),
    )


def drop_rx_stream(pkts: list[bytes]) -> list[bytes]:
    """Discard every URB on the RX data pipe.

    They carry whatever was in the air while the capture ran: unreproducible, and nothing the
    port is asked to emit. Dropping them leaves the response stream holding only EP 0x85 MCU
    replies, which the port consumes in order.
    """
    return [p for p in pkts
            if not (len(p) > E.UsbmonOff.EP
                    and p[E.UsbmonOff.XFER] == _XFER_BULK
                    and p[E.UsbmonOff.EP] == EP_PKT_RX_IN)]


class _Endpoint:
    def __init__(self, addr: int, mps: int):
        self.bEndpointAddress = addr
        self.wMaxPacketSize = mps


class _Interface(list):
    """What assign_pipes() iterates: the endpoint descriptors, in descriptor order."""
    bInterfaceClass = 0xFF
    bInterfaceNumber = 0


class _Configuration:
    """Indexed as cfg[(0, 0)] by assign_pipes()."""

    def __init__(self, endpoints: list[_Endpoint]):
        self._iface = _Interface(endpoints)

    def __getitem__(self, _key):
        return self._iface


def _parse_endpoints(blob: bytes) -> list[_Endpoint]:
    eps: list[_Endpoint] = []
    i = 0
    while i + 2 <= len(blob):
        blen, btype = blob[i], blob[i + 1]
        if blen == 0:
            break
        if btype == _DESC_ENDPOINT and i + 7 <= len(blob):
            eps.append(_Endpoint(blob[i + 2], struct.unpack_from("<H", blob, i + 4)[0]))
        i += blen
    return eps


def interface_endpoints(pkts: list[bytes]) -> list[_Endpoint]:
    """The endpoints the card reported, read out of the capture's own enumeration.

    assign_pipes() is positional (usb.c:243) and this card's descriptor order is not
    ascending, so the order has to come from the capture rather than be assumed.
    """
    pending: set[bytes] = set()
    for pkt in pkts:
        if len(pkt) < int(E.UsbmonOff.SETUP) + 8 or pkt[E.UsbmonOff.XFER] != _XFER_CTRL:
            continue
        urb = bytes(pkt[0:8])
        if pkt[E.UsbmonOff.TYPE] == _URB_SUBMIT:
            wval = struct.unpack_from("<H", pkt, E.UsbmonOff.SETUP + 2)[0]
            if pkt[E.UsbmonOff.SETUP + 1] == _GET_DESCRIPTOR and (wval >> 8) == _DESC_CONFIGURATION:
                pending.add(urb)
        elif pkt[E.UsbmonOff.TYPE] == _URB_COMPLETE and urb in pending:
            pending.discard(urb)
            eps = _parse_endpoints(bytes(pkt[E.UsbmonOff.DATA:]))
            if eps:
                return eps
    return []


def driver_on(dev, endpoints: list[_Endpoint]) -> MT7601UDriver:
    """The real driver over the replay device, with connect()'s host-side half done here.

    assign_pipes() is the port of usb.c:228 and emits no wire bytes, so it runs for real
    against the captured descriptor. The RX reader thread is stubbed: it would race the
    cursor reading a pipe this walk serves no responses for.
    """
    drv = MT7601UDriver(dev)
    dev.get_active_configuration = lambda: _Configuration(endpoints)
    drv.transport.assign_pipes()
    drv._start_rx = lambda: None
    return drv


def rx_decode_phase(pkts: list[bytes], ee) -> None:
    """METHODOLOGY step 3: run the captured RX stream through the real decode path.

    drop_rx_stream throws these buffers away before the cursor walk, because what was in
    the air is unreproducible. The bytes are still the only real RX descriptors available
    offline, so decode them here, outside the cursor, where a surprise cannot derail it.
    Addresses and SSIDs are deliberately not printed: counts answer the question, and
    nothing real belongs in this output.

    usbmon truncates part of the bulk-IN stream -- its record length field exceeds the
    bytes it captured -- so those records are counted and skipped rather than decoded. A
    truncated buffer is not a decode failure; the C rejects it on the same test
    (dma.c:125 `dma_len + MT_DMA_HDRS > data_len`).
    """
    whole, truncated = [], 0
    for pkt in pkts:
        if not (len(pkt) > E.UsbmonOff.EP
                and pkt[E.UsbmonOff.TYPE] == _URB_COMPLETE
                and pkt[E.UsbmonOff.XFER] == _XFER_BULK
                and pkt[E.UsbmonOff.EP] == EP_PKT_RX_IN
                and pkt[E.UsbmonOff.LEN_CAP] > 0):
            continue
        cap = pkt[E.UsbmonOff.LEN_CAP]
        if int.from_bytes(pkt[_USBMON_LEN:_USBMON_LEN + 4], "little") != cap:
            truncated += 1
            continue
        whole.append(bytes(pkt[E.UsbmonOff.DATA:E.UsbmonOff.DATA + cap]))
    if not whole:
        print(f"RX DECODE: no untruncated EP {EP_PKT_RX_IN:#04x} payloads "
              f"({truncated} truncated by usbmon)")
        return

    parser = WlanFrameParser()
    segments = decoded = parsed = unconsumed = 0
    fc_bytes: set[int] = set()
    offset = ee.rssi_offset[0] if ee.rssi_offset else 0
    for buf in whole:
        walked = 0
        while True:
            seg_len = next_segment_len(buf[walked:])
            if not seg_len:
                break
            segments += 1
            walked += seg_len
        # MT_FCE_INFO_LEN of zero padding rides after the last segment (dma.h:15).
        if len(buf) - walked > MT_FCE_INFO_LEN:
            unconsumed += 1
        for frame in iter_frames(buf, ee.lna_gain, offset):
            decoded += 1
            fc_bytes.add(frame.frame[0])
            if parser.parse_80211_frame(frame.frame, frame.rssi) is not None:
                parsed += 1

    total = sum(len(b) for b in whole)
    print(f"RX DECODE: {len(whole)} whole bulk-IN buffers ({total} bytes), "
          f"{truncated} truncated by usbmon and skipped")
    print(f"           {segments} chained segments -> {decoded} frames decoded, "
          f"{parsed} parsed; {len(fc_bytes)} distinct frame-control bytes")
    if segments and decoded < segments:
        print(f"           {segments - decoded} segments dropped by the rxwi gates")
    if unconsumed:
        print(f"           {unconsumed} buffers left more than a trailer unconsumed")


async def _run_bringup(walk: E.Walk, endpoints: list[_Endpoint], state: dict) -> None:
    async def go(dev):
        state["drv"] = drv = driver_on(dev, endpoints)
        return await drv._bringup()

    await walk.run_async(go, "bringup")


def run(cap: str | None = None, verbose: bool = False) -> int:
    if not verbose:
        logging.getLogger("wifit3").setLevel(logging.CRITICAL)
    _real_sleep, time.sleep = time.sleep, lambda *a, **k: None
    _real_asleep = asyncio.sleep

    async def _fast_sleep(delay, *a, **k):
        return await _real_asleep(0)
    asyncio.sleep = _fast_sleep
    try:
        return _run(cap)
    finally:
        time.sleep = _real_sleep
        asyncio.sleep = _real_asleep


def _run(cap: str | None) -> int:
    path = cap or DEFAULT_CAP
    if not Path(path).exists():
        print(f"FAIL: no such capture {path}")
        return 1
    pkts = E.parse_pcapng(path)
    endpoints = interface_endpoints(pkts)
    if len(endpoints) != 8:
        print(f"FAIL: {path} carries no usable interface descriptor "
              f"({len(endpoints)} endpoints found, assign_pipes needs 2 IN + 6 OUT)")
        return 1
    rx_pkts = pkts
    pkts = drop_rx_stream(pkts)
    dev = E.busiest_vendor_devnum(pkts)
    if dev is None:
        print(f"FAIL: no vendor-control device found in {path}")
        return 1
    capture = E.extract(pkts, dev)
    walk = E.Walk(capture, waivers=waivers())
    state: dict = {}

    title = f"mt7601u verify · {Path(path).name}"
    eps = " ".join(f"{e.bEndpointAddress:#04x}" for e in endpoints)
    print(f"{title}: dev{dev}, {len(capture.ops)} host-to-device ops, "
          f"{len(capture.responses)} MCU responses, endpoints {eps}")

    try:
        asyncio.run(_run_bringup(walk, endpoints, state))
    except E.Divergence:
        pass
    except Exception as e:  # noqa: BLE001
        print(f"\n[harness] bring-up raised {type(e).__name__}: {e}")

    rc = walk.report(title)
    if walk.ledger.frontier is not None:
        return rc
    # _bringup ends at the first channel tune, so the rest of the capture is the
    # operational phase (hopping, TX) that this walk is not scoped to drive.
    remaining = len(capture.ops) - walk.i
    print()
    drv = state.get("drv")
    try:
        rx_decode_phase(rx_pkts, drv.ee if drv is not None else MT7601UEepromParams())
    except Exception as e:  # noqa: BLE001
        print(f"RX DECODE: raised {type(e).__name__}: {e}")
    print()
    print(f"OVERALL: _bringup replayed against the capture with no divergence; "
          f"{remaining} operational-phase ops after it are out of its scope.")
    return 0 if walk.ledger.waived_count == 0 else 2


def main() -> int:
    args = [a for a in sys.argv[1:] if a != "--verbose"]
    verbose = "--verbose" in sys.argv[1:]
    return run(args[0] if args else None, verbose=verbose)


if __name__ == "__main__":
    raise SystemExit(main())
