"""Verify the MT7601U TX descriptor against the recorded kernel injection.

Every other porting stage replays a kernel capture and asserts an op-for-op match.
TX had no such gate, which is why the live-TX defect survived: the descriptor was
only ever compared by eye against capture-6.

This parses capture-6's recorded bulk OUT -- the kernel's own injected deauth --
rebuilds the same frame through the port's tx.py, and asserts the two descriptors are
identical field for field. It also decodes both against struct mt76_txwi, so a
divergence names the field that diverged instead of dumping 32 bytes of hex.

The capture is truncated at 32 bytes per record (usbmon prints no continuation line),
so only the DMA info word and the full 20-byte txwi are recorded. That is exactly the
descriptor header, and it is the part that was never machine-checked.

Run: uv run python scripts/chips/mt7601u/verify_tx.py
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "src"))

from wifit3.chips.mt7601u import constants as C
from wifit3.chips.mt7601u.tx import TX_NO_STATION, TX_QUEUE_INJECT, build_tx_dma

CAPTURE = REPO / "driver_captures_mt7601u" / "capture-6-kernel-tx" / "bulk_out.txt"
FRAME = bytes.fromhex("00000000000000000000000000000000")  # placeholder, see below

USB_LINE = re.compile(r"Bo:\d+:\d+:(\d+) -115 (\d+) = ([0-9a-f ]+)")


@dataclass(frozen=True)
class Descriptor:
    """The 24-byte descriptor header: 4-byte DMA info plus a 20-byte txwi."""

    info: int
    txwi: bytes

    @property
    def info_le_hex(self) -> str:
        return self.info.to_bytes(4, "little").hex()


def parse_capture(path: Path) -> list[tuple[int, bytes]]:
    """Return every bulk OUT record as (endpoint, recorded_bytes)."""
    out = []
    for line in path.read_text().splitlines():
        m = USB_LINE.search(line)
        if not m:
            continue
        endpoint = int(m.group(1))
        length = int(m.group(2))
        payload = bytes.fromhex(m.group(3).replace(" ", ""))
        if length and len(payload) >= length:
            payload = payload[:length]
        out.append((endpoint, payload))
    return out


def kernel_descriptors(path: Path) -> list[Descriptor]:
    """Every captured TX descriptor, i.e. bulk OUTs on the TX endpoint."""
    found = []
    for endpoint, payload in parse_capture(path):
        if len(payload) < 24 or endpoint == 8:      # 8 is the MCU inband endpoint
            continue
        info = int.from_bytes(payload[:4], "little")
        # A TX descriptor carries MT_TXD_PKT_INFO_80211; filter on it rather than
        # trusting the endpoint index, so a stray record cannot become the oracle.
        if not info & C.MT_TXD_PKT_INFO_80211:
            continue
        found.append(Descriptor(info=info, txwi=payload[4:24]))
    return found


def decode_txwi(txwi: bytes) -> dict[str, int]:
    """Decode a 20-byte txwi field by field (struct mt76_txwi, mac.h)."""
    return {
        "flags": int.from_bytes(txwi[0:2], "little"),
        "rate_ctl": int.from_bytes(txwi[2:4], "little"),
        "ack_ctl": txwi[4],
        "wcid": txwi[5],
        "len_ctl": int.from_bytes(txwi[6:8], "little"),
        "iv": int.from_bytes(txwi[8:12], "little"),
        "eiv": int.from_bytes(txwi[12:16], "little"),
        "aid": txwi[16],
        "txstream": txwi[17],
        "ctl": int.from_bytes(txwi[18:20], "little"),
    }


def decode_info(info: int) -> dict[str, int]:
    return {
        "LEN": info & C.MT_TXD_INFO_LEN,
        "D_PORT": (info & C.MT_TXD_INFO_D_PORT) >> 27,
        "TYPE": (info & C.MT_TXD_INFO_TYPE) >> 30,
        "80211": (info & C.MT_TXD_PKT_INFO_80211) >> 19,
        "WIV": (info & C.MT_TXD_PKT_INFO_WIV) >> 24,
        "QSEL": (info & C.MT_TXD_PKT_INFO_QSEL) >> 25,
    }


def main() -> int:
    if not CAPTURE.exists():
        print(f"capture missing: {CAPTURE}")
        print("re-capture with the kernel driver; see capture_mt7601u.py")
        return 2

    recorded = kernel_descriptors(CAPTURE)
    if not recorded:
        print(f"no TX descriptors in {CAPTURE}")
        return 2

    counts: dict[tuple[str, str], int] = {}
    for d in recorded:
        counts[(d.info_le_hex, d.txwi.hex())] = counts.get(
            (d.info_le_hex, d.txwi.hex()), 0) + 1

    print(f"capture-6: {len(recorded)} TX descriptors in {len(counts)} variant(s)")
    variants = []
    for (info_hex, txwi_hex), n in counts.items():
        info = int.from_bytes(bytes.fromhex(info_hex), "little")
        fields = decode_txwi(bytes.fromhex(txwi_hex))
        variants.append((n, info, bytes.fromhex(txwi_hex)))
        print(f"\n  x{n}")
        print(f"    info {info_hex} -> {decode_info(info)}")
        print(f"    txwi {txwi_hex}")
        print(f"      wcid={fields['wcid']} ack_ctl={fields['ack_ctl']:#04x} "
              f"byte_cnt={fields['len_ctl'] & C.MT_TXWI_LEN_BYTE_CNT} "
              f"pktid={fields['len_ctl'] >> 12} rate_ctl={fields['rate_ctl']:#06x}")

    # aireplay-ng's injection test sends probe requests on a WCID the kernel
    # actually allocated, with the chip stamping the sequence number. The
    # broadcast deauths go out on the monitor WCID. This port only ever builds the
    # monitor form, so it cannot produce the variant that reaches the air.
    wcids = {decode_txwi(t)["wcid"] for _, _, t in variants}
    print(f"\nWCIDs present in the reference capture: {sorted(wcids)}")

    failures = []

    reference_n, reference, reference_txwi = max(variants, key=lambda v: v[0])
    print(f"\ncomparing the port against the dominant kernel variant (x{reference_n})")

    ref_fields = decode_txwi(reference_txwi)
    ref_info = decode_info(reference)

    ref_len = ref_fields["len_ctl"] & C.MT_TXWI_LEN_BYTE_CNT
    frame = b"\x00" * ref_len
    port = build_tx_dma(frame, ack=False, wcid=ref_fields["wcid"],
                        rate=ref_fields["rate_ctl"] & C.MT_TXWI_RATE_MCS)

    port_info = int.from_bytes(port[:4], "little")
    port_txwi = port[4:24]
    port_info_fields = decode_info(port_info)
    port_fields = decode_txwi(port_txwi)

    print(f"  info.{port_info_fields}")
    print(f"  txwi.{port_fields}")

    for field in ("D_PORT", "TYPE", "80211", "WIV", "QSEL"):
        if port_info_fields[field] != ref_info[field]:
            failures.append(f"info.{field}: port {port_info_fields[field]} "
                            f"!= kernel {ref_info[field]}")

    for field in ref_fields:
        if field == "len_ctl":
            if port_fields[field] & 0xF000 != ref_fields[field] & 0xF000:
                failures.append(f"txwi.{field} PKTID: port "
                                f"{port_fields[field] & 0xF000:#06x} != kernel "
                                f"{ref_fields[field] & 0xF000:#06x}")
            continue
        if port_fields[field] != ref_fields[field]:
            failures.append(f"txwi.{field}: port {port_fields[field]} "
                            f"!= kernel {ref_fields[field]}")

    print()
    if failures:
        print(f"FAIL: {len(failures)} field(s) diverge from the kernel descriptor")
        for f in failures:
            print(f"  {f}")
        return 1

    print("PASS: port TX descriptor matches the dominant kernel variant field for field")
    print(f"  endpoint index {TX_QUEUE_INJECT}, QSEL {ref_info['QSEL']}, "
          f"wcid {ref_fields['wcid']}, rate_ctl {ref_fields['rate_ctl']:#06x}")

    if len(wcids) > 1:
        print(f"\nNOTE: this capture contains {len(wcids)} WCIDs "
              f"{sorted(wcids)}. This port only builds wcid={TX_NO_STATION} "
              f"(0xff), so the variant(s) carrying another WCID cannot be "
              f"reproduced. Allocation is unported (see MT7601U.md).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())