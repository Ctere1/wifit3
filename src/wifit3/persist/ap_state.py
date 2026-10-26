"""One AP's keys, hashlines and SSIDs across every SSID it has had, and its password status."""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable, Optional

from wifit3.crack import wpa_psk
from wifit3.crack.hc22000_format import Hc22000Line, parse_hc22000
from wifit3.dot11.wpa import derive_pmk
from wifit3.models import CaptureType, PersistedCapture
from wifit3.persist.meta import bssid_meta_paths, meta_path, read_meta, update_meta
from wifit3.persist.pcap import read_pcap
from wifit3.vault.exhaustion import hashline_id

_HASHLINES_KEY = "hashlines"
_LIVE_VERIFICATIONS_KEY = "live_verifications"
_RAW_PMK_RE = re.compile(r"[0-9a-fA-F]{64}")
_PAIR_LABELS = {0: "M1+M2", 1: "M1+M4", 2: "M2+M3", 3: "M2+M3", 4: "M3+M4", 5: "M3+M4"}

_pmk_cache: dict[tuple[str, bytes], bytes] = {}
_pcap_cache: dict[tuple[str, int], list[tuple[bytes, int]]] = {}


class PasswordStatus(Enum):
    CURRENT = "CURRENT PASSWORD"
    NOT_VERIFIED = "NOT VERIFIED"
    STALE = "STALE PASSWORD"
    NOT_CRACKED = "NOT CRACKED"


@dataclass(frozen=True)
class DatedHashline:
    id: str
    raw: str
    line: Hc22000Line
    ssid: str
    captured: tuple[int, ...]       # epoch seconds; empty when no record or pcap dates it

    @property
    def first_captured(self) -> int:
        return min(self.captured, default=0)

    @property
    def pair_label(self) -> str:
        return "PMKID" if self.line.is_pmkid else _PAIR_LABELS.get(self.line.eapol_message_pair, "M??")

    @property
    def client(self) -> str:
        """Last two bytes of the client MAC, ``aa:bb``."""
        return f"{self.line.mac_sta[-4:-2]}:{self.line.mac_sta[-2:]}"


@dataclass(frozen=True)
class LiveVerification:
    at: int
    correct: bool


@dataclass(frozen=True)
class Key:
    capture_type: CaptureType       # WPA_PSK (also when recovered over WPS), WPS_PIN or WEP
    value: str                      # passphrase or raw PMK, WPS PIN, or WEP key hex
    capture: PersistedCapture       # the .txt it was read from
    hashline_ids: frozenset[str]
    live_verifications: tuple[LiveVerification, ...]

    @property
    def from_access_point(self) -> bool:
        """Recovered from the AP itself (WEP key, WPS M7), so correct when it was recovered."""
        return self.capture.type in (CaptureType.WEP, CaptureType.WPS_PIN, CaptureType.WPS_PBC)


@dataclass(frozen=True)
class SsidHistory:
    ssid: str
    first_seen: int
    last_seen: int


@dataclass(frozen=True)
class ApState:
    bssid: str
    ssids: tuple[SsidHistory, ...]          # newest first
    hashlines: tuple[DatedHashline, ...]    # newest first, undated last
    keys: tuple[Key, ...]                   # most recently confirmed first
    status: PasswordStatus
    status_key: Optional[Key]
    hashline_capture: Optional[PersistedCapture]    # the newest SSID's .hc22000; jobs are filed under it

    @property
    def uncracked(self) -> tuple[DatedHashline, ...]:
        cracked = {h for key in self.keys for h in key.hashline_ids}
        return tuple(h for h in self.hashlines if h.id not in cracked)


def _pmk(passphrase: str, essid: bytes) -> bytes:
    if _RAW_PMK_RE.fullmatch(passphrase):
        return bytes.fromhex(passphrase)
    cached = _pmk_cache.get((passphrase, essid))
    if cached is None:
        cached = _pmk_cache[(passphrase, essid)] = derive_pmk(passphrase, essid)
    return cached


def psk_matches(passphrase: str, line: Hc22000Line) -> bool:
    """Whether the passphrase (or 64-hex raw PMK) cracks the hashline; PMKs are cached."""
    return wpa_psk.psk_matches(_pmk(passphrase, bytes.fromhex(line.essid)), line)


def _pcap_frames(path: Path) -> list[tuple[bytes, int]]:
    try:
        stamp = path.stat().st_mtime_ns
    except OSError:
        return []
    key = (str(path), stamp)
    if key not in _pcap_cache:
        _pcap_cache[key] = list(read_pcap(path))
    return _pcap_cache[key]


def _pcap_dates(lines: dict[str, Hc22000Line], pcaps: Iterable[Path]) -> dict[str, set[int]]:
    """Per hashline id, the time of each pcap frame carrying its MIC or PMKID."""
    needles = {hid: bytes.fromhex(line.pmkid_or_mic) for hid, line in lines.items()}
    found: dict[str, set[int]] = {}
    for pcap in pcaps:
        for frame, epoch in _pcap_frames(pcap):
            for hid, needle in needles.items():
                if needle in frame:
                    found.setdefault(hid, set()).add(epoch)
    return found


def _stored_dates(metas: list[dict]) -> dict[str, set[int]]:
    found: dict[str, set[int]] = {}
    for meta in metas:
        stored = meta.get(_HASHLINES_KEY)
        if not isinstance(stored, dict):
            continue
        for hid, record in stored.items():
            captured = record.get("captured") if isinstance(record, dict) else None
            if isinstance(captured, list):
                found.setdefault(hid, set()).update(e for e in captured if isinstance(e, int))
    return found


def _stored_verifications(metas: list[dict]) -> dict[tuple[CaptureType, str], list[LiveVerification]]:
    found: dict[tuple[CaptureType, str], list[LiveVerification]] = {}
    for meta in metas:
        stored = meta.get(_LIVE_VERIFICATIONS_KEY)
        if not isinstance(stored, list):
            continue
        for record in stored:
            if not isinstance(record, dict):
                continue
            kind, value, at = record.get("kind"), record.get("key"), record.get("at")
            if kind in list(CaptureType) and isinstance(value, str) and isinstance(at, int):
                found.setdefault((CaptureType(kind), value), []).append(
                    LiveVerification(at, bool(record.get("correct"))))
    return found


def read_hashlines(bssid: str, captures: list[PersistedCapture]) -> dict[str, tuple[str, Hc22000Line]]:
    """The AP's lines in its captures' .hc22000 files, ``{hashline id: (raw, parsed)}``."""
    compact_bssid = bssid.replace(":", "").lower()
    found: dict[str, tuple[str, Hc22000Line]] = {}
    for path in dict.fromkeys(c.path for c in captures if c.path.endswith(".hc22000")):
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for raw in text.splitlines():
            line = parse_hc22000(raw)
            if line is not None and line.mac_ap == compact_bssid:
                found.setdefault(hashline_id(raw), (raw.strip(), line))
    return found


def _keys_from_captures(captures: list[PersistedCapture]) -> list[tuple[CaptureType, str, PersistedCapture]]:
    """Every saved key, newest capture first, one per capture type and value."""
    found: dict[tuple[CaptureType, str], PersistedCapture] = {}
    for capture in sorted(captures, key=lambda c: c.timestamp, reverse=True):
        if capture.type == CaptureType.WEP and capture.value:
            found.setdefault((CaptureType.WEP, capture.value), capture)
        if capture.type == CaptureType.WPS_PIN and capture.pin is not None:
            found.setdefault((CaptureType.WPS_PIN, capture.pin), capture)
        if capture.type in (CaptureType.WPA_PSK, CaptureType.WPS_PIN, CaptureType.WPS_PBC) and capture.value:
            found.setdefault((CaptureType.WPA_PSK, capture.value), capture)
    return [(capture_type, value, capture) for (capture_type, value), capture in found.items()]


def password_status(hashlines: Iterable[DatedHashline],
                    keys: Iterable[Key]) -> tuple[PasswordStatus, Optional[Key]]:
    """Judged on the newest authorized hashline, live verification, or key recovered from the AP;
    with none of those, on the newest M1+M2 hashline. ``keys`` is most recently confirmed first."""
    hashlines, keys = list(hashlines), list(keys)
    if not keys:
        return PasswordStatus.NOT_CRACKED, None

    def matching(hashline: DatedHashline) -> Optional[Key]:
        return next((k for k in keys if hashline.id in k.hashline_ids), None)

    evidence: list[tuple[int, Optional[Key]]] = [
        (h.first_captured, matching(h)) for h in hashlines if h.line.authorized]
    for key in keys:
        evidence += [(v.at, key if v.correct else None) for v in key.live_verifications]
        if key.from_access_point:
            evidence.append((key.capture.timestamp, key))
    if evidence:
        _, key = max(evidence, key=lambda e: e[0])
        return (PasswordStatus.CURRENT, key) if key else (PasswordStatus.STALE, keys[0])
    newest_match = next((k for h in hashlines if (k := matching(h))), None)
    return PasswordStatus.NOT_VERIFIED, newest_match or keys[0]


def _confirmed_at(key: Key, hashlines: dict[str, DatedHashline]) -> int:
    dates = [hashlines[h].first_captured for h in key.hashline_ids if h in hashlines]
    dates += [v.at for v in key.live_verifications if v.correct]
    return max(dates, default=key.capture.timestamp)


def load_ap_state(bssid: str, captures: list[PersistedCapture]) -> ApState:
    """``captures``: the AP's indexed captures (every SSID). Dates missing from the .meta files
    are read from the AP's pcaps."""
    metas = [read_meta(path) for path in bssid_meta_paths(bssid)]
    lines = read_hashlines(bssid, captures)
    dates = _stored_dates(metas)
    undated = {hid: line for hid, (_, line) in lines.items() if not dates.get(hid)}
    if undated:
        pcaps = [Path(c.path) for c in captures if c.path.endswith(".pcap")]
        for hid, found in _pcap_dates(undated, pcaps).items():
            dates.setdefault(hid, set()).update(found)

    hashlines = {
        hid: DatedHashline(hid, raw, line,
                           bytes.fromhex(line.essid).decode("utf-8", errors="replace"),
                           tuple(sorted(dates.get(hid, ()))))
        for hid, (raw, line) in lines.items()}
    verifications = _stored_verifications(metas)
    keys = []
    for capture_type, value, capture in _keys_from_captures(captures):
        matched = frozenset(h.id for h in hashlines.values()
                            if capture_type == CaptureType.WPA_PSK and psk_matches(value, h.line))
        keys.append(Key(capture_type, value, capture, matched,
                        tuple(sorted(verifications.get((capture_type, value), []), key=lambda v: v.at))))
    keys.sort(key=lambda k: _confirmed_at(k, hashlines), reverse=True)

    ordered = sorted(hashlines.values(), key=lambda h: (h.first_captured != 0, h.first_captured),
                     reverse=True)
    status, status_key = password_status(ordered, keys)
    ssids = _ssid_histories(ordered, keys)
    hc22000 = sorted((c for c in captures if c.path.endswith(".hc22000")),
                     key=lambda c: (bool(ssids) and c.ssid == ssids[0].ssid, c.timestamp), reverse=True)
    return ApState(bssid, ssids, tuple(ordered), tuple(keys), status, status_key,
                   hc22000[0] if hc22000 else None)


def _ssid_histories(hashlines: list[DatedHashline], keys: list[Key]) -> tuple[SsidHistory, ...]:
    seen: dict[str, list[int]] = {}
    for h in hashlines:
        seen.setdefault(h.ssid, []).extend(h.captured)
    for key in keys:
        if key.capture.ssid and key.capture.ssid not in seen:
            seen[key.capture.ssid] = [key.capture.timestamp]
    histories = [SsidHistory(ssid, min(epochs, default=0), max(epochs, default=0))
                 for ssid, epochs in seen.items()]
    return tuple(sorted(histories, key=lambda s: s.last_seen, reverse=True))


def record_hashlines_captured(ssid: Optional[str], bssid: str, raw_lines: Iterable[str],
                              epoch: Optional[int] = None) -> None:
    """Note in the SSID's .meta that these hashlines were captured, now."""
    path = meta_path(ssid, bssid)
    stored = read_meta(path).get(_HASHLINES_KEY)
    stored = stored if isinstance(stored, dict) else {}
    at = int(time.time()) if epoch is None else epoch
    for raw in raw_lines:
        record = stored.setdefault(hashline_id(raw), {})
        captured = record.setdefault("captured", [])
        if at not in captured:
            captured.append(at)
    update_meta(ssid, bssid, **{_HASHLINES_KEY: stored})


def record_live_verification(key: Key, correct: bool) -> None:
    """Note in the key's SSID .meta that a live check against the AP accepted or rejected it."""
    capture = key.capture
    stored = read_meta(meta_path(capture.ssid, capture.bssid)).get(_LIVE_VERIFICATIONS_KEY)
    stored = stored if isinstance(stored, list) else []
    stored.append({"kind": key.capture_type.value, "key": key.value, "at": int(time.time()),
                   "correct": correct})
    update_meta(capture.ssid, capture.bssid, **{_LIVE_VERIFICATIONS_KEY: stored})
