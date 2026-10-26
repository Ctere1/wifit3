"""One AP's keys, hashlines and SSIDs across every SSID it has had, and its password status."""
from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable, Optional

from wifit3.crack.hc22000_format import Hc22000Line, hashline_id, read_hc22000
from wifit3.crack.wpa_psk import psk_matches
from wifit3.models import AP_RECOVERED_CAPTURE_TYPES, PSK_CAPTURE_TYPES, CaptureType, PersistedCapture
from wifit3.persist.exhaustion import Exhaustion, read_exhaustion
from wifit3.persist.meta import meta_path, read_bssid_metas, read_meta, update_meta
from wifit3.persist.pcap import read_pcap

_HASHLINES_KEY = "hashlines"
_LIVE_VERIFICATIONS_KEY = "live_verifications"
_PASSWORD_KEY_TYPES = frozenset({CaptureType.WPA_PSK, CaptureType.WEP})


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
    captured: tuple[int, ...]       # epoch seconds; empty when no record or pcap dates it

    @property
    def first_captured(self) -> Optional[int]:
        return min(self.captured, default=None)


@dataclass(frozen=True)
class LiveVerification:
    at: int
    correct: bool


@dataclass(frozen=True)
class Key:
    type: CaptureType               # the key's kind: WPA_PSK (also when recovered over WPS), WPS_PIN or WEP
    value: str                      # passphrase or raw PMK, WPS PIN, or WEP key hex
    captures: tuple[PersistedCapture, ...]  # every saved capture holding it, newest first
    hashline_ids: frozenset[str]
    live_verifications: tuple[LiveVerification, ...]

    @property
    def newest_capture(self) -> PersistedCapture:
        return self.captures[0]

    @property
    def is_password(self) -> bool:
        return self.type in _PASSWORD_KEY_TYPES

    @property
    def ap_recovered_at(self) -> Optional[int]:
        """When the AP itself last gave the key up (WEP IVs, WPS), so it was correct then."""
        return next((c.timestamp for c in self.captures if c.type in AP_RECOVERED_CAPTURE_TYPES), None)


@dataclass(frozen=True)
class SsidHistory:
    ssid: str
    first_seen: Optional[int]
    last_seen: Optional[int]


@dataclass(frozen=True)
class ApState:
    bssid: str
    ssids: tuple[SsidHistory, ...]          # newest first
    hashlines: tuple[DatedHashline, ...]    # newest first, undated last
    keys: tuple[Key, ...]                   # most recently confirmed first
    status: PasswordStatus
    status_key: Optional[Key]
    hashline_capture: Optional[PersistedCapture]    # the newest SSID's .hc22000; jobs are filed under it
    uncracked: tuple[DatedHashline, ...]            # the hashlines no key matches, newest first
    uncracked_exhaustion: tuple[Exhaustion, ...]    # wordlists that ran out on the uncracked lines


def epoch_sort_key(epoch: Optional[int]) -> tuple[bool, int]:
    """Sort key for an optional epoch; with ``reverse=True``, newest first and undated last."""
    return epoch is not None, epoch or 0


def _pcap_dates(lines: dict[str, Hc22000Line], pcaps: Iterable[Path]) -> dict[str, set[int]]:
    """Per hashline id, the time of each pcap frame carrying its MIC or PMKID."""
    needles = {hid: bytes.fromhex(line.pmkid_or_mic) for hid, line in lines.items()}
    found: dict[str, set[int]] = {}
    for pcap in pcaps:
        for frame, epoch in read_pcap(pcap):
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


def _capture_type(value: object) -> Optional[CaptureType]:
    try:
        return CaptureType(value)
    except ValueError:
        return None


def _stored_verifications(metas: list[dict]) -> dict[tuple[CaptureType, str], list[LiveVerification]]:
    found: dict[tuple[CaptureType, str], list[LiveVerification]] = {}
    for meta in metas:
        stored = meta.get(_LIVE_VERIFICATIONS_KEY)
        if not isinstance(stored, list):
            continue
        for record in stored:
            if not isinstance(record, dict):
                continue
            kind, value, at = _capture_type(record.get("kind")), record.get("key"), record.get("at")
            if kind is not None and isinstance(value, str) and isinstance(at, int):
                found.setdefault((kind, value), []).append(LiveVerification(at, bool(record.get("correct"))))
    return found


def read_hashlines(bssid: str, captures: list[PersistedCapture]) -> dict[str, tuple[str, Hc22000Line]]:
    """The AP's lines in its captures' .hc22000 files, ``{hashline id: (raw, parsed)}``."""
    compact_bssid = bssid.replace(":", "").lower()
    found: dict[str, tuple[str, Hc22000Line]] = {}
    for path in dict.fromkeys(c.path for c in captures if c.path.endswith(".hc22000")):
        for raw, line in read_hc22000(path):
            if line.mac_ap == compact_bssid:
                found.setdefault(hashline_id(raw), (raw, line))
    return found


def _keys_in_capture(capture: PersistedCapture) -> list[tuple[CaptureType, str]]:
    keys = []
    if capture.type == CaptureType.WEP and capture.value:
        keys.append((CaptureType.WEP, capture.value))
    if capture.type == CaptureType.WPS_PIN and capture.pin is not None:
        keys.append((CaptureType.WPS_PIN, capture.pin))
    if capture.type in PSK_CAPTURE_TYPES and capture.value:
        keys.append((CaptureType.WPA_PSK, capture.value))
    return keys


def _key_captures(captures: list[PersistedCapture]) -> dict[tuple[CaptureType, str], list[PersistedCapture]]:
    """Every saved key, ``(kind, value)``, and the captures holding it, newest first."""
    found: dict[tuple[CaptureType, str], list[PersistedCapture]] = {}
    for capture in sorted(captures, key=lambda c: c.timestamp, reverse=True):
        for kind_and_value in _keys_in_capture(capture):
            found.setdefault(kind_and_value, []).append(capture)
    return found


def _confirmations(key: Key, hashlines: Iterable[DatedHashline]) -> list[Optional[int]]:
    """Dates of the authorized hashlines (None when undated), correct live checks and AP recoveries
    that confirm the key. An M1+M2 match doesn't: it may be a client's wrong password."""
    dates = [h.first_captured for h in hashlines if h.id in key.hashline_ids and h.line.authorized]
    dates += [v.at for v in key.live_verifications if v.correct]
    if key.ap_recovered_at is not None:
        dates.append(key.ap_recovered_at)
    return dates


def confirmed_at(key: Key, hashlines: Iterable[DatedHashline]) -> Optional[int]:
    """When the key was last confirmed; None if nothing dated has (see ``is_confirmed``)."""
    return max((d for d in _confirmations(key, hashlines) if d is not None), default=None)


def is_confirmed(key: Key, hashlines: Iterable[DatedHashline]) -> bool:
    return bool(_confirmations(key, hashlines))


def _matching_key(hashline: DatedHashline, keys: list[Key]) -> Optional[Key]:
    return next((k for k in keys if hashline.id in k.hashline_ids), None)


def _evidence(hashlines: list[DatedHashline], keys: list[Key]) -> list[tuple[Optional[int], Optional[Key]]]:
    """Each authorized hashline (with the password key matching it), correct live check and AP
    recovery of a password key, newest first."""
    evidence: list[tuple[Optional[int], Optional[Key]]] = [
        (h.first_captured, _matching_key(h, keys)) for h in hashlines if h.line.authorized]
    for key in keys:
        evidence += [(v.at, key) for v in key.live_verifications if v.correct]
        if (recovered_at := key.ap_recovered_at) is not None:
            evidence.append((recovered_at, key))
    return sorted(evidence, key=lambda e: epoch_sort_key(e[0]), reverse=True)


def password_status(hashlines: Iterable[DatedHashline],
                    keys: Iterable[Key]) -> tuple[PasswordStatus, Optional[Key]]:
    """Judged on the newest authorized hashline, correct live check, or key the AP gave up; with
    none of those, on the newest M1+M2 hashline. Only PSKs and WEP keys count; ``hashlines`` is
    newest first, ``keys`` most recently confirmed first."""
    hashlines = list(hashlines)
    keys = [k for k in keys if k.is_password]
    if not keys:
        return PasswordStatus.NOT_CRACKED, None
    evidence = _evidence(hashlines, keys)
    if not evidence:
        newest_match = next((k for h in hashlines if (k := _matching_key(h, keys))), None)
        return PasswordStatus.NOT_VERIFIED, newest_match or keys[0]

    newest_at, newest_key = evidence[0]
    if newest_key is not None:
        return PasswordStatus.CURRENT, newest_key
    unconfirmed_newer = [k for k in keys if newest_at is not None and k.newest_capture.timestamp > newest_at
                         and not is_confirmed(k, hashlines)]
    if unconfirmed_newer:
        return PasswordStatus.NOT_VERIFIED, unconfirmed_newer[0]
    return PasswordStatus.STALE, next((key for _, key in evidence if key is not None), None)


def key_status(key: Key, state: ApState) -> PasswordStatus:
    """The AP's status for its status key. Any other key: NOT_VERIFIED when nothing confirms it,
    STALE when evidence newer than its last confirmation refutes it, else CURRENT."""
    if key == state.status_key:
        return state.status
    if not is_confirmed(key, state.hashlines):
        return PasswordStatus.NOT_VERIFIED
    if not key.is_password:
        return PasswordStatus.CURRENT
    hashlines = list(state.hashlines)
    newest_at = next((at for at, _ in _evidence(hashlines, [k for k in state.keys if k.is_password])
                      if at is not None), None)
    if newest_at is None or epoch_sort_key(confirmed_at(key, hashlines)) >= epoch_sort_key(newest_at):
        return PasswordStatus.CURRENT
    return PasswordStatus.STALE


def load_ap_state(bssid: str, captures: list[PersistedCapture]) -> ApState:
    """``captures``: the AP's indexed captures (every SSID). Dates missing from the .meta files
    are read from the AP's pcaps."""
    metas = read_bssid_metas(bssid)
    lines = read_hashlines(bssid, captures)
    dates = _stored_dates(metas)
    undated = {hid: line for hid, (_, line) in lines.items() if not dates.get(hid)}
    if undated:
        pcaps = [Path(c.path) for c in captures if c.path.endswith(".pcap")]
        for hid, found in _pcap_dates(undated, pcaps).items():
            dates.setdefault(hid, set()).update(found)

    hashlines = sorted(
        (DatedHashline(hid, raw, line, tuple(sorted(dates.get(hid, ())))) for hid, (raw, line) in lines.items()),
        key=lambda h: epoch_sort_key(h.first_captured), reverse=True)
    verifications = _stored_verifications(metas)
    keys = []
    for (key_type, value), key_captures in _key_captures(captures).items():
        matched = frozenset(h.id for h in hashlines
                            if key_type == CaptureType.WPA_PSK and psk_matches(value, h.line))
        keys.append(Key(key_type, value, tuple(key_captures), matched,
                        tuple(sorted(verifications.get((key_type, value), []), key=lambda v: v.at))))
    keys.sort(key=lambda k: epoch_sort_key(confirmed_at(k, hashlines)), reverse=True)

    status, status_key = password_status(hashlines, keys)
    ssids = _ssid_histories(hashlines, keys)
    hc22000 = sorted((c for c in captures if c.path.endswith(".hc22000")),
                     key=lambda c: (bool(ssids) and c.ssid == ssids[0].ssid, c.timestamp), reverse=True)
    cracked = {hid for key in keys for hid in key.hashline_ids}
    uncracked = tuple(h for h in hashlines if h.id not in cracked)
    exhaustion = read_exhaustion(metas, [h.id for h in uncracked]) if uncracked else {}
    return ApState(bssid, ssids, tuple(hashlines), tuple(keys), status, status_key,
                   hc22000[0] if hc22000 else None, uncracked, tuple(exhaustion.values()))


def _ssid_histories(hashlines: list[DatedHashline], keys: list[Key]) -> tuple[SsidHistory, ...]:
    seen: dict[str, list[int]] = {}
    for h in hashlines:
        seen.setdefault(h.line.ssid, []).extend(h.captured)
    for key in keys:
        for capture in key.captures:
            if capture.ssid and capture.ssid not in seen:
                seen[capture.ssid] = [capture.timestamp]
    histories = [SsidHistory(ssid, min(epochs, default=None), max(epochs, default=None))
                 for ssid, epochs in seen.items()]
    return tuple(sorted(histories, key=lambda s: epoch_sort_key(s.last_seen), reverse=True))


def record_hashlines_captured(ssid: Optional[str], bssid: str, raw_lines: Iterable[str]) -> None:
    """Note in the SSID's .meta that these hashlines were captured, now."""
    stored = read_meta(meta_path(ssid, bssid)).get(_HASHLINES_KEY)
    stored = stored if isinstance(stored, dict) else {}
    now = int(time.time())
    for raw in raw_lines:
        hid = hashline_id(raw)
        if not isinstance(stored.get(hid), dict):
            stored[hid] = {}
        if not isinstance(stored[hid].get("captured"), list):
            stored[hid]["captured"] = []
        if now not in stored[hid]["captured"]:
            stored[hid]["captured"].append(now)
    update_meta(ssid, bssid, **{_HASHLINES_KEY: stored})


def record_live_verification(key: Key, correct: bool) -> None:
    """Note in the .meta of the key's newest capture that a live check against the AP accepted or
    rejected it."""
    capture = key.newest_capture
    stored = read_meta(meta_path(capture.ssid, capture.bssid)).get(_LIVE_VERIFICATIONS_KEY)
    stored = stored if isinstance(stored, list) else []
    stored.append({"kind": key.type.value, "key": key.value, "at": int(time.time()), "correct": correct})
    update_meta(capture.ssid, capture.bssid, **{_LIVE_VERIFICATIONS_KEY: stored})
