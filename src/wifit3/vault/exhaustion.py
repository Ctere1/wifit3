"""Which wordlists ran to the end against which hashlines, kept in the AP's .meta file."""
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from wifit3.crack.hc22000_format import hashline_id, read_hc22000
from wifit3.crack.passwords import DEFAULT_PASSWORDS_PATH, SSID_VARIANTS_VERSION
from wifit3.models import PersistedCapture
from wifit3.persist.config import Config
from wifit3.persist.meta import bssid_meta_paths, meta_path, read_meta, update_meta

SSID_VARIANTS_IDENTITY = f"ssid-variants:v{SSID_VARIANTS_VERSION}"
SSID_VARIANTS_NAME = "SSID variants"
_EXHAUSTED_KEY = "exhausted"
_WORDLISTS_KEY = "wordlists"


@dataclass(frozen=True)
class Exhaustion:
    exhausted_hashlines: int
    hashlines: int
    latest: int             # epoch seconds of the newest record among the exhausted hashlines


def capture_hashline_ids(capture_path: str) -> list[str]:
    """``hashline_id`` of each hashline in the capture file, deduped."""
    return list(dict.fromkeys(hashline_id(raw) for raw, _ in read_hc22000(capture_path)))


def wordlist_identity(path: str | Path) -> str:
    """Size and mtime, so a moved or renamed wordlist keeps its identity."""
    stat = Path(path).stat()
    return f"{stat.st_size}:{stat.st_mtime_ns}"


def _exhausted(meta: dict) -> dict[str, dict[str, int]]:
    stored = meta.get(_EXHAUSTED_KEY)
    if not isinstance(stored, dict):
        return {}
    return {identity: {hashline: epoch for hashline, epoch in recorded.items()
                       if isinstance(epoch, int)}
            for identity, recorded in stored.items() if isinstance(recorded, dict)}


def _wordlist_names(meta: dict) -> dict[str, list[str]]:
    stored = meta.get(_WORDLISTS_KEY)
    if not isinstance(stored, dict):
        return {}
    return {identity: [n for n in record.get("names", []) if isinstance(n, str)]
            for identity, record in stored.items() if isinstance(record, dict)}


def record_exhausted(ssid: Optional[str], bssid: str, identity: str, wordlist_name: str,
                     hashline_ids: list[str]) -> None:
    """Note in the AP's .meta that ``identity`` (named ``wordlist_name``) ran out on these
    hashlines, now."""
    if not hashline_ids:
        return
    meta = read_meta(meta_path(ssid, bssid))
    exhausted = _exhausted(meta)
    recorded = exhausted.setdefault(identity, {})
    now = int(time.time())
    for hashline in hashline_ids:
        recorded[hashline] = max(recorded.get(hashline, 0), now)
    names = _wordlist_names(meta)
    if wordlist_name and wordlist_name not in names.setdefault(identity, []):
        names[identity].append(wordlist_name)
    saved_ssid = meta.get("ssid")
    update_meta(saved_ssid if isinstance(saved_ssid, str) else ssid, bssid,
                **{_EXHAUSTED_KEY: exhausted,
                   _WORDLISTS_KEY: {i: {"names": n} for i, n in names.items()}})


def exhausted_wordlist_names(bssid: str, hashline_ids: list[str]) -> dict[str, int]:
    """Per wordlist that ran out on any of these hashlines (any SSID of the BSSID), how many.
    Records from before names were stored are named from the configured wordlists, if found."""
    exhausted: dict[str, set[str]] = {}
    names: dict[str, list[str]] = {}
    for path in bssid_meta_paths(bssid):
        meta = read_meta(path)
        for identity, recorded in _exhausted(meta).items():
            exhausted.setdefault(identity, set()).update(recorded)
        for identity, stored in _wordlist_names(meta).items():
            names.setdefault(identity, []).extend(n for n in stored if n not in names[identity])
    configured = {SSID_VARIANTS_IDENTITY: SSID_VARIANTS_NAME}
    for wordlist in [DEFAULT_PASSWORDS_PATH, *Config.hashcat.wordlists, *Config.cpu_crack.wordlists]:
        try:
            configured.setdefault(wordlist_identity(wordlist), Path(wordlist).name)
        except OSError:
            continue
    found: dict[str, int] = {}
    wanted = set(hashline_ids)
    for identity, recorded in exhausted.items():
        count = len(recorded & wanted)
        if count:
            name = " / ".join(names.get(identity) or [configured.get(identity, "unnamed wordlist")])
            found[name] = found.get(name, 0) + count
    return found


def capture_exhaustion(capture: PersistedCapture) -> dict[str, Exhaustion]:
    """Per identity that ran out on any of the capture's current hashlines."""
    hashline_ids = capture_hashline_ids(capture.path)
    exhausted = _exhausted(read_meta(meta_path(capture.ssid, capture.bssid)))
    found: dict[str, Exhaustion] = {}
    for identity, recorded in exhausted.items():
        epochs = [recorded[hashline] for hashline in hashline_ids if hashline in recorded]
        if epochs:
            found[identity] = Exhaustion(len(epochs), len(hashline_ids), max(epochs))
    return found
