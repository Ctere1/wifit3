"""Active decloak: send directed Probe Requests with sibling-derived SSID candidates
and let the existing passive decloak path catch the response. When every probe draws
silence, retry the same candidates as Association Requests, which an AP answers on a
match and ignores otherwise."""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Callable, List, Optional

from wifit3.models import AccessPoint
from wifit3.campaigns.auth_assoc import Association, build_client_leaving
from wifit3.campaigns.campaign import Campaign
from wifit3.dot11 import mac_to_str, str_to_mac
from wifit3.dot11.mac import random_client_mac
from wifit3.dot11.probe import probe_req

logger = logging.getLogger(__name__)

_SSID_MAX_OCTETS = 32
_ASSOCIATION_FALLBACK_LIMIT = 32


# Curated suffix list, kept short on purpose so a full run is ~5 seconds.
SIBLING_SUFFIXES: List[str] = [
    "",
    "-Guest", "_Guest", "-guest", " Guest",
    "-5G", "_5G", "-5GHz",
    "-2G", "_2G", "-2.4G", "-2.4GHz",
    "-IoT", "_IoT",
    "-Setup", "_Setup",
    "-EXT",
]


def build_candidates(base: str) -> List[str]:
    """Generate likely sibling SSIDs given a known visible sibling's SSID."""
    if not base:
        return []
    out: List[str] = []
    seen: set[str] = set()
    for suffix in SIBLING_SUFFIXES:
        cand = (base + suffix).rstrip()
        if cand and cand not in seen and len(cand.encode("utf-8")) <= _SSID_MAX_OCTETS:
            seen.add(cand)
            out.append(cand)
    return out


def best_named_sibling_ssid(array, target: AccessPoint) -> str:
    """The loudest visible sibling's SSID, the base a hidden AP's name is guessed from."""
    if array is None or not target.siblings:
        return ""
    best_ssid, best_beacons = "", -1
    for sibling_bssid in target.siblings:
        sibling = array.access_points.get(sibling_bssid)
        if sibling and sibling.ssid and sibling.beacons > best_beacons:
            best_ssid, best_beacons = sibling.ssid, sibling.beacons
    return best_ssid


class DecloakAttack:
    """Run an active decloak sequence against a single hidden AP."""

    def __init__(
        self,
        array,
        target: AccessPoint,
        base_ssid: str,
        source_mac: Optional[bytes] = None,
        candidates_override: Optional[List[str]] = None,
        iface=None,
        association_fallback: bool = True,
    ):
        self.array = array
        self.target = target
        self.base_ssid = base_ssid
        self.bssid_bytes = str_to_mac(target.bssid)
        self.source_mac = source_mac or random_client_mac()
        # When non-None, bypass build_candidates() and use this list verbatim
        # (a hook for supplying SSIDs directly; currently exercised only by tests).
        self.candidates_override = candidates_override
        self.iface = iface
        self.association_fallback = association_fallback
        self.tried = 0
        self.associations_tried = 0
        # Register so client/handshake tracking ignores our forged STA.
        self.array.register_forged_mac(self.source_mac)

    # ---- Driver -------------------------------------------------------------

    async def run(
        self,
        per_candidate_timeout: float = 0.3,
        should_stop: Optional[Callable[[], bool]] = None,
    ) -> Optional[str]:
        """Send one Probe Request per candidate SSID, polling for the parser to flip
        ``ap.ssid``; on silence, retry the candidates as Association Requests. Returns
        the discovered SSID, else None when every candidate is exhausted."""
        iface = self.iface or self.array.select_iface(self.target.channel)
        if iface is None:
            logger.info("[DECLOAK] no card can reach channel %s for %s",
                        self.target.channel, self.target.bssid)
            return None
        if iface.current_channel != self.target.channel:
            await iface.set_channel(self.target.channel)

        candidates = (
            self.candidates_override
            if self.candidates_override is not None
            else build_candidates(self.base_ssid)
        )
        bssid_lower = self.target.bssid.lower()
        initial_ssid = self.array.access_points.get(bssid_lower, self.target).ssid

        src = ("explicit" if self.candidates_override is not None
               else f"base '{self.base_ssid}'")
        logger.info(
            f"[DECLOAK] {self.target.bssid}: trying {len(candidates)} candidates "
            f"({src}) as STA {mac_to_str(self.source_mac)}"
        )

        for candidate in candidates:
            if should_stop is not None and should_stop():
                logger.info("[DECLOAK] stop requested for %s", self.target.bssid)
                return None
            frame = probe_req(self.bssid_bytes, self.source_mac, candidate,
                              channel=self.target.channel)
            await iface.send_no_wait(frame)
            self.tried += 1

            # Poll briefly: the parser flips ap.ssid asynchronously when the AP echoes back a
            # Probe Response the sink's decloak guard sees.
            deadline = time.monotonic() + per_candidate_timeout
            while time.monotonic() < deadline:
                ap_state = self.array.access_points.get(bssid_lower)
                if ap_state and ap_state.ssid and ap_state.ssid != initial_ssid:
                    logger.info(
                        f"[DECLOAK] hit on candidate '{candidate}' → "
                        f"{ap_state.ssid!r}"
                    )
                    return ap_state.ssid
                await asyncio.sleep(0.03)

        if self.association_fallback:
            revealed = await self._associate_through(
                iface, candidates[:_ASSOCIATION_FALLBACK_LIMIT], should_stop,
            )
            if revealed is not None:
                return revealed

        logger.info(f"[DECLOAK] exhausted candidates for {self.target.bssid}")
        return None

    # ---- Association fallback -----------------------------------------------

    async def _associate_through(
        self, iface, candidates: List[str], should_stop: Optional[Callable[[], bool]],
    ) -> Optional[str]:
        """Claim each candidate SSID in an Association Request. An AP that answers one
        has confirmed the name; measured behaviour is accept-on-match and silence
        otherwise, so silence is a refusal and not an inconclusive result."""
        logger.info(
            "[DECLOAK] directed probes silent; trying %d candidates by association",
            len(candidates),
        )
        arm = self.array.lease(fake_mac=self.source_mac, bssid=self.bssid_bytes,
                               iface=iface)
        async with arm:
            # Without active monitor the AP's Auth Resp goes unACKed, auth never completes,
            # and every Assoc is answered with a class-2 deauth instead of a verdict.
            sta = str_to_mac(arm.mac) if arm.mac else self.source_mac
            control = f"wifit3-control-{os.urandom(8).hex()}"
            probe = await self._associate_as(iface, control, should_stop, sta)
            if probe.associated:
                await self._leave(iface, sta)
                logger.info("[DECLOAK] %s accepts any SSID; association cannot confirm one",
                            self.target.bssid)
                return None
            if probe.auth_status is None:
                logger.info("[DECLOAK] %s never answered our Auth Req; association "
                            "cannot confirm an SSID", self.target.bssid)
                return None
            for candidate in candidates:
                if should_stop is not None and should_stop():
                    return None
                association = await self._associate_as(iface, candidate, should_stop, sta)
                self.associations_tried += 1
                if association.associated:
                    await self._leave(iface, sta)
                    self.array.confirm_decloak(self.target.bssid, candidate, "assoc")
                    logger.info("[DECLOAK] %s accepted candidate %r",
                                self.target.bssid, candidate)
                    return candidate
        return None

    async def _associate_as(self, iface, ssid: str, should_stop, our_mac: bytes) -> Association:
        association = Association(
            iface,
            self.target.bssid,
            ssid,
            self.target.channel,
            our_mac=our_mac,
            auth_timeout=0.2,
            assoc_timeout=0.3,
            assoc_trailer_ies=self.target.rsn_ie or b"",
            privacy=bool(self.target.rsn_ie),
            should_stop=should_stop,
        )
        association.start()
        try:
            await association.associate(attempts=1)
        finally:
            association.stop()
        return association

    async def _leave(self, iface, our_mac: bytes) -> None:
        try:
            await iface.send_no_wait(
                build_client_leaving(self.bssid_bytes, our_mac)
            )
        except Exception:
            logger.debug("[DECLOAK] client-leaving cleanup failed", exc_info=True)


class DecloakCampaign(Campaign):
    """The Focus-screen wrapper: guess one hidden AP's SSID, then stand down."""

    button_id = "btn-decloak"
    key = "decloak"
    hotkey = ("h", "Decloak")
    idle_label = "Decloak"
    run_label = "Stop Decloak"

    @classmethod
    def visible(cls, ap) -> bool:
        return ap.is_hidden

    @classmethod
    def ineligible_reason(cls, ap) -> Optional[str]:
        return None if ap.siblings else "No named sibling to guess from"

    def __init__(self, array, target, *, candidates: Optional[List[str]] = None,
                 base_ssid: str = "", log: Optional[Callable[[str], None]] = None):
        super().__init__(ap=target, array=array)
        self.candidates = candidates
        self.base_ssid = base_ssid or best_named_sibling_ssid(array, target)
        self._log = log or (lambda _message: None)
        self._attack: Optional[DecloakAttack] = None
        self.revealed: Optional[str] = None
        self.tried = 0

    def status_under_card(self) -> str:
        return "● Decloak"

    def status_headlines(self, vault) -> list[str]:
        total = len(self.candidates if self.candidates is not None
                    else build_candidates(self.base_ssid))
        return ["[bold cyan]● Decloak[/bold cyan] probing candidate SSIDs",
                f"[dim]{self.tried}/{total} sent[/dim]"]

    async def _loop(self) -> None:
        self._attack = DecloakAttack(
            self.array,
            self.ap,
            base_ssid=self.base_ssid,
            candidates_override=self.candidates,
            iface=self.iface,
        )
        self._log(f"guessing from '{self.base_ssid}'" if self.base_ssid
                  else "no named sibling; nothing to guess from")
        try:
            self.revealed = await self._attack.run(should_stop=lambda: self.stopped)
        finally:
            self.tried = self._attack.tried

    async def teardown(self) -> None:
        if self._attack is not None:
            self.array.unregister_own_mac(self._attack.source_mac)
