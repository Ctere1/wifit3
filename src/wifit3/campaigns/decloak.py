"""Guess a hidden AP's SSID: directed Probe Requests first, then Association Requests.

An AP answers a directed probe only when it names the AP, so the sink's existing decloak
path catches the reply. When every probe draws silence, the same candidates are claimed in
Association Requests: 802.11 keeps a refused station in state 2, so one authentication
covers the whole sweep.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Callable, Optional

from wifit3.campaigns.auth_assoc import Association, build_client_leaving
from wifit3.campaigns.campaign import Campaign
from wifit3.dot11 import mac_to_str, str_to_mac
from wifit3.dot11.mac import random_client_mac
from wifit3.dot11.probe import probe_req
from wifit3.models import AccessPoint
from wifit3.wlan.array import WlanArray
from wifit3.wlan.interface import WlanInterface

logger = logging.getLogger(__name__)

SSID_MAX_OCTETS = 32
PROBE_REPLY_WINDOW_S = 0.3
ASSOCIATION_CANDIDATE_LIMIT = 32

# Curated suffix list, kept short on purpose so a full run is ~5 seconds. In-house: keep
# growing it, do not import anyone else's.
SIBLING_SUFFIXES: list[str] = [
    "",
    "-Guest", "_Guest", "-guest", " Guest",
    "-5G", "_5G", "-5GHz",
    "-2G", "_2G", "-2.4G", "-2.4GHz",
    "-IoT", "_IoT",
    "-Setup", "_Setup",
    "-EXT",
]


def candidates_from_sibling(sibling_ssid: str) -> list[str]:
    """Likely names for a hidden AP, built from a visible sibling's SSID."""
    if not sibling_ssid:
        return []
    candidates: list[str] = []
    for suffix in SIBLING_SUFFIXES:
        candidate = (sibling_ssid + suffix).rstrip()
        if (candidate and candidate not in candidates
                and len(candidate.encode("utf-8")) <= SSID_MAX_OCTETS):
            candidates.append(candidate)
    return candidates


def named_sibling_ssid(array: WlanArray, hidden: AccessPoint) -> str:
    """The SSID of the hidden AP's most-beaconed named sibling; "" when it has none."""
    best_ssid, best_beacons = "", -1
    for bssid in hidden.siblings:
        sibling = array.access_points.get(bssid)
        if sibling and sibling.ssid and sibling.beacons > best_beacons:
            best_ssid, best_beacons = sibling.ssid, sibling.beacons
    return best_ssid


class DecloakAttack:
    """One decloak run against one hidden AP, over one card."""

    def __init__(self, array: WlanArray, target: AccessPoint, iface: WlanInterface,
                 candidates: list[str]) -> None:
        self.array = array
        self.target = target
        self.iface = iface
        self.candidates = candidates
        self.bssid_bytes = str_to_mac(target.bssid)
        self.source_mac = random_client_mac()
        self.probes_sent = 0
        self.associations_sent = 0
        self.array.register_forged_mac(self.source_mac)

    async def run(self, should_stop: Callable[[], bool]) -> Optional[str]:
        """The revealed SSID, or None once every candidate is exhausted."""
        if self.iface.current_channel != self.target.channel:
            await self.iface.set_channel(self.target.channel)
        revealed = await self._probe_every_candidate(should_stop)
        if revealed is None and not should_stop():
            revealed = await self._associate_every_candidate(should_stop)
        if revealed is None:
            logger.info("[DECLOAK] %s: no candidate matched", self.target.bssid)
        return revealed

    # ----- probes ------------------------------------------------------------

    async def _probe_every_candidate(self, should_stop: Callable[[], bool]) -> Optional[str]:
        bssid = self.target.bssid.lower()
        before = self.array.access_points.get(bssid, self.target).ssid
        logger.info("[DECLOAK] %s: probing %d candidates as STA %s", self.target.bssid,
                    len(self.candidates), mac_to_str(self.source_mac))
        for candidate in self.candidates:
            if should_stop():
                return None
            await self.iface.send_no_wait(
                probe_req(self.bssid_bytes, self.source_mac, candidate,
                          channel=self.target.channel)
            )
            self.probes_sent += 1
            revealed = await self._await_reveal(bssid, before, should_stop)
            if revealed is not None:
                logger.info("[DECLOAK] probe hit on %r -> %r", candidate, revealed)
                return revealed
        return None

    async def _await_reveal(self, bssid: str, before: Optional[str],
                            should_stop: Callable[[], bool]) -> Optional[str]:
        """Poll the sink, which flips ap.ssid asynchronously when the Probe Response lands."""
        deadline = time.monotonic() + PROBE_REPLY_WINDOW_S
        while time.monotonic() < deadline and not should_stop():
            ap = self.array.access_points.get(bssid)
            if ap and ap.ssid and ap.ssid != before:
                return ap.ssid
            await asyncio.sleep(0.03)
        return None

    # ----- associations ------------------------------------------------------

    async def _associate_every_candidate(self, should_stop: Callable[[], bool]) -> Optional[str]:
        candidates = self.candidates[:ASSOCIATION_CANDIDATE_LIMIT]
        logger.info("[DECLOAK] probes silent; associating through %d candidates",
                    len(candidates))
        # Unarmed, the AP's Auth Resp goes unACKed, authentication never completes, and
        # every Assoc Req comes back as a class-2 deauth instead of a verdict.
        arm = self.array.lease(fake_mac=self.source_mac, bssid=self.bssid_bytes,
                               iface=self.iface)
        async with arm:
            our_mac = str_to_mac(arm.mac) if arm.mac else self.source_mac
            association = self._association(our_mac, should_stop)
            association.start()
            try:
                if not await association.authenticate():
                    logger.info("[DECLOAK] %s will not authenticate us", self.target.bssid)
                    return None
                if await association.associate_as(self._control_ssid()) == 0:
                    logger.info("[DECLOAK] %s accepts any SSID; association proves nothing",
                                self.target.bssid)
                    return None
                return await self._claim_each(association, candidates, should_stop)
            finally:
                association.stop()
                await self._announce_leaving(our_mac)

    async def _claim_each(self, association: Association, candidates: list[str],
                          should_stop: Callable[[], bool]) -> Optional[str]:
        for candidate in candidates:
            if should_stop():
                return None
            # A refusal leaves us in state 2 and a disassoc returns us to it; only a deauth
            # drops us to state 1, where the sweep has to authenticate again.
            if association.state == 1 and not await association.authenticate():
                logger.info("[DECLOAK] %s deauthenticated us mid-sweep", self.target.bssid)
                return None
            self.associations_sent += 1
            if await association.associate_as(candidate) == 0:
                self.array.confirm_decloak(self.target.bssid, candidate, "assoc")
                logger.info("[DECLOAK] %s accepted %r", self.target.bssid, candidate)
                return candidate
        return None

    def _association(self, our_mac: bytes, should_stop: Callable[[], bool]) -> Association:
        return Association(self.iface, self.target.bssid, "", self.target.channel,
                           our_mac=our_mac, auth_timeout=0.2, assoc_timeout=0.3,
                           assoc_trailer_ies=self.target.rsn_ie or b"",
                           privacy=bool(self.target.rsn_ie), should_stop=should_stop)

    @staticmethod
    def _control_ssid() -> str:
        """A name no AP can legitimately own: one that accepts it accepts anything."""
        return f"wifit3-control-{os.urandom(8).hex()}"

    async def _announce_leaving(self, our_mac: bytes) -> None:
        try:
            await self.iface.send_no_wait(build_client_leaving(self.bssid_bytes, our_mac))
        except Exception:
            logger.debug("[DECLOAK] client-leaving cleanup failed", exc_info=True)


class DecloakCampaign(Campaign):
    """Focus-screen wrapper: guess one hidden AP's SSID, then stand down."""

    button_id = "btn-decloak"
    key = "decloak"
    hotkey = ("h", "Decloak")
    idle_label = "Decloak"
    run_label = "Stop Decloak"

    @classmethod
    def visible(cls, ap: AccessPoint) -> bool:
        return ap.is_hidden

    @classmethod
    def ineligible_reason(cls, ap: AccessPoint) -> Optional[str]:
        return None if ap.siblings else "No named sibling to guess from"

    def __init__(self, array: WlanArray, target: AccessPoint, *,
                 candidates: Optional[list[str]] = None,
                 log: Optional[Callable[[str], None]] = None) -> None:
        super().__init__(ap=target, array=array)
        self.sibling_ssid = named_sibling_ssid(array, target)
        self.candidates = candidates or candidates_from_sibling(self.sibling_ssid)
        self._log = log or (lambda _message: None)
        self._attack: Optional[DecloakAttack] = None
        self.revealed: Optional[str] = None
        self.tried = 0

    def status_under_card(self) -> str:
        return "● Decloak"

    def status_headlines(self, vault) -> list[str]:
        return ["[bold cyan]● Decloak[/bold cyan] probing candidate SSIDs",
                f"[dim]{self.tried}/{len(self.candidates)} sent[/dim]"]

    async def _loop(self) -> None:
        if not self.candidates:
            self._log("no named sibling to guess from")
            return
        if self.iface is None:
            self._log(f"no card can reach channel {self.ap.channel}")
            return
        self._log(f"guessing from '{self.sibling_ssid}'")
        self._attack = DecloakAttack(self.array, self.ap, self.iface, self.candidates)
        try:
            self.revealed = await self._attack.run(lambda: self.stopped)
        finally:
            self.tried = self._attack.probes_sent

    async def teardown(self) -> None:
        if self._attack is not None:
            self.array.unregister_own_mac(self._attack.source_mac)
