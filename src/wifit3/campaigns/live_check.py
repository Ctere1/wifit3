"""Live key verifier: validates stored credentials against a live access point.

Runs on-demand from the Vault UI without using offline VaultTools.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Optional, Tuple

from wifit3.campaigns.auth_assoc import Association, WlanTransport
from wifit3.campaigns.campaign import Campaign
from wifit3.campaigns.wps.registrar import PinResult, WpsRegistrar
from wifit3.crack.wep import rc4_keystream
from wifit3.dot11 import build_deauth, random_client_mac, str_to_mac
from wifit3.dot11.ie import GENERIC_RSN_IE, force_psk_akm
from wifit3.dot11.mac import mac_header
from wifit3.dot11.packet import EapolPacket, WepDataPacket
from wifit3.dot11.wep.crypto import arp_request_plaintext, icv, wep_encrypt
from wifit3.dot11.wpa import build_eapol_m2, derive_pmk, derive_ptk, random_nonce
from wifit3.dot11.wsc.assoc_ie import WPS_REQ_REGISTRAR, wps_assoc_ie
from wifit3.models import AccessPoint, CaptureType, PersistedCapture

logger = logging.getLogger(__name__)


class LiveKeyVerifier:
    """Verifies stored credentials against in-range APs via live radio frames."""

    async def verify_credential(self, capture: PersistedCapture, array) -> Tuple[bool, str]:
        """Verify the credential in ``capture`` against the live AP using ``array``."""
        if Campaign.active is not None:
            return False, f"Cannot verify: {Campaign.active.key} campaign is active"

        if not array or not array.members:
            return False, "No wireless adapter available"

        ap: Optional[AccessPoint] = array.access_points.get(capture.bssid.lower())
        if ap is None:
            return False, f"AP {capture.ssid or capture.bssid} not in range"

        iface = array.select_iface(ap.channel)
        if iface is None:
            return False, f"No wireless card supports channel {ap.channel}"

        async with array.claim(iface):
            await iface.set_channel(ap.channel)
            now = time.time()
            if now - ap.last_seen > 15.0:
                seen = await array.wait_until(
                    lambda: time.time() - array.access_points.get(capture.bssid.lower(), ap).last_seen <= 2.0,
                    timeout=1.5,
                    poll=0.1,
                )
                if not seen:
                    return False, f"AP {ap.ssid or ap.bssid} not in range on channel {ap.channel}"

            our_mac = random_client_mac()
            our_mac_str = array.register_own_mac(our_mac)
            await iface.set_fake_mac(our_mac, str_to_mac(ap.bssid))
            try:
                if capture.type in (CaptureType.WPA_PSK, CaptureType.WPS_PBC):
                    psk = capture.value or ""
                    return await self._verify_wpa_psk(iface, array, ap, psk, our_mac, our_mac_str)
                if capture.type == CaptureType.WPS_PIN:
                    pin = capture.pin or capture.value or ""
                    return await self._verify_wps_pin(iface, ap, pin, our_mac)
                if capture.type == CaptureType.WEP:
                    key = capture.value or ""
                    return await self._verify_wep_key(iface, array, ap, key, our_mac)
                return False, f"Unsupported capture type: {capture.type}"
            finally:
                try:
                    deauth = build_deauth(str_to_mac(ap.bssid), our_mac, str_to_mac(ap.bssid), 3)
                    await iface.send_no_wait(deauth)
                    await asyncio.sleep(0.5)
                except Exception:
                    pass
                finally:
                    try:
                        await iface.clear_fake_mac()
                    except Exception:
                        pass
                    array.unregister_own_mac(our_mac_str)

    async def _verify_wpa_psk(
        self, iface, array, ap: AccessPoint, psk: str, our_mac: bytes, our_mac_str: str
    ) -> Tuple[bool, str]:
        trailer = force_psk_akm(ap.rsn_ie or GENERIC_RSN_IE) or GENERIC_RSN_IE
        assoc = Association(
            iface,
            ap.bssid,
            ap.ssid or "",
            ap.channel,
            our_mac=our_mac,
            assoc_trailer_ies=trailer,
        )
        assoc.start()
        try:
            if not await assoc.associate(attempts=2):
                return False, f"Association failed: {assoc.fail_reason or 'no response'}"
        finally:
            assoc.stop()

        m1_pkt = await array.next_frame(
            lambda p: (
                isinstance(p, EapolPacket)
                and p.dest == our_mac_str
                and p.bssid == ap.bssid.lower()
                and p.msg_num == 1
                and p.nonce is not None
            ),
            timeout=2.0,
        )
        if m1_pkt is None or m1_pkt.nonce is None:
            return False, "AP never sent EAPOL M1"

        pmk = derive_pmk(psk, ap.ssid or "")
        snonce = random_nonce()
        replay = int.from_bytes(m1_pkt.replay_counter, "big") if m1_pkt.replay_counter else 1
        ptk = derive_ptk(pmk, str_to_mac(ap.bssid), our_mac, m1_pkt.nonce, snonce)
        kck = ptk[:16]
        m2 = build_eapol_m2(
            str_to_mac(ap.bssid), our_mac, m1_pkt.nonce, snonce, kck, replay=replay, rsn_ie=trailer
        )
        await iface.send_no_wait(m2)

        m3_pkt = await array.next_frame(
            lambda p: (
                isinstance(p, EapolPacket)
                and p.dest == our_mac_str
                and p.bssid == ap.bssid.lower()
                and p.msg_num == 3
            ),
            timeout=2.0,
        )
        if m3_pkt is not None:
            return True, "WPA PSK still works"
        return False, "WPA PSK failed: No M3 received"

    async def _verify_wps_pin(
        self, iface, ap: AccessPoint, pin: str, our_mac: bytes
    ) -> Tuple[bool, str]:
        assoc = Association(
            iface,
            ap.bssid,
            ap.ssid or "",
            ap.channel,
            our_mac=our_mac,
            assoc_trailer_ies=wps_assoc_ie(WPS_REQ_REGISTRAR),
        )
        assoc.start()
        transport = WlanTransport(iface, str_to_mac(ap.bssid), our_mac)
        transport.start()
        try:
            if not await assoc.associate(attempts=2):
                return False, f"Association failed: {assoc.fail_reason or 'no response'}"
            reg = WpsRegistrar(transport, str_to_mac(ap.bssid), our_mac)
            outcome = await reg.try_pin(pin)
            if outcome.result == PinResult.SUCCESS:
                return True, "WPS PIN still works"
            if outcome.result in (PinResult.FIRST_HALF_WRONG, PinResult.SECOND_HALF_WRONG):
                return False, "WPS PIN invalid"
            return False, f"WPS verification failed: {outcome.detail or outcome.result.value}"
        finally:
            assoc.stop()
            transport.stop()

    async def _verify_wep_key(
        self, iface, array, ap: AccessPoint, key_hex: str, our_mac: bytes
    ) -> Tuple[bool, str]:
        try:
            key_bytes = bytes.fromhex(key_hex)
        except ValueError:
            key_bytes = key_hex.encode("ascii")

        def _is_valid_wep(p) -> bool:
            if not (isinstance(p, WepDataPacket) and p.bssid == ap.bssid.lower() and p.iv and p.cipher):
                return False
            if len(p.cipher) < 4:
                return False
            ks = rc4_keystream(p.iv + key_bytes, len(p.cipher))
            plain = bytes(c ^ k for c, k in zip(p.cipher, ks))
            return icv(plain[:-4]) == plain[-4:]

        passive = await array.next_frame(_is_valid_wep, timeout=0.5)
        if passive is not None:
            return True, "WEP Key still works"

        assoc = Association(iface, ap.bssid, ap.ssid or "", ap.channel, our_mac=our_mac)
        assoc.start()
        try:
            if not await assoc.associate(attempts=2):
                return False, f"Association failed: {assoc.fail_reason or 'no response'}"
        finally:
            assoc.stop()

        pt = arp_request_plaintext(
            sender_mac=our_mac, sender_ip=b"\xc0\xa8\x01\xfe", target_ip=b"\xc0\xa8\x01\x01"
        )
        iv = os.urandom(3)
        ks = rc4_keystream(iv + key_bytes, len(pt) + 4)
        body = iv + b"\x00" + wep_encrypt(ks, pt)
        hdr = mac_header(b"\x08\x41", b"\xff\xff\xff\xff\xff\xff", our_mac, str_to_mac(ap.bssid))
        await iface.send_no_wait(hdr + body)

        relayed = await array.next_frame(_is_valid_wep, timeout=1.5)
        if relayed is not None:
            return True, "WEP Key still works"
        return False, "WEP Key failed: unconfirmed by AP"
