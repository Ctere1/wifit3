"""Tests for LiveKeyVerifier."""
from unittest.mock import AsyncMock, MagicMock

from wifit3.campaigns.campaign import Campaign
from wifit3.campaigns.live_check import LiveKeyVerifier, VerifyStatus
from wifit3.campaigns.wps.registrar import AttemptOutcome, PinResult
from wifit3.dot11.packet import EapolPacket, WepDataPacket
from wifit3.dot11.wep.crypto import icv
from wifit3.crack.wep import rc4_keystream
from wifit3.models import AccessPoint, CaptureType, PersistedCapture


def _make_capture(cap_type: CaptureType, bssid: str, value: str = "", pin: str = "") -> PersistedCapture:
    return PersistedCapture(
        type=cap_type,
        timestamp=1000,
        path="/tmp/cap",
        bssid=bssid,
        value=value,
        pin=pin,
        ssid="TestNet",
    )


def _make_ap(bssid: str, channel: int = 6) -> AccessPoint:
    return AccessPoint(bssid=bssid, ssid="TestNet", channel=channel)


async def test_verify_blocked_when_campaign_active():
    verifier = LiveKeyVerifier()
    cap = _make_capture(CaptureType.WPA_PSK, "00:11:22:33:44:55", value="secret123")
    mock_camp = MagicMock()
    mock_camp.key = "deauth"

    orig_active = Campaign.active
    Campaign.active = mock_camp
    try:
        res = await verifier.verify_credential(cap, MagicMock())
        assert res.status == VerifyStatus.ERROR
        assert "deauth campaign is active" in res.body
    finally:
        Campaign.active = orig_active


async def test_verify_no_members():
    verifier = LiveKeyVerifier()
    cap = _make_capture(CaptureType.WPA_PSK, "00:11:22:33:44:55", value="secret123")
    array = MagicMock()
    array.members = []

    res = await verifier.verify_credential(cap, array)
    assert res.status == VerifyStatus.ERROR
    assert "No wireless adapter available" in res.body


async def test_verify_ap_not_in_range():
    verifier = LiveKeyVerifier()
    cap = _make_capture(CaptureType.WPA_PSK, "00:11:22:33:44:55", value="secret123")
    array = MagicMock()
    array.members = [MagicMock()]
    array.access_points = {}

    res = await verifier.verify_credential(cap, array)
    assert res.status == VerifyStatus.ERROR
    assert "not in range" in res.body


async def test_verify_wpa_psk_success(monkeypatch):
    verifier = LiveKeyVerifier()
    bssid = "00:11:22:33:44:55"
    cap = _make_capture(CaptureType.WPA_PSK, bssid, value="password")
    ap = _make_ap(bssid, channel=1)

    iface = MagicMock()
    iface.set_channel = AsyncMock()
    iface.set_fake_mac = AsyncMock()
    iface.clear_fake_mac = AsyncMock()
    iface.send_no_wait = AsyncMock()

    class FakeClaim:
        async def __aenter__(self):
            return iface
        async def __aexit__(self, *args):
            pass

    array = MagicMock()
    array.members = [iface]
    array.access_points = {bssid.lower(): ap}
    array.select_iface.return_value = iface
    array.claim.return_value = FakeClaim()
    array.register_own_mac.return_value = "00:aa:bb:cc:dd:ee"
    array.unregister_own_mac = MagicMock()

    m1_pkt = EapolPacket(
        type="eapol",
        type_id=2,
        subtype_id=0,
        bssid=bssid.lower(),
        source=bssid.lower(),
        dest="00:aa:bb:cc:dd:ee",
        to_ds=False,
        from_ds=True,
        rssi=-50,
        raw=b"\x00" * 30,
        msg_num=1,
        nonce=b"\x11" * 32,
        replay_counter=b"\x00\x00\x00\x00\x00\x00\x00\x01",
    )
    m3_pkt = EapolPacket(
        type="eapol",
        type_id=2,
        subtype_id=0,
        bssid=bssid.lower(),
        source=bssid.lower(),
        dest="00:aa:bb:cc:dd:ee",
        to_ds=False,
        from_ds=True,
        rssi=-50,
        raw=b"\x00" * 30,
        msg_num=3,
    )

    array.next_frame = AsyncMock(side_effect=[m1_pkt, m3_pkt])

    monkeypatch.setattr("wifit3.campaigns.live_check.Association.associate", AsyncMock(return_value=True))

    res = await verifier.verify_credential(cap, array)
    assert res.status == VerifyStatus.SUCCESS
    assert res.title == "PSK verified for TestNet"
    assert 'Key "password" still works' in res.body


async def test_verify_wpa_psk_no_m3(monkeypatch):
    verifier = LiveKeyVerifier()
    bssid = "00:11:22:33:44:55"
    cap = _make_capture(CaptureType.WPA_PSK, bssid, value="wrongpassword")
    ap = _make_ap(bssid, channel=1)

    iface = MagicMock()
    iface.set_channel = AsyncMock()
    iface.set_fake_mac = AsyncMock()
    iface.clear_fake_mac = AsyncMock()
    iface.send_no_wait = AsyncMock()

    class FakeClaim:
        async def __aenter__(self):
            return iface
        async def __aexit__(self, *args):
            pass

    array = MagicMock()
    array.members = [iface]
    array.access_points = {bssid.lower(): ap}
    array.select_iface.return_value = iface
    array.claim.return_value = FakeClaim()
    array.register_own_mac.return_value = "00:aa:bb:cc:dd:ee"
    array.unregister_own_mac = MagicMock()

    m1_pkt = EapolPacket(
        type="eapol",
        type_id=2,
        subtype_id=0,
        bssid=bssid.lower(),
        source=bssid.lower(),
        dest="00:aa:bb:cc:dd:ee",
        to_ds=False,
        from_ds=True,
        rssi=-50,
        raw=b"\x00" * 30,
        msg_num=1,
        nonce=b"\x11" * 32,
        replay_counter=b"\x00\x00\x00\x00\x00\x00\x00\x01",
    )

    array.next_frame = AsyncMock(side_effect=[m1_pkt, None])

    monkeypatch.setattr("wifit3.campaigns.live_check.Association.associate", AsyncMock(return_value=True))

    res = await verifier.verify_credential(cap, array)
    assert res.status == VerifyStatus.INCORRECT
    assert 'Key "wrongpassword" is incorrect (no M3)' in res.body


async def test_verify_wps_pin_success(monkeypatch):
    verifier = LiveKeyVerifier()
    bssid = "00:11:22:33:44:55"
    cap = _make_capture(CaptureType.WPS_PIN, bssid, pin="12345670")
    ap = _make_ap(bssid, channel=1)

    iface = MagicMock()
    iface.set_channel = AsyncMock()
    iface.set_fake_mac = AsyncMock()
    iface.clear_fake_mac = AsyncMock()
    iface.send_no_wait = AsyncMock()

    class FakeClaim:
        async def __aenter__(self):
            return iface
        async def __aexit__(self, *args):
            pass

    array = MagicMock()
    array.members = [iface]
    array.access_points = {bssid.lower(): ap}
    array.select_iface.return_value = iface
    array.claim.return_value = FakeClaim()
    array.register_own_mac.return_value = "00:aa:bb:cc:dd:ee"
    array.unregister_own_mac = MagicMock()

    monkeypatch.setattr("wifit3.campaigns.live_check.Association.associate", AsyncMock(return_value=True))
    monkeypatch.setattr(
        "wifit3.campaigns.live_check.WpsRegistrar.try_pin",
        AsyncMock(return_value=AttemptOutcome(PinResult.SUCCESS, pin="12345670")),
    )

    res = await verifier.verify_credential(cap, array)
    assert res.status == VerifyStatus.SUCCESS
    assert 'PIN "12345670" still works' in res.body


async def test_verify_wps_pin_invalid(monkeypatch):
    verifier = LiveKeyVerifier()
    bssid = "00:11:22:33:44:55"
    cap = _make_capture(CaptureType.WPS_PIN, bssid, pin="12345670")
    ap = _make_ap(bssid, channel=1)

    iface = MagicMock()
    iface.set_channel = AsyncMock()
    iface.set_fake_mac = AsyncMock()
    iface.clear_fake_mac = AsyncMock()
    iface.send_no_wait = AsyncMock()

    class FakeClaim:
        async def __aenter__(self):
            return iface
        async def __aexit__(self, *args):
            pass

    array = MagicMock()
    array.members = [iface]
    array.access_points = {bssid.lower(): ap}
    array.select_iface.return_value = iface
    array.claim.return_value = FakeClaim()
    array.register_own_mac.return_value = "00:aa:bb:cc:dd:ee"
    array.unregister_own_mac = MagicMock()

    monkeypatch.setattr("wifit3.campaigns.live_check.Association.associate", AsyncMock(return_value=True))
    monkeypatch.setattr(
        "wifit3.campaigns.live_check.WpsRegistrar.try_pin",
        AsyncMock(return_value=AttemptOutcome(PinResult.FIRST_HALF_WRONG, pin="12345670")),
    )

    res = await verifier.verify_credential(cap, array)
    assert res.status == VerifyStatus.INCORRECT
    assert 'PIN "12345670" is incorrect' in res.body


async def test_verify_wep_key_passive(monkeypatch):
    verifier = LiveKeyVerifier()
    bssid = "00:11:22:33:44:55"
    hex_key = "1234567890"
    cap = _make_capture(CaptureType.WEP, bssid, value=hex_key)
    ap = _make_ap(bssid, channel=1)

    iface = MagicMock()
    iface.set_channel = AsyncMock()
    iface.set_fake_mac = AsyncMock()
    iface.clear_fake_mac = AsyncMock()
    iface.send_no_wait = AsyncMock()

    class FakeClaim:
        async def __aenter__(self):
            return iface
        async def __aexit__(self, *args):
            pass

    array = MagicMock()
    array.members = [iface]
    array.access_points = {bssid.lower(): ap}
    array.select_iface.return_value = iface
    array.claim.return_value = FakeClaim()
    array.register_own_mac.return_value = "00:aa:bb:cc:dd:ee"
    array.unregister_own_mac = MagicMock()

    key_bytes = bytes.fromhex(hex_key)
    iv_bytes = b"\x01\x02\x03"
    plain = b"\xaa\xaa\x03\x00\x00\x00" + b"\x08\x06" + b"arp-body"
    blob = plain + icv(plain)
    ks = rc4_keystream(iv_bytes + key_bytes, len(blob))
    cipher = bytes(b ^ k for b, k in zip(blob, ks))

    wep_pkt = WepDataPacket(
        type="wep_data",
        type_id=2,
        subtype_id=0,
        bssid=bssid.lower(),
        source=bssid.lower(),
        dest="ff:ff:ff:ff:ff:ff",
        to_ds=False,
        from_ds=True,
        rssi=-50,
        raw=b"\x00" * 30,
        iv=iv_bytes,
        cipher=cipher,
    )

    async def _next_frame(predicate, timeout=0.0):
        return wep_pkt if predicate(wep_pkt) else None

    array.next_frame = _next_frame

    res = await verifier.verify_credential(cap, array)
    assert res.status == VerifyStatus.SUCCESS
    assert f'Key "{hex_key}" still works' in res.body
