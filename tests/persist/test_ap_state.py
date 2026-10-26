"""Tests for one AP's keys, hashlines, SSIDs and password status, across its SSID files."""
from __future__ import annotations

from pathlib import Path

from wifit3.crack.hc22000_format import parse_hc22000
from wifit3.models import CaptureType, PersistedCapture
from wifit3.persist.capture_history import load_capture_index
from wifit3.persist.ap_state import (
    DatedHashline,
    Key,
    LiveVerification,
    PasswordStatus,
    load_ap_state,
    password_status,
    record_hashlines_captured,
    record_live_verification,
)
from wifit3.persist.pcap import write_pcap
from wifit3.vault.exhaustion import hashline_id

# hashcat wiki example_hashes, mode 22000 (password "hashcat!"); message pair a2 = M2+M3.
_BSSID = "64:66:b3:8e:c3:fc"
_DASHED = "64-66-b3-8e-c3-fc"
_MIC = "024022795224bffca545276c3762686f"
_EAPOL_LINE = (
    f"WPA*02*{_MIC}*6466b38ec3fc*225edc49b7aa"
    "*54502d4c494e4b5f484153484341545f54455354"
    "*10e3be3b005a629e89de088d6a2fdc489db83ad4764f2d186b9cde15446e972e"
    "*0103007502010a0000000000000000000148ce2ccba9c1fda130ff2fbbfb4fd3b063d1a93920b0f7df54a5cb"
    "f787b16171000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000001630140100000fac040100000fac040100000fac028000*a2")
_CHALLENGE_LINE = _EAPOL_LINE[:-2] + "80"       # same MIC, flagged M1+M2
_OTHER_LINE = _EAPOL_LINE.replace(_MIC, "f" * 32)
_SSID = "TP-LINK_HASHCAT_TEST"
_OLD_SSID_LINE = _OTHER_LINE.replace("54502d4c494e4b5f484153484341545f54455354", b"Old".hex())


def _hashline(raw: str, captured: int) -> DatedHashline:
    return DatedHashline(hashline_id(raw), raw, parse_hc22000(raw), _SSID, (captured,))


def _key(*hashlines: DatedHashline, capture_type=CaptureType.WPA_PSK, timestamp=1,
         verifications: tuple[LiveVerification, ...] = ()) -> Key:
    capture = PersistedCapture(type=capture_type, timestamp=timestamp, path="x.txt", bssid=_BSSID,
                               value="hashcat!", ssid=_SSID)
    return Key(capture_type, "hashcat!", capture, frozenset(h.id for h in hashlines), verifications)


def test_no_key_is_not_cracked():
    assert password_status([_hashline(_EAPOL_LINE, 10)], []) == (PasswordStatus.NOT_CRACKED, None)


def test_a_key_matching_the_newest_authorized_hashline_is_current():
    newest = _hashline(_EAPOL_LINE, 20)
    key = _key(newest)
    assert password_status([newest, _hashline(_OTHER_LINE, 10)], [key]) == (PasswordStatus.CURRENT, key)


def test_a_newer_authorized_hashline_no_key_matches_is_stale():
    key = _key(old := _hashline(_EAPOL_LINE, 10))
    assert password_status([_hashline(_OTHER_LINE, 20), old], [key]) == (PasswordStatus.STALE, key)


def test_a_newer_challenge_hashline_does_not_make_it_stale():
    key = _key(old := _hashline(_EAPOL_LINE, 10))
    status, _ = password_status([_hashline(_OTHER_LINE[:-2] + "80", 20), old], [key])
    assert status is PasswordStatus.CURRENT


def test_only_challenge_matches_is_not_verified():
    key = _key(challenge := _hashline(_CHALLENGE_LINE, 10))
    assert password_status([challenge], [key]) == (PasswordStatus.NOT_VERIFIED, key)


def test_a_newer_live_verification_decides():
    challenge = _hashline(_CHALLENGE_LINE, 10)
    correct = _key(challenge, verifications=(LiveVerification(20, True),))
    assert password_status([challenge], [correct])[0] is PasswordStatus.CURRENT
    rejected = _key(_hashline(_EAPOL_LINE, 10), verifications=(LiveVerification(20, False),))
    assert password_status([_hashline(_EAPOL_LINE, 10)], [rejected])[0] is PasswordStatus.STALE


def test_a_key_recovered_from_the_ap_is_current_without_hashlines():
    wep = _key(capture_type=CaptureType.WEP)
    assert password_status([], [wep]) == (PasswordStatus.CURRENT, wep)


def _write_aggregate(ssid: str, *lines: str) -> Path:
    from wifit3.persist.config import Config
    path = Path(Config.captures_dir) / f"{ssid}_{_DASHED}.hc22000"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _write_psk(ssid: str, epoch: int, psk: str) -> None:
    from wifit3.persist.config import Config
    (Path(Config.captures_dir) / f"{ssid}_{_DASHED}_{epoch}_wpa_psk.txt").write_text(
        f"SSID: {ssid}\nBSSID: {_BSSID}\nPSK: {psk}\n", encoding="utf-8")


def _state():
    return load_ap_state(_BSSID, load_capture_index()[_BSSID])


def test_load_matches_saved_psks_against_every_ssid_file(tmp_path):
    _write_aggregate("Old", _OLD_SSID_LINE)
    _write_aggregate(_SSID, _EAPOL_LINE)
    _write_psk(_SSID, 1700000000, "hashcat!")
    record_hashlines_captured("Old", _BSSID, [_OLD_SSID_LINE], epoch=1600000000)
    record_hashlines_captured(_SSID, _BSSID, [_EAPOL_LINE], epoch=1700000000)

    state = _state()
    assert state.status is PasswordStatus.CURRENT
    assert state.status_key.value == "hashcat!"
    assert [h.raw for h in state.uncracked] == [_OLD_SSID_LINE]
    assert [(s.ssid, s.first_seen) for s in state.ssids] == [(_SSID, 1700000000), ("Old", 1600000000)]
    assert state.hashline_capture.path.endswith(f"{_SSID}_{_DASHED}.hc22000")


def test_load_dates_a_hashline_from_the_pcap_frame_carrying_its_mic(tmp_path):
    _write_aggregate(_SSID, _EAPOL_LINE)
    write_pcap(tmp_path / f"{_SSID}_{_DASHED}_1700000005_handshake.pcap",
               [(b"\x88\x02" + bytes.fromhex(_MIC), 1700000003.5)])
    assert _state().hashlines[0].captured == (1700000003,)


def test_a_recorded_live_verification_is_read_back(tmp_path):
    _write_aggregate(_SSID, _CHALLENGE_LINE)
    _write_psk(_SSID, 1700000000, "hashcat!")
    assert _state().status is PasswordStatus.NOT_VERIFIED
    record_live_verification(_state().keys[0], correct=True)
    state = _state()
    assert state.status is PasswordStatus.CURRENT
    assert [v.correct for v in state.keys[0].live_verifications] == [True]


def test_pair_labels_name_both_messages():
    assert [_hashline(raw, 1).pair_label for raw in (_EAPOL_LINE, _CHALLENGE_LINE)] == ["M2+M3", "M1+M2"]
    pmkid = f"WPA*01*{_MIC}*6466b38ec3fc*225edc49b7aa*{_SSID.encode().hex()}***"
    assert _hashline(pmkid, 1).pair_label == "PMKID"


def test_a_wps_pin_capture_gives_a_pin_key_and_a_wpa_psk_key(tmp_path):
    capture = PersistedCapture(type=CaptureType.WPS_PIN, timestamp=1, path="x.txt", bssid=_BSSID,
                               value="hashcat!", pin="12345670", ssid=_SSID)
    keys = load_ap_state(_BSSID, [capture]).keys
    assert sorted((k.capture_type, k.value) for k in keys) == [
        (CaptureType.WPA_PSK, "hashcat!"), (CaptureType.WPS_PIN, "12345670")]
