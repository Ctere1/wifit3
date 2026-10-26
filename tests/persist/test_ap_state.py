"""Tests for one AP's keys, hashlines, SSIDs and password status, across its SSID files."""
from __future__ import annotations

import time
from pathlib import Path

from wifit3.crack.hc22000_format import hashline_id, parse_hc22000
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
from wifit3.persist.meta import update_meta
from wifit3.persist.pcap import write_pcap

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


def _hashline(raw: str, *captured: int) -> DatedHashline:
    return DatedHashline(hashline_id(raw), raw, parse_hc22000(raw), captured)


def _key(*hashlines: DatedHashline, value: str = "hashcat!", capture_type: CaptureType = CaptureType.WPA_PSK,
         source_type: CaptureType = CaptureType.WPA_PSK, saved_at: int = 1,
         verifications: tuple[LiveVerification, ...] = ()) -> Key:
    source = PersistedCapture(type=source_type, timestamp=saved_at, path="x.txt", bssid=_BSSID,
                              value=value, ssid=_SSID)
    return Key(capture_type, value, (source,), frozenset(h.id for h in hashlines), verifications)


def test_no_key_is_not_cracked():
    assert password_status([_hashline(_EAPOL_LINE, 10)], []) == (PasswordStatus.NOT_CRACKED, None)


def test_only_a_wps_pin_is_not_cracked():
    pin = _key(value="12345670", capture_type=CaptureType.WPS_PIN, source_type=CaptureType.WPS_PIN)
    assert password_status([], [pin]) == (PasswordStatus.NOT_CRACKED, None)


def test_a_key_matching_the_newest_authorized_hashline_is_current():
    newest = _hashline(_EAPOL_LINE, 20)
    key = _key(newest)
    assert password_status([newest, _hashline(_OTHER_LINE, 10)], [key]) == (PasswordStatus.CURRENT, key)


def test_a_newer_authorized_hashline_no_key_matches_is_stale():
    key = _key(old := _hashline(_EAPOL_LINE, 10))
    assert password_status([_hashline(_OTHER_LINE, 20), old], [key]) == (PasswordStatus.STALE, key)


def test_stale_names_the_key_that_matched_last_not_the_first_listed():
    matched = _key(old := _hashline(_EAPOL_LINE, 10))
    unmatched_older = _key(value="guess", saved_at=5)
    status = password_status([_hashline(_OTHER_LINE, 20), old], [unmatched_older, matched])
    assert status == (PasswordStatus.STALE, matched)


def test_a_key_cracked_late_from_an_old_capture_is_still_stale():
    late = _key(old := _hashline(_EAPOL_LINE, 10), saved_at=30)
    assert password_status([_hashline(_OTHER_LINE, 20), old], [late]) == (PasswordStatus.STALE, late)


def test_a_key_saved_after_the_unmatched_capture_is_not_verified():
    old_key = _key(old := _hashline(_EAPOL_LINE, 10))
    added = _key(value="newpass", saved_at=30)
    status = password_status([_hashline(_OTHER_LINE, 20), old], [added, old_key])
    assert status == (PasswordStatus.NOT_VERIFIED, added)


def test_a_newer_challenge_hashline_does_not_make_it_stale():
    key = _key(old := _hashline(_EAPOL_LINE, 10))
    status, _ = password_status([_hashline(_OTHER_LINE[:-2] + "80", 20), old], [key])
    assert status is PasswordStatus.CURRENT


def test_only_challenge_matches_is_not_verified():
    key = _key(challenge := _hashline(_CHALLENGE_LINE, 10))
    assert password_status([challenge], [key]) == (PasswordStatus.NOT_VERIFIED, key)


def test_a_correct_live_verification_after_a_change_makes_the_new_key_current():
    old_key = _key(old := _hashline(_EAPOL_LINE, 10))
    new_key = _key(value="newpass", saved_at=25, verifications=(LiveVerification(30, True),))
    status = password_status([_hashline(_OTHER_LINE, 20), old], [new_key, old_key])
    assert status == (PasswordStatus.CURRENT, new_key)


def test_a_rejected_live_verification_is_not_judged():
    key = _key(newest := _hashline(_EAPOL_LINE, 10), verifications=(LiveVerification(20, False),))
    assert password_status([newest], [key]) == (PasswordStatus.CURRENT, key)


def test_a_key_recovered_from_the_ap_is_current_without_hashlines():
    wep = _key(value="6162636465", capture_type=CaptureType.WEP, source_type=CaptureType.WEP)
    assert password_status([], [wep]) == (PasswordStatus.CURRENT, wep)


def test_a_rejected_wps_pin_does_not_touch_the_psk():
    psk = _key(source_type=CaptureType.WPS_PIN, saved_at=10)
    pin = _key(value="12345670", capture_type=CaptureType.WPS_PIN, source_type=CaptureType.WPS_PIN,
               saved_at=10, verifications=(LiveVerification(20, False),))
    assert password_status([], [pin, psk]) == (PasswordStatus.CURRENT, psk)


def test_undated_authorized_evidence_is_older_than_any_dated():
    key = _key(dated := _hashline(_EAPOL_LINE, 10))
    assert password_status([dated, _hashline(_OTHER_LINE)], [key]) == (PasswordStatus.CURRENT, key)


def _write_aggregate(ssid: str, *lines: str) -> Path:
    from wifit3.persist.config import Config
    path = Path(Config.captures_dir) / f"{ssid}_{_DASHED}.hc22000"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _write_psk(ssid: str, epoch: int, psk: str) -> None:
    from wifit3.persist.config import Config
    (Path(Config.captures_dir) / f"{ssid}_{_DASHED}_{epoch}_wpa_psk.txt").write_text(
        f"SSID: {ssid}\nBSSID: {_BSSID}\nPSK: {psk}\n", encoding="utf-8")


def _date_hashline(ssid: str, raw: str, epoch: int) -> None:
    update_meta(ssid, _BSSID, hashlines={hashline_id(raw): {"captured": [epoch]}})


def _state():
    return load_ap_state(_BSSID, load_capture_index()[_BSSID])


def test_load_matches_saved_psks_against_every_ssid_file(tmp_path):
    _write_aggregate("Old", _OLD_SSID_LINE)
    _write_aggregate(_SSID, _EAPOL_LINE)
    _write_psk(_SSID, 1700000000, "hashcat!")
    _date_hashline("Old", _OLD_SSID_LINE, 1600000000)
    _date_hashline(_SSID, _EAPOL_LINE, 1700000000)

    state = _state()
    assert state.status is PasswordStatus.CURRENT
    assert state.status_key.value == "hashcat!"
    assert [h.raw for h in state.uncracked] == [_OLD_SSID_LINE]
    assert [(s.ssid, s.first_seen) for s in state.ssids] == [(_SSID, 1700000000), ("Old", 1600000000)]
    assert state.hashline_capture.path.endswith(f"{_SSID}_{_DASHED}.hc22000")


def test_load_lists_undated_hashlines_last(tmp_path):
    _write_aggregate(_SSID, _OTHER_LINE, _EAPOL_LINE)
    _date_hashline(_SSID, _EAPOL_LINE, 1700000000)
    assert [(h.raw, h.first_captured) for h in _state().hashlines] == [
        (_EAPOL_LINE, 1700000000), (_OTHER_LINE, None)]


def test_load_dates_a_hashline_from_the_pcap_frame_carrying_its_mic(tmp_path):
    _write_aggregate(_SSID, _EAPOL_LINE)
    write_pcap(tmp_path / f"{_SSID}_{_DASHED}_1700000005_handshake.pcap",
               [(b"\x88\x02" + bytes.fromhex(_MIC), 1700000003.5)])
    assert _state().hashlines[0].captured == (1700000003,)


def test_record_hashlines_captured_dates_them_now_and_replaces_a_bad_record(tmp_path):
    _write_aggregate(_SSID, _EAPOL_LINE, _OTHER_LINE)
    update_meta(_SSID, _BSSID, hashlines={hashline_id(_EAPOL_LINE): "not a record"})
    before = int(time.time())
    record_hashlines_captured(_SSID, _BSSID, [_EAPOL_LINE, _OTHER_LINE])
    assert all(before <= h.first_captured <= int(time.time()) for h in _state().hashlines)


def test_a_recorded_live_verification_is_read_back(tmp_path):
    _write_aggregate(_SSID, _CHALLENGE_LINE)
    _write_psk(_SSID, 1700000000, "hashcat!")
    assert _state().status is PasswordStatus.NOT_VERIFIED
    record_live_verification(_state().keys[0], correct=True)
    state = _state()
    assert state.status is PasswordStatus.CURRENT
    assert [v.correct for v in state.keys[0].live_verifications] == [True]


def test_a_live_verification_of_an_unknown_kind_is_ignored(tmp_path):
    _write_psk(_SSID, 1700000000, "hashcat!")
    update_meta(_SSID, _BSSID, live_verifications=[
        {"kind": "PSK", "key": "hashcat!", "at": 1700000001, "correct": True},
        {"kind": "WPA_PSK", "key": "hashcat!", "at": 1700000002, "correct": True}])
    assert [v.at for v in _state().keys[0].live_verifications] == [1700000002]


def test_a_wps_pin_capture_gives_a_current_psk_key_and_a_pin_key(tmp_path):
    capture = PersistedCapture(type=CaptureType.WPS_PIN, timestamp=1, path="x.txt", bssid=_BSSID,
                               value="hashcat!", pin="12345670", ssid=_SSID)
    state = load_ap_state(_BSSID, [capture])
    assert sorted((k.capture_type, k.value) for k in state.keys) == [
        (CaptureType.WPA_PSK, "hashcat!"), (CaptureType.WPS_PIN, "12345670")]
    assert (state.status, state.status_key.capture_type) == (PasswordStatus.CURRENT, CaptureType.WPA_PSK)


def test_a_psk_saved_in_two_files_keeps_both_sources(tmp_path):
    wps = PersistedCapture(type=CaptureType.WPS_PBC, timestamp=1, path="a.txt", bssid=_BSSID,
                           value="hashcat!", ssid=_SSID)
    cracked = PersistedCapture(type=CaptureType.WPA_PSK, timestamp=2, path="b.txt", bssid=_BSSID,
                               value="hashcat!", ssid=_SSID)
    [key] = load_ap_state(_BSSID, [wps, cracked]).keys
    assert key.sources == (cracked, wps)
    assert key.recovered_from_access_point_at == 1
