"""Active decloak: candidate generation, the probe frame builder, and the association
sweep's adherence to the 802.11 state machine."""
from __future__ import annotations

import types
from unittest.mock import MagicMock

from wifit3.campaigns.decloak import (
    SIBLING_SUFFIXES,
    DecloakAttack,
    candidates_from_sibling,
    named_sibling_ssid,
)
from wifit3.models import AccessPoint
from wifit3.dot11.parser import WlanFrameParser
from wifit3.dot11.probe import probe_req

_BSSID = "aa:bb:cc:dd:ee:ff"


def _attack(candidates, *, target=None, iface=None):
    array = MagicMock()
    array.access_points = {}
    return DecloakAttack(array, target or AccessPoint(bssid=_BSSID, channel=6),
                         iface or MagicMock(), candidates)


# ----- candidate generation ----------------------------------------------------


def test_no_sibling_ssid_yields_no_candidates():
    assert candidates_from_sibling("") == []


def test_candidates_dedup_and_keep_suffix_order():
    out = candidates_from_sibling("Foo")
    assert out[0] == "Foo"                      # empty suffix: the same-SSID dual-band case
    assert len(out) == len(set(out))
    assert out.index("Foo-Guest") < out.index("Foo-EXT")
    assert len(out) <= len(SIBLING_SUFFIXES)


def test_candidates_strip_trailing_whitespace():
    out = candidates_from_sibling("TestSSID 2.4")
    assert "TestSSID 2.4 Guest" in out
    assert "TestSSID 2.4-Guest" in out


def test_candidates_drop_names_over_32_octets():
    out = candidates_from_sibling("X" * 31)
    assert "X" * 31 in out                      # the bare sibling still fits
    assert all(len(c.encode("utf-8")) <= 32 for c in out)
    assert ("X" * 31) + "-Guest" not in out


def test_named_sibling_prefers_the_most_beaconed():
    array = MagicMock()
    array.access_points = {
        "11:11:11:11:11:11": types.SimpleNamespace(ssid="Quiet", beacons=3),
        "22:22:22:22:22:22": types.SimpleNamespace(ssid="Loud", beacons=90),
        "33:33:33:33:33:33": types.SimpleNamespace(ssid=None, beacons=500),
    }
    hidden = AccessPoint(bssid=_BSSID, channel=6,
                         siblings=["11:11:11:11:11:11", "22:22:22:22:22:22",
                                   "33:33:33:33:33:33"])
    assert named_sibling_ssid(array, hidden) == "Loud"


def test_named_sibling_is_empty_without_siblings():
    assert named_sibling_ssid(MagicMock(), AccessPoint(bssid=_BSSID, channel=6)) == ""


# ----- frame building ----------------------------------------------------------


def test_probe_req_round_trips_with_the_candidate_ssid():
    """Feed a frame we built back through the parser the receive path uses: the wire
    format is well formed and the SSID we asked for is what an AP would see."""
    attack = _attack(["Foo-Guest"])
    frame = probe_req(attack.bssid_bytes, attack.source_mac, "Foo-Guest", channel=6)
    parsed = WlanFrameParser.parse_80211_frame(frame, rssi=-30)

    assert parsed is not None
    assert parsed.type == "probe_req"
    assert parsed.bssid == _BSSID
    assert parsed.dest == _BSSID
    assert parsed.ssid == "Foo-Guest"


def test_probe_req_round_trips_a_full_length_ssid():
    attack = _attack(["X" * 32], target=AccessPoint(bssid="11:22:33:44:55:66", channel=44))
    frame = probe_req(attack.bssid_bytes, attack.source_mac, "X" * 32, channel=44)
    parsed = WlanFrameParser.parse_80211_frame(frame, rssi=-30)
    assert parsed is not None and parsed.ssid == "X" * 32


def test_attack_registers_its_forged_mac():
    """The source MAC is registered so the EAPOL/handshake/client paths never treat our
    forged STA as a real one."""
    attack = _attack(["Foo"])
    attack.array.register_forged_mac.assert_called_once_with(attack.source_mac)


# ----- association sweep -------------------------------------------------------


class _FakeAssociation:
    """Records the auth/assoc calls a sweep makes, and replays scripted verdicts."""

    def __init__(self, verdicts: dict, *, deauth_after: str = ""):
        self._verdicts = verdicts
        self._deauth_after = deauth_after
        self.state = 2                          # _claim_each's caller authenticates first
        self.calls: list[str] = []

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    async def authenticate(self) -> bool:
        self.calls.append("auth")
        self.state = 2
        return True

    async def associate_as(self, ssid: str):
        self.calls.append(f"assoc:{ssid}")
        status = self._verdicts.get(ssid)
        if status == 0:
            self.state = 3
        elif ssid == self._deauth_after:
            self.state = 1                      # the AP deauthed us: back to state 1
        return status


async def test_sweep_authenticates_once_for_every_candidate():
    attack = _attack(["A", "B", "C"])
    association = _FakeAssociation({"C": 0})
    found = await attack._claim_each(association, ["A", "B", "C"], lambda: False)

    assert found == "C"
    assert association.calls == ["assoc:A", "assoc:B", "assoc:C"]   # no re-auth
    attack.array.confirm_decloak.assert_called_once_with(_BSSID, "C", "assoc")


async def test_sweep_reauthenticates_only_after_a_deauth():
    attack = _attack(["A", "B"])
    association = _FakeAssociation({}, deauth_after="A")
    found = await attack._claim_each(association, ["A", "B"], lambda: False)

    assert found is None
    assert association.calls == ["assoc:A", "auth", "assoc:B"]


async def test_sweep_stops_when_asked():
    attack = _attack(["A", "B"])
    association = _FakeAssociation({"B": 0})
    assert await attack._claim_each(association, ["A", "B"], lambda: True) is None
    assert association.calls == []
