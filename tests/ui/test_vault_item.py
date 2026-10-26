import time
from unittest.mock import MagicMock

from wifit3.crack.hc22000_format import parse_hc22000
from wifit3.models import CaptureType, PersistedCapture
from wifit3.persist.crack_state import CrackState, Hashline, Key, KeyKind, PasswordStatus
from wifit3.ui.screens.vault_item import VaultItemView, _KeyRow, hashline_groups, key_text, when

_LINE = "WPA*02*" + "0" * 32 + "*aabbccddeeff*{sta}*486f6d65*" + "a" * 64 + "*" + "00" * 99 + "*{pair}"


def _hashline(captured: int, sta: str = "112233445566", pair: str = "02") -> Hashline:
    raw = _LINE.format(sta=sta, pair=pair) + str(captured)[-2:].rjust(2, "0")
    line = parse_hc22000(_LINE.format(sta=sta, pair=pair))
    return Hashline(raw, raw, line, "Home", (captured,))


def _key(kind: KeyKind, value: str) -> Key:
    capture = PersistedCapture(type=CaptureType.WPA_PSK, timestamp=1, path="x.txt",
                               bssid="aa:bb:cc:dd:ee:ff", value=value)
    return Key(kind, value, capture, frozenset(), ())


def test_when_says_today_and_drops_the_time_for_another_year():
    now = int(time.time())
    assert when(now).startswith("today ")
    assert when(0) == "no date"
    assert when(now - 2 * 366 * 86400)[-4:].isdigit()


def test_key_text_shows_a_printable_wep_key_as_ascii_and_an_empty_pin_by_label():
    assert key_text(_key(KeyKind.WEP, "6162636465")) == "abcde"
    assert key_text(_key(KeyKind.WEP, "00ff00ff00")) == "00ff00ff00"
    assert key_text(_key(KeyKind.WPS, "")) != ""
    assert key_text(_key(KeyKind.PSK, "hunter22")) == "hunter22"


def test_hashline_groups_join_runs_from_one_minute_pair_and_client():
    base = 1_700_000_040
    lines = (_hashline(base + 10), _hashline(base + 5), _hashline(base, sta="112233445577"),
             _hashline(base, pair="00"))
    assert [len(group) for group in hashline_groups(lines)] == [2, 1, 1]


def test_key_row_cancel_verification():
    state = CrackState("aa:bb:cc:dd:ee:ff", (), (), (), PasswordStatus.NOT_CRACKED, None, None)
    row = _KeyRow(_key(KeyKind.PSK, "x"), state)
    task = MagicMock()
    task.done.return_value = False
    row._verify_task = task

    row.cancel_verification()
    task.cancel.assert_called_once()
    assert row._verify_task is None


def test_vault_item_view_cancel_verification():
    view = VaultItemView()
    panel = MagicMock()
    view.query = MagicMock(return_value=[panel])

    view.cancel_verification()
    panel.cancel_verification.assert_called_once()
