from __future__ import annotations

import logging
import time
from collections.abc import Hashable
from dataclasses import dataclass
from itertools import groupby
from typing import Mapping, Optional

from rich.markup import escape
from textual import on, work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalGroup, VerticalScroll
from textual.content import Content
from textual.events import MouseMove, Resize
from textual.message import Message
from textual.reactive import reactive, var
from textual.widget import Widget
from textual.widgets import Button, Label, Rule, SelectionList, Static
from textual.widgets.selection_list import Selection

from wifit3.campaigns.live_check import LiveKeyVerifier, VerifyStatus
from wifit3.campaigns.pin import EMPTY_PIN_LABEL
from wifit3.models import CaptureType, PersistedCapture
from wifit3.persist.ap_state import (
    ApState,
    DatedHashline,
    Key,
    LiveVerification,
    PasswordStatus,
    epoch_sort_key,
)
from wifit3.persist.exhaustion import ExhaustedWordlist
from wifit3.ui.colors import PASSWORD_MISMATCH_COLOR
from wifit3.ui.encryption_format import wep_key_ascii
from wifit3.ui.screens.vault_breakpoints import NARROW, SHORT, TALL, TINY, WIDE
from wifit3.ui.vault.tools_ui import UI_TOOLS
from wifit3.vault.tools.base import VaultTool


logger = logging.getLogger(__name__)

_STATUS_COLOR = {
    PasswordStatus.CURRENT: "$text-success",
    PasswordStatus.NOT_VERIFIED: "$text-warning",
    PasswordStatus.STALE: PASSWORD_MISMATCH_COLOR,
    PasswordStatus.NOT_CRACKED: "$text-error",
}
_KEY_CHIP_STYLE = {
    PasswordStatus.CURRENT: "black bold on lightgreen",
    PasswordStatus.NOT_VERIFIED: "black bold on $warning",
    PasswordStatus.STALE: f"black bold on {PASSWORD_MISMATCH_COLOR}",
}
_AUTHORIZED_TOOLTIP = "[$text-success]authorized:[/] PMKID or M3/M4 (the AP accepted this password)"
_CHALLENGE_TOOLTIP = "[$text-warning]challenge:[/] No M3/M4 (could be a wrong password)"
_EXPAND_LABEL, _COLLAPSE_LABEL = "▶", "▼"
_EXPAND_TOOLTIP, _COLLAPSE_TOOLTIP = "Show captures and verifications", "Hide captures and verifications"
_VERIFY_TOOLTIP = "Connect to the live AP and verify this key"
_BUSY_TOOLTIP = "A live check is running on another AP"


@dataclass(frozen=True)
class _KeyKind:
    name: str           # in sentences: ``WPS PIN 12345670``
    badge: str          # before the value in its row, and on the status chip
    badge_color: str


_KEY_KINDS = {
    CaptureType.WPA_PSK: _KeyKind("PSK", "PSK", "$text-success"),
    CaptureType.WPS_PIN: _KeyKind("WPS PIN", "WPS", "$text-accent"),
    CaptureType.WEP: _KeyKind("WEP key", "WEP", "$text-secondary"),
}
_TOGGLE_WIDTH = 3
_BADGE_WIDTH = max(len(kind.badge) for kind in _KEY_KINDS.values())
_VALUE_COLUMN = _TOGGLE_WIDTH + _BADGE_WIDTH + 2       # a space after the badge, then the chip's own space
_LIST_INDENT = 2                                        # the UNCRACKED rows under their header

_VerifyingKey = tuple[str, tuple[CaptureType, str]]    # BSSID, Key.id
_HashlineGroup = tuple[DatedHashline, ...]


def key_description(key: Key) -> str:
    """``PSK hunter22``, ``WPS PIN 12345670``, ``WEP key abcde``."""
    return f"{_KEY_KINDS[key.type].name} {key_text(key)}"


def _status_reason(key: Key, status: PasswordStatus) -> str:
    if status is PasswordStatus.CURRENT:
        return "verified"
    if status is PasswordStatus.STALE:
        return "stale"
    if key.manual_capture_names:
        return "added, unverified"
    return "not verified yet"


def key_text(key: Key) -> str:
    """The key as the user types it: a WEP key in ASCII when printable, else hex."""
    if key.type == CaptureType.WEP:
        return wep_key_ascii(key.value) or key.value
    if key.type == CaptureType.WPS_PIN:
        return key.value or EMPTY_PIN_LABEL
    return key.value


def date_text(epoch: Optional[int]) -> str:
    """``today  19:37``, ``Oct 22 19:37``, ``Oct 22 2025``; ``no date`` for None."""
    if epoch is None:
        return "no date"
    moment, now = time.localtime(epoch), time.localtime()
    if moment.tm_year != now.tm_year:
        return time.strftime("%b %d %Y", moment)
    if moment.tm_yday == now.tm_yday:
        return time.strftime("today  %H:%M", moment)
    return time.strftime("%b %d %H:%M", moment)


def _client_text(hashline: DatedHashline) -> str:
    """Last two bytes of the client MAC, ``…aa:bb``."""
    mac_sta = hashline.line.mac_sta
    return f"…{mac_sta[-4:-2]}:{mac_sta[-2:]}"


def hashline_groups(hashlines: tuple[DatedHashline, ...]) -> list[_HashlineGroup]:
    """Runs of hashlines from the same minute, message pair, client and SSID."""
    def same(h: DatedHashline) -> tuple:
        minute = None if h.first_captured is None else h.first_captured // 60
        return minute, h.line.pair_label, h.line.mac_sta, h.line.ssid, h.line.authorized
    return [tuple(group) for _, group in groupby(hashlines, same)]


def _captures_count_markup(count: int, total: int) -> str:
    return f"[dim]({count}/{total} captures)[/]"


def _no_crackable_text(files: tuple[PersistedCapture, ...]) -> str:
    count = len(files)
    return f"{count} capture{'' if count == 1 else 's'}, none crackable ({date_text(files[0].timestamp)})"


def _selected_count_text(count: int) -> str:
    return f"{count} capture{'' if count == 1 else 's'} selected"


def _wordlists_text(count: int) -> str:
    return f"{count} wordlist{'' if count == 1 else 's'}"


def _exhausted_count_text(group: _HashlineGroup,
                          exhausted: Mapping[str, frozenset[ExhaustedWordlist]]) -> str:
    """``2 wordlists exhausted (1 on some lines)``: the wordlists that ran out on the group's lines."""
    per_line = [exhausted.get(h.id, frozenset()) for h in group]
    on_any = frozenset.union(*per_line)
    on_some = on_any - frozenset.intersection(*per_line)
    if not on_any:
        return ""
    return f"{_wordlists_text(len(on_any))} exhausted" + (f" ({len(on_some)} on some lines)" if on_some else "")


def _exhausted_names(group: _HashlineGroup, exhausted: Mapping[str, frozenset[ExhaustedWordlist]]) -> list[str]:
    wordlists = frozenset.union(frozenset(), *(exhausted.get(h.id, frozenset()) for h in group))
    return sorted(" / ".join(w.names) or "unnamed wordlist" for w in wordlists)


def _verdict_tooltip(hashline: DatedHashline) -> str:
    return _AUTHORIZED_TOOLTIP if hashline.line.authorized else _CHALLENGE_TOOLTIP


def _hashline_tooltip(group: _HashlineGroup, exhausted: Mapping[str, frozenset[ExhaustedWordlist]]) -> str:
    tooltip = _verdict_tooltip(group[0])
    names = _exhausted_names(group, exhausted)
    if names:
        tooltip += f"\n\n[$text-warning]Exhausted {_wordlists_text(len(names))}:[/]\n" + "\n".join(f"- {escape(n)}" for n in names)
    return tooltip


def _row_content(epoch: Optional[int], pair: str, client: str, verdict: tuple[str, str], show_client: bool,
                 trailing: list[tuple[str, str]]) -> Content:
    """One history or UNCRACKED row: date, pair, client, verdict, then ``trailing`` (text, style) columns."""
    columns = [(date_text(epoch).ljust(12), "$foreground-muted"), (pair.ljust(5), "")]
    if show_client:
        columns.append((client.ljust(6), "$text-secondary"))
    columns += [(verdict[0].ljust(10), verdict[1]), *trailing]
    return Content(" ").join(Content.styled(text, style) for text, style in columns)


def _hashline_prompt(group: _HashlineGroup, show_client: bool, show_ssid: bool,
                     exhausted_count: str, exhausted_width: int) -> Content:
    first = group[0]
    verdict = ("authorized", "$text-success") if first.line.authorized else ("challenge", "$text-warning")
    trailing = [((f"×{len(group)}" if len(group) > 1 else "").ljust(3), "$foreground-muted")]
    if exhausted_width:
        trailing.append((exhausted_count.ljust(exhausted_width), "italic $text-accent"))
    if show_ssid:
        trailing.append((first.line.ssid, ""))
    return _row_content(first.first_captured, first.line.pair_label, _client_text(first), verdict, show_client,
                        trailing)


def _live_verification_content(verification: LiveVerification, show_client: bool) -> Content:
    verdict = (("✓ verified live", "$text-success") if verification.correct
               else ("✗ rejected live", "$foreground-muted"))
    return _row_content(verification.at, "", "", verdict, show_client, [])


def _status_class(status: PasswordStatus) -> str:
    return "-" + status.name.lower().replace("_", "-")


class DeleteKeyPressed(Message):
    """The user asked to delete ``key`` and every file holding it."""

    def __init__(self, key: Key) -> None:
        super().__init__()
        self.key = key


class _KeyRow(VerticalGroup):
    DEFAULT_CSS = f"""
    _KeyRow {{ height: auto; }}
    _KeyRow .key-line {{ height: 3; }}
    _KeyRow .no-toggle {{ width: {_TOGGLE_WIDTH}; }}
    _KeyRow Button.toggle {{
        width: {_TOGGLE_WIDTH}; height: 100%; content-align: center middle; background: transparent;
    }}
    _KeyRow .key-text {{
        width: 1fr; height: 100%; content-align: left middle; text-wrap: nowrap; text-overflow: ellipsis;
    }}
    _KeyRow .history {{ display: none; height: auto; padding-left: {_VALUE_COLUMN}; }}
    _KeyRow.-expanded .history {{ display: block; }}
    _KeyRow .history-rows {{ height: auto; max-height: 8; scrollbar-size-vertical: 1; }}
    _KeyRow .history-row {{ height: 1; text-wrap: nowrap; text-overflow: ellipsis; }}
    """

    expanded: reactive[bool] = reactive(False)

    class Toggled(Message):
        def __init__(self, key: Key, expanded: bool) -> None:
            super().__init__()
            self.key = key
            self.expanded = expanded

    class VerifyPressed(Message):
        def __init__(self, key: Key) -> None:
            super().__init__()
            self.key = key

    def __init__(self, key: Key, state: ApState, *, show_client: bool, show_ssid: bool, expanded: bool,
                 verifying: Optional[_VerifyingKey]) -> None:
        status = state.key_statuses[key.id]
        super().__init__(classes=_status_class(status))
        self.status = status
        self.key = key
        self._state = state
        self._show_client = show_client
        self._show_ssid = show_ssid
        self._has_history = bool(key.live_verifications or key.hashline_ids)
        self._history_built = False
        self.toggle_button = Button("", compact=True, classes="toggle")
        self.copy_button = Button("Copy", classes="key-btn")
        self.verify_button = Button("Verify", variant="primary", classes="key-btn")
        self.delete_button = Button("Delete", variant="error", classes="key-btn",
                                    tooltip="Delete this key and every file holding it")
        self.history_rows = VerticalScroll(classes="history-rows")
        self.set_reactive(_KeyRow.expanded, expanded)
        self._show_expansion(expanded)
        self.show_verifying(verifying)

    def _history(self) -> list[Static]:
        rows = [(v.at, Static(_live_verification_content(v, self._show_client), classes="history-row"))
                for v in self.key.live_verifications]
        matched = tuple(h for h in self._state.hashlines if h.id in self.key.hashline_ids)
        for group in hashline_groups(matched):
            row = Static(_hashline_prompt(group, self._show_client, self._show_ssid, "", 0), classes="history-row")
            row.tooltip = _verdict_tooltip(group[0])
            rows.append((group[0].first_captured, row))
        return [row for _, row in sorted(rows, key=lambda row: epoch_sort_key(row[0]), reverse=True)]

    def compose(self) -> ComposeResult:
        with Horizontal(classes="key-line"):
            yield self.toggle_button if self._has_history else Label("", classes="no-toggle")
            summary = Label(Content.from_markup(self._summary_markup()), classes="key-text")
            summary.tooltip = self._details()
            yield summary
            yield self.copy_button
            yield self.verify_button
            yield self.delete_button
        if self._has_history:
            with Vertical(classes="history"):
                yield self.history_rows

    async def on_mount(self) -> None:
        if self.expanded:
            await self._build_history()

    async def _build_history(self) -> None:
        """The history rows, built the first time the key is expanded."""
        if self._history_built or not self._has_history:
            return
        self._history_built = True
        await self.history_rows.mount_all(self._history())

    def _summary_markup(self) -> str:
        key = self.key
        kind = _KEY_KINDS[key.type]
        markup = (f"[bold {kind.badge_color}]{kind.badge.ljust(_BADGE_WIDTH)}[/] "
                  f"[{_KEY_CHIP_STYLE[self.status]}] {escape(key_text(key))} [/]")
        return f"{markup} [dim]({self._details()})[/dim]"

    def _details(self) -> str:
        details = [_status_reason(self.key, self.status)]
        total = len(self._state.hashlines)
        if self.key.type == CaptureType.WPA_PSK and total:
            details.insert(0, f"{len(self.key.hashline_ids)}/{total} captures")
        return ", ".join(details)

    def _show_expansion(self, expanded: bool) -> None:
        self.set_class(expanded, "-expanded")
        self.toggle_button.label = _COLLAPSE_LABEL if expanded else _EXPAND_LABEL
        self.toggle_button.tooltip = _COLLAPSE_TOOLTIP if expanded else _EXPAND_TOOLTIP

    async def watch_expanded(self, expanded: bool) -> None:
        self._show_expansion(expanded)
        if expanded and self.is_mounted:
            await self._build_history()

    def show_verifying(self, verifying: Optional[_VerifyingKey]) -> None:
        """Verify is disabled while any live check runs: "Verifying…" on its key, "Busy" when it is
        another AP's."""
        button = self.verify_button
        button.disabled = verifying is not None
        button.label, button.tooltip = "Verify", _VERIFY_TOOLTIP
        if verifying == (self._state.bssid, self.key.id):
            button.label = "Verifying…"
        elif verifying is not None and verifying[0] != self._state.bssid:
            button.label, button.tooltip = "Busy", _BUSY_TOOLTIP

    @on(Button.Pressed)
    def _button_pressed(self, event: Button.Pressed) -> None:
        if event.button is self.toggle_button:
            self.expanded = not self.expanded
            self.post_message(self.Toggled(self.key, self.expanded))
        elif event.button is self.copy_button:
            self._copy()
        elif event.button is self.verify_button:
            self.post_message(self.VerifyPressed(self.key))
        elif event.button is self.delete_button:
            self.post_message(DeleteKeyPressed(self.key))
        else:
            return
        event.stop()

    def _copy(self) -> None:
        if self.key.type == CaptureType.WPS_PIN and not self.key.value:
            self.app.copy_to_clipboard("")
            self.notify("PIN is empty")
            return
        self.app.copy_to_clipboard(key_text(self.key))
        self.notify("Copied to clipboard")


class AddKeyPressed(Message):
    """The user asked to add a key to the AP in view."""


class _CrackerButton(Button):
    """Opens ``tool``'s launch modal for the ticked hashlines; jobs are filed under ``capture``."""

    def __init__(self, tool: VaultTool, capture: PersistedCapture, disabled: bool) -> None:
        super().__init__(tool.label, "primary", classes="tool-btn", disabled=disabled)
        self.tool = tool
        self.capture = capture


class _UncrackedList(SelectionList[_HashlineGroup]):
    """The uncracked hashline groups, each ticked to crack or not."""

    def __init__(self, *selections: Selection[_HashlineGroup],
                 exhausted: Mapping[str, frozenset[ExhaustedWordlist]], classes: str) -> None:
        super().__init__(*selections, classes=classes)
        self._exhausted = exhausted

    def on_mouse_move(self, event: MouseMove) -> None:
        index = event.style.meta.get("option")
        tooltip = None if index is None else _hashline_tooltip(self.get_option_at_index(index).value, self._exhausted)
        if tooltip != self.tooltip:
            self.tooltip = tooltip

    def groups(self) -> list[_HashlineGroup]:
        return [self.get_option_at_index(i).value for i in range(self.option_count)]

    def highlighted_group(self) -> Optional[_HashlineGroup]:
        return None if self.highlighted is None else self.get_option_at_index(self.highlighted).value


class _ApStatePanel(VerticalGroup):
    """One AP's status, SSIDs, keys and uncracked hashlines."""

    SCOPED_CSS = False
    DEFAULT_CSS = f"""
    _ApStatePanel {{ height: auto; max-width: 81; }}
    _ApStatePanel Rule.-horizontal {{ margin: 0; color: $panel-lighten-2; }}
    _ApStatePanel Rule.uncracked-rule {{ margin-top: 1; }}
    _ApStatePanel .status {{ width: 100%; text-align: center; margin-top: 1; }}
    _ApStatePanel .ssids {{ height: auto; }}
    _ApStatePanel .section-line {{ height: 1; }}
    _ApStatePanel .section {{ text-style: bold; color: $text-muted; width: auto; margin-right: 2; }}
    _ApStatePanel .ssids .section {{ width: 4; }}
    _ApStatePanel .ssid {{ width: 1fr; text-wrap: nowrap; text-overflow: ellipsis; }}
    _ApStatePanel .dates {{ width: auto; color: $text-muted; margin-left: 1; }}
    _ApStatePanel .none-yet {{ color: $text-muted; padding-left: 2; }}
    _ApStatePanel .tools {{ height: auto; align-horizontal: center; }}
    _ApStatePanel .selected-count {{ color: $text-muted; padding-left: {2 * _LIST_INDENT}; }}
    _ApStatePanel .uncracked {{
        height: auto; max-height: 8; margin-top: 1; padding: 0 0 0 {_LIST_INDENT}; border: none;
        background: transparent; scrollbar-size-vertical: 1; text-wrap: nowrap; text-overflow: ellipsis;
    }}

    Screen.{TINY} _ApStatePanel Button.tool-btn {{ height: 1; border: none; }}
    Screen.{SHORT} _ApStatePanel Button.key-btn, Screen.{TINY} _ApStatePanel Button.key-btn,
    Screen.{NARROW} _ApStatePanel Button.key-btn {{
        height: 1; border: none;
    }}
    Screen.{SHORT} _ApStatePanel .key-line, Screen.{TINY} _ApStatePanel .key-line,
    Screen.{NARROW} _ApStatePanel .key-line {{
        height: 1;
    }}
    Screen.{TINY} _ApStatePanel .ssids, Screen.{NARROW} _ApStatePanel .ssids {{ display: none; }}
    Screen.{TINY} _ApStatePanel .status, Screen.{NARROW} _ApStatePanel .status,
    Screen.{TINY} _ApStatePanel Rule.uncracked-rule, Screen.{NARROW} _ApStatePanel Rule.uncracked-rule {{
        margin-top: 0;
    }}
    Screen.{TALL}.{WIDE} _ApStatePanel .uncracked {{ max-height: 12; }}
    """

    add_key_button: Button
    _selected_count_label: Label
    _uncracked_list: Optional[_UncrackedList] = None

    def __init__(self, state: ApState, expanded_key_ids: frozenset[tuple[CaptureType, str]],
                 unticked_hashline_ids: frozenset[str], verifying: Optional[_VerifyingKey]) -> None:
        super().__init__()
        self._state = state
        self._expanded_key_ids = expanded_key_ids
        self._unticked_hashline_ids = unticked_hashline_ids
        self._verifying = verifying

    async def show(self, state: ApState, expanded_key_ids: frozenset[tuple[CaptureType, str]],
                   unticked_hashline_ids: frozenset[str], verifying: Optional[_VerifyingKey]) -> None:
        """Recompose for ``state``; for the same AP, keep the focus, the highlighted hashline and each
        list's scroll."""
        same_ap = state.bssid == self._state.bssid
        focused = self.screen.focused
        focus_key = self._focus_key(focused) if focused is not None and self in focused.ancestors else None
        history_scroll = {row.key.id: row.history_rows.scroll_y for row in self.query(_KeyRow).results(_KeyRow)}
        uncracked = self._uncracked_list
        uncracked_scroll = uncracked.scroll_y if uncracked is not None else 0.0
        highlighted = uncracked.highlighted_group() if uncracked is not None else None
        self._state, self._expanded_key_ids = state, expanded_key_ids
        self._unticked_hashline_ids, self._verifying = unticked_hashline_ids, verifying
        await self.recompose()
        if same_ap:
            self.call_after_refresh(self._restore, focus_key, history_scroll, uncracked_scroll,
                                    highlighted[0].id if highlighted else None)

    def _restore(self, focus_key: Optional[Hashable], history_scroll: dict[tuple[CaptureType, str], float],
                 uncracked_scroll: float, highlighted_hashline_id: Optional[str]) -> None:
        for row in self.query(_KeyRow).results(_KeyRow):
            row.history_rows.scroll_to(y=history_scroll.get(row.key.id, 0.0), animate=False)
        uncracked = self._uncracked_list
        if uncracked is not None:
            index = next((i for i, group in enumerate(uncracked.groups())
                          if group[0].id == highlighted_hashline_id), None)
            if index is not None:
                uncracked.highlighted = index
            uncracked.scroll_to(y=uncracked_scroll, animate=False)
        if focus_key is not None:
            match = next((w for w in self.query("*") if w.focusable and self._focus_key(w) == focus_key), None)
            if match is not None:
                match.focus(scroll_visible=False)

    def _focus_key(self, widget: Widget) -> Optional[Hashable]:
        """What ``widget`` stands for, the same before and after a recompose; None if nothing."""
        if isinstance(widget, _UncrackedList):
            return "uncracked"
        if isinstance(widget, _CrackerButton):
            return "tool", widget.tool.name
        if widget is self.add_key_button:
            return "add-key"
        row = next((a for a in widget.ancestors if isinstance(a, _KeyRow)), None)
        if row is None:
            return None
        buttons = (row.toggle_button, row.copy_button, row.verify_button, row.delete_button)
        return ("key", row.key.id, buttons.index(widget)) if widget in buttons else None

    def compose(self) -> ComposeResult:
        state = self._state
        show_client = len({h.line.mac_sta for h in state.hashlines}) > 1
        show_ssid = len(state.ssids) > 1
        yield Static(Content.from_markup(self._status_markup()), classes="status")
        yield Rule()
        with Vertical(classes="ssids"):
            yield from self._compose_ssids()
            yield Rule()
        with Horizontal(classes="section-line"):
            yield Label("KEYS", classes="section")
            self.add_key_button = Button("Add key", compact=True, classes="add-key",
                                         tooltip="Add a PSK, WPS PIN or WEP key")
            yield self.add_key_button
        for key in state.keys:
            yield _KeyRow(key, state, show_client=show_client, show_ssid=show_ssid,
                          expanded=key.id in self._expanded_key_ids, verifying=self._verifying)
        if not state.keys:
            yield Label("none yet", classes="none-yet")
        if state.handshake_and_pmkid_files and not state.hashlines:
            yield Label(_no_crackable_text(state.handshake_and_pmkid_files), classes="none-yet")
        self._uncracked_list = None
        if state.uncracked:
            yield Rule(classes="uncracked-rule")
            yield from self._compose_uncracked(show_client, show_ssid)

    def _status_markup(self) -> str:
        state = self._state
        status = f"[bold {_STATUS_COLOR[state.status]}]{state.status.value}[/]"
        key = state.status_key
        if key is None:
            return status
        chip = f"[{_KEY_CHIP_STYLE[state.status]}] {_KEY_KINDS[key.type].badge}: {escape(key_text(key))} [/]"
        return f"{chip} {status}"

    def _compose_ssids(self) -> ComposeResult:
        ssids = self._state.ssids
        if len(ssids) <= 1:
            with Horizontal(classes="section-line"):
                yield Label("SSID", classes="section")
                yield Label(ssids[0].ssid if ssids else "‹hidden›", classes="ssid", markup=False)
            return
        for i, history in enumerate(ssids):
            first, last = date_text(history.first_seen), date_text(history.last_seen)
            dates = first if first == last else f"{first} → {last}"
            with Horizontal(classes="section-line"):
                yield Label("" if i else "SSID", classes="section")
                yield Label(history.ssid, classes="ssid", markup=False)
                yield Label(dates, classes="dates")

    def _compose_uncracked(self, show_client: bool, show_ssid: bool) -> ComposeResult:
        state = self._state
        uncracked = state.uncracked
        exhausted = state.exhausted_wordlists
        with Horizontal(classes="section-line"):
            yield Label("UNCRACKED", classes="section")
            yield Label(Content.from_markup(_captures_count_markup(len(uncracked), len(state.hashlines))))
        groups = hashline_groups(uncracked)
        ticked = [not all(h.id in self._unticked_hashline_ids for h in group) for group in groups]
        exhausted_counts = [_exhausted_count_text(group, exhausted) for group in groups]
        exhausted_width = max(map(len, exhausted_counts), default=0)
        self._uncracked_list = _UncrackedList(
            *(Selection(_hashline_prompt(group, show_client, show_ssid, count, exhausted_width), group, is_ticked)
              for group, count, is_ticked in zip(groups, exhausted_counts, ticked)),
            exhausted=exhausted, classes="uncracked")
        yield self._uncracked_list
        selected = [h.line for group, is_ticked in zip(groups, ticked) if is_ticked for h in group]
        self._selected_count_label = Label(_selected_count_text(len(selected)), classes="selected-count")
        yield self._selected_count_label
        capture = state.hashline_capture
        with Horizontal(classes="tools"):
            if capture is not None:
                for tool in self.app.vault.manager.tools.values():
                    if tool.can_crack([h.line for h in uncracked]):
                        yield _CrackerButton(tool, capture, disabled=not tool.can_crack(selected))

    def _selected_hashlines(self) -> list[DatedHashline]:
        if self._uncracked_list is None:
            return []
        return [h for group in self._uncracked_list.selected for h in group]

    @on(SelectionList.SelectedChanged)
    def _selection_changed(self, event: SelectionList.SelectedChanged) -> None:
        if event.selection_list is not self._uncracked_list:
            return
        selected = [h.line for h in self._selected_hashlines()]
        self._selected_count_label.update(_selected_count_text(len(selected)))
        for button in self.query(_CrackerButton).results(_CrackerButton):
            button.disabled = not button.tool.can_crack(selected)

    @on(Button.Pressed)
    def _button_pressed(self, event: Button.Pressed) -> None:
        if isinstance(event.button, _CrackerButton):
            self._launch_tool(event.button)
        elif event.button is self.add_key_button:
            self.post_message(AddKeyPressed())
        else:
            return
        event.stop()

    def _launch_tool(self, button: _CrackerButton) -> None:
        tool, capture = button.tool, button.capture
        selected = self._selected_hashlines()

        def _on_config(config: dict | None) -> None:
            if not config:
                return
            job_id = self.app.vault.manager.submit_job(
                tool.name, capture, self.app.vault.add_probed_ssids(config), hashlines=[h.raw for h in selected])
            self.notify(f"Queued job: {job_id}")

        self.app.push_screen(UI_TOOLS[tool.name](bssid=self._state.bssid, probed_ssids=self.app.vault.probed_ssids(),
                                                 hashlines=selected), _on_config)


class VaultItemView(Vertical):
    DEFAULT_CSS = """
    VaultItemView {
        width: 1fr;
        height: 1fr;
        align-horizontal: center;
        background: $background;
        border: heavy $primary;
        border-title-align: center;
        border-title-color: $primary;
        border-title-style: bold;
        padding: 0 1;
        overflow-y: auto;
        scrollbar-size-vertical: 1;
    }
    VaultItemView #vault-item-empty { color: $text-muted; }
    """

    verifying: var[Optional[_VerifyingKey]] = var(None)

    def __init__(self, id: Optional[str] = None) -> None:
        super().__init__(id=id)
        self.key_verifier = LiveKeyVerifier()
        self.history_expanded_by_user: dict[tuple[CaptureType, str], bool] = {}    # by Key.id, this AP's
        self.unticked_hashline_ids: set[str] = set()
        self._bssid = ""
        self._ssid: Optional[str] = None
        self._state: Optional[ApState] = None

    def load(self, bssid: str, ssid: Optional[str]) -> None:
        """Show this AP. Reloading the AP in view keeps the pane's scroll, the focus, each list's
        scroll, and what the user expanded and ticked."""
        state = self.app.vault.ap_state(bssid) if bssid else None
        if (bssid, ssid, state) == (self._bssid, self._ssid, self._state):
            return
        same_ap, same_state = bssid == self._bssid, state == self._state
        if not same_ap:
            self.history_expanded_by_user.clear()
        self._bssid, self._ssid, self._state = bssid, ssid, state
        if state is None or not self.query_children(_ApStatePanel):
            self.refresh(recompose=True)
            return
        self._set_title()
        if same_ap and same_state:
            return
        self.call_later(self._show_state)
        if not same_ap:
            self.scroll_home(animate=False)

    async def _show_state(self) -> None:
        panel = next(iter(self.query_children(_ApStatePanel).results(_ApStatePanel)), None)
        if panel is not None and self._state is not None:
            await panel.show(self._state, *self._panel_choices(self._state))

    def history_expanded(self, key: Key) -> bool:
        """The user's choice for this key's history, else expanded only in a tall, wide drawer."""
        chosen = self.history_expanded_by_user.get(key.id)
        return chosen if chosen is not None else self.screen.has_class(TALL) and self.screen.has_class(WIDE)

    def _panel_choices(self, state: ApState
                       ) -> tuple[frozenset[tuple[CaptureType, str]], frozenset[str], Optional[_VerifyingKey]]:
        expanded = frozenset(key.id for key in state.keys if self.history_expanded(key))
        return expanded, frozenset(self.unticked_hashline_ids), self.verifying

    def _set_title(self) -> None:
        name = self._ssid or "‹hidden›"
        title = Content.from_markup(f"[$background bold on $primary] {escape(name)} [/]")
        self.border_title = title.append(Content.from_text(f" ({self._bssid}) "))

    def compose(self) -> ComposeResult:
        if self._state is None:
            self.border_title = "Vault Detail"
            yield Label("Select an AP to view its captures", id="vault-item-empty")
            return
        self._set_title()
        yield _ApStatePanel(self._state, *self._panel_choices(self._state))

    def on_resize(self, event: Resize) -> None:
        self.call_after_refresh(self._expand_by_drawer_size)

    def _expand_by_drawer_size(self) -> None:
        for row in self.query(_KeyRow).results(_KeyRow):
            row.expanded = self.history_expanded(row.key)

    def watch_verifying(self, verifying: Optional[_VerifyingKey]) -> None:
        for row in self.query(_KeyRow).results(_KeyRow):
            row.show_verifying(verifying)

    @on(_KeyRow.Toggled)
    def _key_toggled(self, event: _KeyRow.Toggled) -> None:
        self.history_expanded_by_user[event.key.id] = event.expanded

    @on(SelectionList.SelectedChanged)
    def _hashline_tick_changed(self, event: SelectionList.SelectedChanged) -> None:
        if not isinstance(event.selection_list, _UncrackedList):
            return
        ticked = set(event.selection_list.selected)
        for group in event.selection_list.groups():
            ids = {h.id for h in group}
            if group in ticked:
                self.unticked_hashline_ids -= ids
            else:
                self.unticked_hashline_ids |= ids

    @on(_KeyRow.VerifyPressed)
    def _verify_pressed(self, event: _KeyRow.VerifyPressed) -> None:
        if self.verifying is not None or not self._bssid:
            return
        self.verifying = self._bssid, event.key.id
        self._verify(event.key)

    @work
    async def _verify(self, key: Key) -> None:
        """Check the key against the live AP; one check at a time, since they share the devices."""
        try:
            res = await self.key_verifier.verify_credential(key.newest_capture, self.app.array,
                                                            target_type=key.type)
            severity = {VerifyStatus.SUCCESS: "information",
                        VerifyStatus.INCORRECT: "warning"}.get(res.status, "error")
            self.notify(res.body, title=res.title, severity=severity)
            if res.status in (VerifyStatus.SUCCESS, VerifyStatus.INCORRECT):
                self.app.vault.record_live_verification(key, correct=res.status == VerifyStatus.SUCCESS)
        except Exception as exc:
            logger.exception("Error during live verification")
            self.notify(f"Verification error: {exc}", title="Verify", severity="error")
        finally:
            self.verifying = None
