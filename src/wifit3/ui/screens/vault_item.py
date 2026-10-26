from __future__ import annotations

import logging
import time
from collections.abc import Hashable
from itertools import groupby
from typing import Optional

from rich.markup import escape
from textual import on, work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalGroup, VerticalScroll
from textual.content import Content
from textual.events import Resize
from textual.message import Message
from textual.reactive import reactive, var
from textual.widget import Widget
from textual.widgets import Button, Checkbox, Label, Rule, Static

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
from wifit3.persist.exhaustion import Exhaustion
from wifit3.ui.colors import PASSWORD_MISMATCH_COLOR
from wifit3.ui.encryption_format import wep_key_ascii
from wifit3.ui.screens.vault_breakpoints import NARROW, TALL, TINY, WIDE
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
_KEY_LABEL = {CaptureType.WPA_PSK: "PSK", CaptureType.WPS_PIN: "PIN", CaptureType.WEP: "Key"}
_KEY_BADGE = {CaptureType.WPA_PSK: ("PSK", "$text-success"), CaptureType.WPS_PIN: ("WPS", "$text-accent"),
              CaptureType.WEP: ("WEP", "$text-secondary")}
_AUTHORIZED_TOOLTIP = "PMKID or M3/M4: the AP accepted this password"
_CHALLENGE_TOOLTIP = "No M3/M4: could be a wrong password"
_EXPAND_LABEL, _COLLAPSE_LABEL = "▶", "▼"
_EXPAND_TOOLTIP, _COLLAPSE_TOOLTIP = "Show captures and verifications", "Hide captures and verifications"
_VERIFY_TOOLTIP = "Connect to the live AP and verify this key"
_BUSY_TOOLTIP = "A live check is running on another AP"

_VerifyingKey = tuple[str, tuple[CaptureType, str]]    # BSSID, Key.id


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


def hashline_groups(hashlines: tuple[DatedHashline, ...]) -> list[list[DatedHashline]]:
    """Runs of hashlines from the same minute, message pair, client and SSID."""
    def same(h: DatedHashline) -> tuple:
        minute = None if h.first_captured is None else h.first_captured // 60
        return minute, h.line.pair_label, h.line.mac_sta, h.line.ssid, h.line.authorized
    return [list(group) for _, group in groupby(hashlines, same)]


def _captures_count_markup(count: int, total: int) -> str:
    return f"[dim]({count}/{total} captures)[/]"


def _selected_count_text(count: int) -> str:
    return f"{count} capture{'' if count == 1 else 's'} selected to crack"


def _history_row_columns(epoch: Optional[int], pair: str, client: str, verdict: Label,
                         show_client: bool) -> list[Label]:
    columns = [Label(date_text(epoch), classes="date"), Label(pair, classes="pair")]
    if show_client:
        columns.append(Label(client, classes="client"))
    columns.append(verdict)
    return columns


def _hashline_columns(group: list[DatedHashline], show_client: bool, show_ssid: bool) -> list[Label]:
    first = group[0]
    if first.line.authorized:
        verdict = Label("authorized", classes="verdict authorized")
        verdict.tooltip = _AUTHORIZED_TOOLTIP
    else:
        verdict = Label("challenge", classes="verdict challenge")
        verdict.tooltip = _CHALLENGE_TOOLTIP
    columns = _history_row_columns(first.first_captured, first.line.pair_label, _client_text(first),
                                   verdict, show_client)
    columns.append(Label(f"×{len(group)}" if len(group) > 1 else "", classes="count"))
    if show_ssid:
        columns.append(Label(first.line.ssid, classes="row-ssid", markup=False))
    return columns


def _live_verification_columns(verification: LiveVerification, show_client: bool) -> list[Label]:
    verdict = (Label("✓ verified live", classes="verdict live verified") if verification.correct
               else Label("✗ rejected live", classes="verdict live rejected"))
    return _history_row_columns(verification.at, "", "", verdict, show_client)


def _exhaustion_text(exhaustion: Exhaustion) -> str:
    name = " / ".join(exhaustion.wordlist_names) or "unnamed wordlist"
    if exhaustion.exhausted_hashlines == exhaustion.hashlines:
        return name
    return f"{name} ({exhaustion.exhausted_hashlines}/{exhaustion.hashlines})"


def _status_class(status: PasswordStatus) -> str:
    return "-" + status.name.lower().replace("_", "-")


class _KeyRow(VerticalGroup):
    DEFAULT_CSS = """
    _KeyRow { height: auto; }
    _KeyRow .key-line { height: 1; }
    _KeyRow .no-toggle { width: 3; }
    _KeyRow Button.toggle { width: 3; background: transparent; }
    _KeyRow .key-text { width: 1fr; text-wrap: nowrap; text-overflow: ellipsis; }
    _KeyRow Button { margin-left: 1; }
    _KeyRow .history { display: none; height: auto; padding-left: 1; }
    _KeyRow.-expanded .history { display: block; }
    _KeyRow .history-rows { height: auto; max-height: 8; scrollbar-size-vertical: 1; }
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
        self.copy_button = Button("Copy", compact=True, classes="copy-btn")
        self.verify_button = Button("Verify", compact=True, variant="primary", classes="verify-btn")
        self.history_rows = VerticalScroll(classes="history-rows")
        self.set_reactive(_KeyRow.expanded, expanded)
        self._show_expansion(expanded)
        self.show_verifying(verifying)

    def _history(self) -> list[tuple[Optional[int], list[Label]]]:
        rows = [(v.at, _live_verification_columns(v, self._show_client)) for v in self.key.live_verifications]
        matched = tuple(h for h in self._state.hashlines if h.id in self.key.hashline_ids)
        rows += [(group[0].first_captured, _hashline_columns(group, self._show_client, self._show_ssid))
                 for group in hashline_groups(matched)]
        return sorted(rows, key=lambda row: epoch_sort_key(row[0]), reverse=True)

    def compose(self) -> ComposeResult:
        with Horizontal(classes="key-line"):
            yield self.toggle_button if self._has_history else Label("", classes="no-toggle")
            yield Label(Content.from_markup(self._summary_markup()), classes="key-text")
            yield self.copy_button
            yield self.verify_button
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
        await self.history_rows.mount_all(Horizontal(*columns, classes="row") for _, columns in self._history())

    def _summary_markup(self) -> str:
        key = self.key
        badge, badge_color = _KEY_BADGE[key.type]
        markup = f"[bold {badge_color}]{badge}[/] [{_KEY_CHIP_STYLE[self.status]}] {escape(key_text(key))} [/]"
        total = len(self._state.hashlines)
        if key.type == CaptureType.WPA_PSK and total:
            markup += f" {_captures_count_markup(len(key.hashline_ids), total)}"
            if self.status is PasswordStatus.NOT_VERIFIED:
                markup += " [$text-warning]unverified[/]"
        return markup

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


class _HashlineGroupCheckbox(Checkbox):
    """Ticks one group of uncracked hashlines for cracking."""

    def __init__(self, group: list[DatedHashline], value: bool) -> None:
        super().__init__("", value, compact=True)
        self.group = group


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
    _ApStatePanel .tools {{ height: auto; }}
    _ApStatePanel .selected-count, _ApStatePanel .exhausted {{ color: $text-muted; }}
    _ApStatePanel .uncracked {{ height: auto; max-height: 8; scrollbar-size-vertical: 1; }}
    _ApStatePanel .row {{ height: 1; }}
    _ApStatePanel .row > * {{ margin-right: 1; text-wrap: nowrap; }}
    _ApStatePanel .row Checkbox {{ width: 3; text-overflow: clip; }}
    _ApStatePanel .row:focus-within {{ background: $block-hover-background; }}
    _ApStatePanel .row .date {{ width: 12; color: $text-muted; }}
    _ApStatePanel .row .pair {{ width: 5; }}
    _ApStatePanel .row .client {{ width: 6; color: $text-muted; }}
    _ApStatePanel .row .verdict {{ width: 10; }}
    _ApStatePanel .row .live {{ width: auto; }}
    _ApStatePanel .row .count {{ width: 4; color: $text-muted; }}
    _ApStatePanel .row .row-ssid {{ width: 1fr; text-overflow: ellipsis; }}
    _ApStatePanel .authorized, _ApStatePanel .verified {{ color: $text-success; }}
    _ApStatePanel .challenge {{ color: $text-warning; }}
    _ApStatePanel .rejected {{ color: $text-muted; }}

    Screen.{TINY} _ApStatePanel Button.tool-btn {{ height: 1; border: none; }}
    Screen.{TINY} _ApStatePanel .ssids, Screen.{NARROW} _ApStatePanel .ssids {{ display: none; }}
    Screen.{TINY} _ApStatePanel .status, Screen.{NARROW} _ApStatePanel .status,
    Screen.{TINY} _ApStatePanel Rule.uncracked-rule, Screen.{NARROW} _ApStatePanel Rule.uncracked-rule {{
        margin-top: 0;
    }}
    Screen.{WIDE} _ApStatePanel .row > * {{ margin-right: 2; }}
    Screen.{TALL}.{WIDE} _ApStatePanel {{ min-height: 100%; }}
    Screen.{TALL}.{WIDE} _ApStatePanel .uncracked {{ height: 1fr; min-height: 8; max-height: 100%; }}
    """

    add_key_button: Button
    _selected_count_label: Label
    _uncracked_list: Optional[VerticalScroll] = None

    def __init__(self, state: ApState, expanded_key_ids: frozenset[tuple[CaptureType, str]],
                 unticked_hashline_ids: frozenset[str], verifying: Optional[_VerifyingKey]) -> None:
        super().__init__()
        self._state = state
        self._expanded_key_ids = expanded_key_ids
        self._unticked_hashline_ids = unticked_hashline_ids
        self._verifying = verifying

    async def show(self, state: ApState, expanded_key_ids: frozenset[tuple[CaptureType, str]],
                   unticked_hashline_ids: frozenset[str], verifying: Optional[_VerifyingKey]) -> None:
        """Recompose for ``state``, keeping the focus and the scroll of each list."""
        focused = self.screen.focused
        focus_key = self._focus_key(focused) if focused is not None and self in focused.ancestors else None
        history_scroll = {row.key.id: row.history_rows.scroll_y for row in self.query(_KeyRow).results(_KeyRow)}
        uncracked_scroll = self._uncracked_list.scroll_y if self._uncracked_list is not None else 0.0
        self._state, self._expanded_key_ids = state, expanded_key_ids
        self._unticked_hashline_ids, self._verifying = unticked_hashline_ids, verifying
        await self.recompose()
        self.call_after_refresh(self._restore, focus_key, history_scroll, uncracked_scroll)

    def _restore(self, focus_key: Optional[Hashable], history_scroll: dict[tuple[CaptureType, str], float],
                 uncracked_scroll: float) -> None:
        for row in self.query(_KeyRow).results(_KeyRow):
            row.history_rows.scroll_to(y=history_scroll.get(row.key.id, 0.0), animate=False)
        if self._uncracked_list is not None:
            self._uncracked_list.scroll_to(y=uncracked_scroll, animate=False)
        if focus_key is not None:
            match = next((w for w in self.query("*") if w.focusable and self._focus_key(w) == focus_key), None)
            if match is not None:
                match.focus(scroll_visible=False)

    def _focus_key(self, widget: Widget) -> Optional[Hashable]:
        """What ``widget`` stands for, the same before and after a recompose; None if nothing."""
        if isinstance(widget, _HashlineGroupCheckbox):
            return "hashlines", widget.group[0].id
        if isinstance(widget, _CrackerButton):
            return "tool", widget.tool.name
        if widget is self.add_key_button:
            return "add-key"
        row = next((a for a in widget.ancestors if isinstance(a, _KeyRow)), None)
        if row is None:
            return None
        buttons = (row.toggle_button, row.copy_button, row.verify_button)
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
        chip = f"[{_KEY_CHIP_STYLE[state.status]}] {_KEY_LABEL[key.type]}: {escape(key_text(key))} [/]"
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
        with Horizontal(classes="section-line"):
            yield Label("UNCRACKED", classes="section")
            yield Label(Content.from_markup(_captures_count_markup(len(uncracked), len(state.hashlines))))
        groups = hashline_groups(uncracked)
        ticked = [not all(h.id in self._unticked_hashline_ids for h in group) for group in groups]
        selected = [h.line for group, is_ticked in zip(groups, ticked) if is_ticked for h in group]
        capture = state.hashline_capture
        with Horizontal(classes="tools"):
            if capture is not None:
                for tool in self.app.vault.manager.tools.values():
                    if tool.can_crack([h.line for h in uncracked]):
                        yield _CrackerButton(tool, capture, disabled=not tool.can_crack(selected))
        self._selected_count_label = Label(_selected_count_text(len(selected)), classes="selected-count")
        yield self._selected_count_label
        if state.uncracked_exhaustion:
            names = [_exhaustion_text(e) for e in state.uncracked_exhaustion]
            yield Static(f"exhausted: {escape(', '.join(names))}", classes="exhausted")
        self._uncracked_list = VerticalScroll(classes="uncracked")
        with self._uncracked_list:
            for group, is_ticked in zip(groups, ticked):
                yield Horizontal(_HashlineGroupCheckbox(group, is_ticked),
                                 *_hashline_columns(group, show_client, show_ssid), classes="row")

    def _selected_hashlines(self) -> list[DatedHashline]:
        return [h for checkbox in self.query(_HashlineGroupCheckbox).results(_HashlineGroupCheckbox)
                if checkbox.value for h in checkbox.group]

    @on(Checkbox.Changed)
    def _selection_changed(self, event: Checkbox.Changed) -> None:
        if not isinstance(event.checkbox, _HashlineGroupCheckbox):
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

    @on(Checkbox.Changed)
    def _hashline_tick_changed(self, event: Checkbox.Changed) -> None:
        if not isinstance(event.checkbox, _HashlineGroupCheckbox):
            return
        ids = {h.id for h in event.checkbox.group}
        if event.value:
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
