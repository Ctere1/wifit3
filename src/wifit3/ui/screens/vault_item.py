from __future__ import annotations

import logging
import time
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
from textual.widgets import Button, Checkbox, Label, Rule, Static

from wifit3.campaigns.live_check import LiveKeyVerifier, VerifyStatus
from wifit3.campaigns.pin import EMPTY_PIN_LABEL
from wifit3.models import CaptureType, PersistedCapture, ToolName
from wifit3.persist.ap_state import (
    ApState,
    DatedHashline,
    Key,
    LiveVerification,
    PasswordStatus,
    epoch_sort_key,
    is_confirmed,
    key_status,
)
from wifit3.persist.exhaustion import Exhaustion
from wifit3.ui.capture_log import STALE_PASSWORD_COLOR
from wifit3.ui.encryption_format import printable_wep_key
from wifit3.ui.vault.tools_ui import UI_TOOLS
from wifit3.vault.tools.base import VaultTool


logger = logging.getLogger(__name__)

_STATUS_COLOR = {
    PasswordStatus.CURRENT: "$text-success",
    PasswordStatus.NOT_VERIFIED: "$text-warning",
    PasswordStatus.STALE: STALE_PASSWORD_COLOR,
    PasswordStatus.NOT_CRACKED: "$text-error",
}
_KEY_CHIP_STYLE = {
    PasswordStatus.CURRENT: "black bold on lightgreen",
    PasswordStatus.NOT_VERIFIED: "black bold on $warning",
    PasswordStatus.STALE: f"black bold on {STALE_PASSWORD_COLOR}",
}
_KEY_LABEL = {CaptureType.WPA_PSK: "PSK", CaptureType.WPS_PIN: "PIN", CaptureType.WEP: "Key"}
_KEY_BADGE = {CaptureType.WPA_PSK: ("PSK", "$text-success"), CaptureType.WPS_PIN: ("WPS", "$text-accent"),
              CaptureType.WEP: ("WEP", "$text-secondary")}
_AUTHORIZED_TOOLTIP = "PMKID or M3/M4: the AP accepted this password"
_CHALLENGE_TOOLTIP = "No M3/M4: could be a wrong password"
_EXPAND_LABEL, _COLLAPSE_LABEL = "▶", "▼"
_EXPAND_TOOLTIP, _COLLAPSE_TOOLTIP = "Show captures and verifications", "Hide captures and verifications"

KeyId = tuple[str, CaptureType, str]    # BSSID, key type, value


def key_text(key: Key) -> str:
    """The key as the user types it: a WEP key in ASCII when printable, else hex."""
    if key.type == CaptureType.WEP:
        return printable_wep_key(key.value) or key.value
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


def _selected_text(count: int) -> str:
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
    if verification.correct:
        verdict = Label("✓ verified live", classes="verdict live verified")
    else:
        verdict = Label("✗ rejected live", classes="verdict live rejected")
        verdict.styles.color = STALE_PASSWORD_COLOR
    return _history_row_columns(verification.at, "", "", verdict, show_client)


def _exhaustion_text(exhaustion: Exhaustion) -> str:
    name = " / ".join(exhaustion.wordlist_names) or "unnamed wordlist"
    if exhaustion.exhausted_hashlines == exhaustion.hashlines:
        return name
    return f"{name} ({exhaustion.exhausted_hashlines}/{exhaustion.hashlines})"


def _key_id(key: Key) -> KeyId:
    return key.newest_capture.bssid, key.type, key.value


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
                 verifying: Optional[Key]) -> None:
        super().__init__()
        self.key = key
        self._state = state
        self._show_client = show_client
        self._show_ssid = show_ssid
        self.verify_button = Button("Verify", compact=True, variant="primary", classes="verify-btn",
                                     tooltip="Connect to the live AP and verify this key")
        self.toggle_button = Button("", compact=True, classes="toggle")
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
        history = self._history()
        with Horizontal(classes="key-line"):
            yield self.toggle_button if history else Label("", classes="no-toggle")
            yield Label(Content.from_markup(self._summary_markup()), classes="key-text")
            yield Button("Copy", compact=True, classes="copy-btn")
            yield self.verify_button
        if history:
            with Vertical(classes="history"):
                with VerticalScroll(classes="history-rows"):
                    for _, columns in history:
                        yield Horizontal(*columns, classes="row")

    def _summary_markup(self) -> str:
        key = self.key
        badge, badge_color = _KEY_BADGE[key.type]
        chip = _KEY_CHIP_STYLE[key_status(key, self._state)]
        markup = f"[bold {badge_color}]{badge}[/] [{chip}] {escape(key_text(key))} [/]"
        total = len(self._state.hashlines)
        if key.type == CaptureType.WPA_PSK and total:
            markup += f" {_captures_count_markup(len(key.hashline_ids), total)}"
            if not is_confirmed(key, self._state.hashlines):
                markup += " [$text-warning]unverified[/]"
        return markup

    def _show_expansion(self, expanded: bool) -> None:
        self.set_class(expanded, "-expanded")
        self.toggle_button.label = _COLLAPSE_LABEL if expanded else _EXPAND_LABEL
        self.toggle_button.tooltip = _COLLAPSE_TOOLTIP if expanded else _EXPAND_TOOLTIP

    def watch_expanded(self, expanded: bool) -> None:
        self._show_expansion(expanded)

    def show_verifying(self, verifying: Optional[Key]) -> None:
        """Disable Verify while any live check runs; label the row whose key it checks."""
        self.verify_button.disabled = verifying is not None
        checking_this = verifying is not None and _key_id(verifying) == _key_id(self.key)
        self.verify_button.label = "Verifying…" if checking_this else "Verify"

    @on(Button.Pressed, ".toggle")
    def _toggle_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.expanded = not self.expanded
        self.post_message(self.Toggled(self.key, self.expanded))

    @on(Button.Pressed, ".copy-btn")
    def _copy(self, event: Button.Pressed) -> None:
        event.stop()
        if self.key.type == CaptureType.WPS_PIN and not self.key.value:
            self.app.copy_to_clipboard("")
            self.notify("PIN is empty")
            return
        self.app.copy_to_clipboard(key_text(self.key))
        self.notify("Copied to clipboard")

    @on(Button.Pressed, ".verify-btn")
    def _verify_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.post_message(self.VerifyPressed(self.key))


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
    """One AP's status, SSIDs, keys and uncracked hashlines; ``view`` holds what the user chose."""

    SCOPED_CSS = False
    DEFAULT_CSS = """
    _ApStatePanel { height: auto; max-width: 81; }
    _ApStatePanel Rule.-horizontal { margin: 0; color: $panel-lighten-2; }
    _ApStatePanel Rule.uncracked-rule { margin-top: 1; }
    _ApStatePanel .status { width: 100%; text-align: center; margin-top: 1; }
    _ApStatePanel .ssids { height: auto; }
    _ApStatePanel .section-line { height: 1; }
    _ApStatePanel .section { text-style: bold; color: $text-muted; width: auto; margin-right: 2; }
    _ApStatePanel .ssids .section { width: 4; }
    _ApStatePanel .ssid { width: 1fr; text-wrap: nowrap; text-overflow: ellipsis; }
    _ApStatePanel .dates { width: auto; color: $text-muted; margin-left: 1; }
    _ApStatePanel .none-yet { color: $text-muted; padding-left: 2; }
    _ApStatePanel .tools { height: auto; }
    _ApStatePanel .tools Button { margin-right: 1; }
    _ApStatePanel .selected-count, _ApStatePanel .exhausted { color: $text-muted; }
    _ApStatePanel .uncracked { height: auto; max-height: 8; scrollbar-size-vertical: 1; }
    _ApStatePanel .row { height: 1; }
    _ApStatePanel .row > * { margin-right: 1; text-wrap: nowrap; }
    _ApStatePanel .row Checkbox { width: 3; text-overflow: clip; }
    _ApStatePanel .row:focus-within { background: $block-hover-background; }
    _ApStatePanel .row .date { width: 12; color: $text-muted; }
    _ApStatePanel .row .pair { width: 5; }
    _ApStatePanel .row .client { width: 6; color: $text-muted; }
    _ApStatePanel .row .verdict { width: 10; }
    _ApStatePanel .row .live { width: auto; }
    _ApStatePanel .row .count { width: 4; color: $text-muted; }
    _ApStatePanel .row .row-ssid { width: 1fr; text-overflow: ellipsis; }
    _ApStatePanel .authorized, _ApStatePanel .verified { color: $text-success; }
    _ApStatePanel .challenge { color: $text-warning; }

    Screen.-tiny _ApStatePanel Button.tool-btn { height: 1; border: none; }
    Screen.-tiny _ApStatePanel .ssids, Screen.-narrow _ApStatePanel .ssids { display: none; }
    Screen.-tiny _ApStatePanel .status, Screen.-narrow _ApStatePanel .status,
    Screen.-tiny _ApStatePanel Rule.uncracked-rule, Screen.-narrow _ApStatePanel Rule.uncracked-rule {
        margin-top: 0;
    }
    Screen.-wide _ApStatePanel .row > * { margin-right: 2; }
    Screen.-tall.-wide _ApStatePanel { min-height: 100%; }
    Screen.-tall.-wide _ApStatePanel .uncracked { height: 1fr; min-height: 8; max-height: 100%; }
    """

    def __init__(self, view: VaultItemView, state: ApState) -> None:
        super().__init__()
        self._view = view
        self._state = state

    def show(self, state: ApState) -> None:
        self._state = state
        self.refresh(recompose=True)

    def compose(self) -> ComposeResult:
        state = self._state
        view = self._view
        show_client = len({h.line.mac_sta for h in state.hashlines}) > 1
        show_ssid = len(state.ssids) > 1
        yield Static(Content.from_markup(self._status_markup()), classes="status")
        yield Rule()
        with Vertical(classes="ssids"):
            yield from self._compose_ssids()
            yield Rule()
        with Horizontal(classes="section-line"):
            yield Label("KEYS", classes="section")
            yield Button("Add key", compact=True, classes="add-key", tooltip="Add a PSK, WPS PIN or WEP key")
        for key in state.keys:
            yield _KeyRow(key, state, show_client=show_client, show_ssid=show_ssid,
                          expanded=view.key_expanded(key), verifying=view.verifying)
        if not state.keys:
            yield Label("none yet", classes="none-yet")
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
        unticked = self._view.unticked_hashline_ids
        groups = hashline_groups(uncracked)
        ticked = [not all(h.id in unticked for h in group) for group in groups]
        selected = sum(len(group) for group, is_ticked in zip(groups, ticked) if is_ticked)
        capture = state.hashline_capture
        with Horizontal(classes="tools"):
            if capture is not None:
                for tool in self.app.vault.manager.tools.values():
                    if tool.can_crack(capture):
                        yield _CrackerButton(tool, capture, disabled=selected == 0)
        yield Label(_selected_text(selected), classes="selected-count")
        if state.uncracked_exhaustion:
            names = [_exhaustion_text(e) for e in state.uncracked_exhaustion]
            yield Static(f"exhausted: {escape(', '.join(names))}", classes="exhausted")
        with VerticalScroll(classes="uncracked"):
            for group, is_ticked in zip(groups, ticked):
                yield Horizontal(_HashlineGroupCheckbox(group, is_ticked),
                                 *_hashline_columns(group, show_client, show_ssid), classes="row")

    def _selected_hashlines(self) -> list[DatedHashline]:
        return [h for checkbox in self.query(_HashlineGroupCheckbox).results(_HashlineGroupCheckbox)
                if checkbox.value for h in checkbox.group]

    @on(Checkbox.Changed)
    def _selection_changed(self, event: Checkbox.Changed) -> None:
        count = len(self._selected_hashlines())
        self.query_one(".selected-count", Label).update(_selected_text(count))
        for button in self.query(_CrackerButton).results(_CrackerButton):
            button.disabled = count == 0

    @on(Button.Pressed, ".add-key")
    def _add_key(self, event: Button.Pressed) -> None:
        event.stop()
        self.post_message(AddKeyPressed())

    @on(Button.Pressed, ".tool-btn")
    def _launch_tool(self, event: Button.Pressed) -> None:
        event.stop()
        assert isinstance(event.button, _CrackerButton)
        tool, capture = event.button.tool, event.button.capture
        selected = self._selected_hashlines()

        def _on_config(config: dict | None) -> None:
            if not config:
                return
            job_id = self.app.vault.manager.submit_job(
                tool.name, capture, self.app.vault.add_probed_ssids(config), hashlines=[h.raw for h in selected])
            self.notify(f"Queued job: {job_id}")

        modal_type = UI_TOOLS[ToolName(tool.name)]
        self.app.push_screen(modal_type(capture=capture, probed_ssids=self.app.vault.probed_ssids(),
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

    verifying: var[Optional[Key]] = var(None)

    def __init__(self, id: Optional[str] = None) -> None:
        super().__init__(id=id)
        self.key_verifier = LiveKeyVerifier()
        self.expanded_key_ids: set[KeyId] = set()       # toggled open by the user
        self.collapsed_key_ids: set[KeyId] = set()      # toggled shut by the user
        self.unticked_hashline_ids: set[str] = set()
        self._bssid = ""
        self._ssid: Optional[str] = None
        self._state: Optional[ApState] = None

    def load(self, bssid: str, ssid: Optional[str]) -> None:
        """Show this AP; reloading the AP in view keeps what the user expanded, ticked and scrolled."""
        state = self.app.vault.ap_state(bssid) if bssid else None
        if (bssid, ssid, state) == (self._bssid, self._ssid, self._state):
            return
        same_ap, shown = bssid == self._bssid, self._state is not None
        self._bssid, self._ssid, self._state = bssid, ssid, state
        if state is None or not shown:
            self.refresh(recompose=True)
            return
        self._set_title()
        self.query_one(_ApStatePanel).show(state)
        if not same_ap:
            self.scroll_home(animate=False)

    def key_expanded(self, key: Key) -> bool:
        """The user's choice for this key's history, else expanded only in a tall, wide drawer."""
        key_id = _key_id(key)
        if key_id in self.expanded_key_ids or key_id in self.collapsed_key_ids:
            return key_id in self.expanded_key_ids
        return self.screen.has_class("-tall") and self.screen.has_class("-wide")

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
        yield _ApStatePanel(self, self._state)

    def on_resize(self, event: Resize) -> None:
        self.call_after_refresh(self._expand_by_drawer_size)

    def _expand_by_drawer_size(self) -> None:
        for row in self.query(_KeyRow).results(_KeyRow):
            row.expanded = self.key_expanded(row.key)

    def watch_verifying(self, verifying: Optional[Key]) -> None:
        for row in self.query(_KeyRow).results(_KeyRow):
            row.show_verifying(verifying)

    @on(_KeyRow.Toggled)
    def _key_toggled(self, event: _KeyRow.Toggled) -> None:
        key_id = _key_id(event.key)
        (self.expanded_key_ids if event.expanded else self.collapsed_key_ids).add(key_id)
        (self.collapsed_key_ids if event.expanded else self.expanded_key_ids).discard(key_id)

    @on(Checkbox.Changed)
    def _hashlines_ticked(self, event: Checkbox.Changed) -> None:
        if not isinstance(event.checkbox, _HashlineGroupCheckbox):
            return
        ids = {h.id for h in event.checkbox.group}
        if event.value:
            self.unticked_hashline_ids -= ids
        else:
            self.unticked_hashline_ids |= ids

    @on(_KeyRow.VerifyPressed)
    def _verify_pressed(self, event: _KeyRow.VerifyPressed) -> None:
        if self.verifying is None:
            self._verify(event.key)

    @work(exclusive=True, group="live-verify")
    async def _verify(self, key: Key) -> None:
        """Check the key against the live AP; one check at a time, since they share the devices."""
        self.verifying = key
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
