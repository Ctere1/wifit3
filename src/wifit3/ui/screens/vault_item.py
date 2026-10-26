from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from itertools import groupby
from typing import Optional

from rich.markup import escape
from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalGroup, VerticalScroll
from textual.content import Content
from textual.message import Message
from textual.widgets import Button, Checkbox, Label, Rule, Static

from wifit3.campaigns.pin import EMPTY_PIN_LABEL
from wifit3.models import CaptureType, PersistedCapture
from wifit3.persist.ap_state import (
    ApState,
    DatedHashline,
    Key,
    LiveVerification,
    PasswordStatus,
    load_ap_state,
    record_live_verification,
)
from wifit3.ui.vault.tools_ui import UI_TOOLS
from wifit3.vault.exhaustion import exhausted_wordlist_names


logger = logging.getLogger(__name__)

_STATUS_STYLE = {
    PasswordStatus.CURRENT: "$text-success",
    PasswordStatus.NOT_VERIFIED: "$text-warning",
    PasswordStatus.STALE: "#ffaf00",
    PasswordStatus.NOT_CRACKED: "$text-error",
}
_KEY_CHIP_STYLE = {
    PasswordStatus.CURRENT: "black bold on lightgreen",
    PasswordStatus.NOT_VERIFIED: "black bold on $warning",
    PasswordStatus.STALE: "black bold on #ffaf00",
}
_KEY_LABEL = {CaptureType.WPA_PSK: "PSK", CaptureType.WPS_PIN: "PIN", CaptureType.WEP: "Key"}
_KEY_BADGE = {CaptureType.WPA_PSK: ("PSK", "$text-success"), CaptureType.WPS_PIN: ("WPS", "$text-accent"),
              CaptureType.WEP: ("WEP", "$text-secondary")}
_AUTHORIZED_TOOLTIP = "PMKID or M3/M4: the AP accepted this password"
_CHALLENGE_TOOLTIP = "No M3/M4: could be a wrong password"


def _hex_to_ascii(hex_key: Optional[str]) -> str:
    if not hex_key:
        return ""
    try:
        raw = bytes.fromhex(hex_key)
    except ValueError:
        return ""
    return raw.decode("ascii") if all(32 <= b < 127 for b in raw) else ""


def key_text(key: Key) -> str:
    """The key as the user types it: a WEP key in ASCII when printable, else hex."""
    if key.capture_type == CaptureType.WEP:
        return _hex_to_ascii(key.value) or key.value
    if key.capture_type == CaptureType.WPS_PIN:
        return key.value or EMPTY_PIN_LABEL
    return key.value


def when(epoch: int) -> str:
    """``today  19:37``, ``Oct 22 19:37``, ``Oct 22 2025``; ``no date`` for 0."""
    if not epoch:
        return "no date"
    moment, now = time.localtime(epoch), time.localtime()
    if moment.tm_year != now.tm_year:
        return time.strftime("%b %d %Y", moment)
    if moment.tm_yday == now.tm_yday:
        return time.strftime("today  %H:%M", moment)
    return time.strftime("%b %d %H:%M", moment)


def hashline_groups(hashlines: tuple[DatedHashline, ...]) -> list[list[DatedHashline]]:
    """Runs of hashlines from the same minute, message pair, client and SSID."""
    def same(h: DatedHashline) -> tuple:
        return h.first_captured // 60, h.pair_label, h.client, h.ssid, h.line.authorized
    return [list(group) for _, group in groupby(hashlines, same)]


def _columns(state: ApState, epoch: int, pair: str, client: str, verdict: Label) -> list[Label]:
    columns = [Label(when(epoch), classes="date"), Label(pair, classes="pair")]
    if len({h.client for h in state.hashlines}) > 1:
        columns.append(Label(client, classes="client"))
    columns.append(verdict)
    return columns


def _hashline_columns(group: list[DatedHashline], state: ApState) -> list[Label]:
    first = group[0]
    if first.line.authorized:
        verdict = Label("authorized", classes="verdict authorized")
        verdict.tooltip = _AUTHORIZED_TOOLTIP
    else:
        verdict = Label("challenge", classes="verdict challenge")
        verdict.tooltip = _CHALLENGE_TOOLTIP
    columns = _columns(state, first.first_captured, first.pair_label, f"…{first.client}", verdict)
    columns.append(Label(f"×{len(group)}" if len(group) > 1 else "", classes="count"))
    if len(state.ssids) > 1:
        columns.append(Label(first.ssid, classes="row-ssid", markup=False))
    return columns


def _live_verification_columns(verification: LiveVerification, state: ApState) -> list[Label]:
    verdict = (Label("✓ verified live", classes="verdict live verified") if verification.correct
               else Label("✗ rejected live", classes="verdict live rejected"))
    return _columns(state, verification.at, "", "", verdict)


def _key_id(key: Key) -> tuple[CaptureType, str]:
    return key.capture_type, key.value


@dataclass(frozen=True)
class _UserChoices:
    expanded_keys: frozenset[tuple[CaptureType, str]]
    collapsed_keys: frozenset[tuple[CaptureType, str]]
    unchecked_hashline_ids: frozenset[str]
    scroll_y: float
    uncracked_scroll_y: float


class _KeyRow(VerticalGroup):
    DEFAULT_CSS = """
    _KeyRow { height: auto; }
    _KeyRow .key-line { height: 1; }
    _KeyRow .no-toggle { width: 3; }
    _KeyRow .key-text { width: 1fr; text-wrap: nowrap; text-overflow: ellipsis; }
    _KeyRow Button { margin-left: 1; }
    _KeyRow .history { height: auto; padding-left: 1; }
    _KeyRow .history-rows { height: auto; max-height: 8; scrollbar-size-vertical: 1; }
    _KeyRow .history, _KeyRow .collapse { display: none; }
    _KeyRow.-expanded .history, _KeyRow.-expanded .collapse { display: block; }
    _KeyRow.-expanded .expand { display: none; }
    """

    def __init__(self, key: Key, state: ApState, classes: str = "") -> None:
        super().__init__(classes=classes)
        self.key = key
        self._state = state
        self._verify_task: Optional[asyncio.Task] = None

    def _history(self) -> list[tuple[int, list[Label]]]:
        rows = [(v.at, _live_verification_columns(v, self._state)) for v in self.key.live_verifications]
        matched = tuple(h for h in self._state.hashlines if h.id in self.key.hashline_ids)
        rows += [(group[0].first_captured, _hashline_columns(group, self._state))
                 for group in hashline_groups(matched)]
        return sorted(rows, key=lambda row: row[0], reverse=True)

    def compose(self) -> ComposeResult:
        history = self._history()
        with Horizontal(classes="key-line"):
            if history:
                yield Button("▶", compact=True, classes="toggle expand", tooltip="Show captures and verifications")
                yield Button("▼", compact=True, classes="toggle collapse", tooltip="Hide captures and verifications")
            else:
                yield Label("", classes="no-toggle")
            yield Label(Content.from_markup(self._summary_markup()), classes="key-text")
            yield Button("Copy", compact=True, classes="copy-btn")
            yield Button("Verify", compact=True, variant="primary", classes="verify-btn",
                         tooltip="Connect to the live AP and verify this key")
        if history:
            with Vertical(classes="history"):
                with VerticalScroll(classes="history-rows"):
                    for _, columns in history:
                        yield Horizontal(*columns, classes="row")

    def _summary_markup(self) -> str:
        key = self.key
        badge, style = _KEY_BADGE[key.capture_type]
        markup = f"[bold {style}]{badge}[/] [black bold on lightgreen] {escape(key_text(key))} [/]"
        total = len(self._state.hashlines)
        if key.capture_type == CaptureType.WPA_PSK and total:
            markup += f" [dim]({len(key.hashline_ids)}/{total} captures)[/]"
            authorized = any(h.line.authorized for h in self._state.hashlines if h.id in key.hashline_ids)
            if not authorized and not any(v.correct for v in key.live_verifications):
                markup += " [#ffaf00]unverified[/]"
        return markup

    @on(Button.Pressed, ".expand")
    def _expand(self, event: Button.Pressed) -> None:
        event.stop()
        self.remove_class("-collapsed").add_class("-expanded")
        if event.button.has_focus:
            self.call_after_refresh(self.query_one(".collapse", Button).focus)

    @on(Button.Pressed, ".collapse")
    def _collapse(self, event: Button.Pressed) -> None:
        event.stop()
        self.remove_class("-expanded").add_class("-collapsed")
        if event.button.has_focus:
            self.call_after_refresh(self.query_one(".expand", Button).focus)

    @on(Button.Pressed, ".copy-btn")
    def _copy(self, event: Button.Pressed) -> None:
        event.stop()
        self.app.copy_to_clipboard(key_text(self.key))
        self.notify("Copied to clipboard")

    def cancel_verification(self) -> None:
        if self._verify_task is not None and not self._verify_task.done():
            self._verify_task.cancel()
            self._verify_task = None

    @on(Button.Pressed, ".verify-btn")
    def _verify(self, event: Button.Pressed) -> None:
        event.stop()
        self.cancel_verification()
        self._verify_task = asyncio.create_task(self._run_verify(event.button))

    async def _run_verify(self, button: Button) -> None:
        from wifit3.campaigns.live_check import LiveKeyVerifier, VerifyStatus

        button.disabled = True
        button.label = "Verifying…"
        try:
            res = await LiveKeyVerifier().verify_credential(
                self.key.capture, self.app.array, target_type=self.key.capture_type)
            if res.status in (VerifyStatus.SUCCESS, VerifyStatus.INCORRECT):
                record_live_verification(self.key, correct=res.status == VerifyStatus.SUCCESS)
            severity = {VerifyStatus.SUCCESS: "information",
                        VerifyStatus.INCORRECT: "warning"}.get(res.status, "error")
            self.notify(res.body, title=res.title, severity=severity)
            if res.status in (VerifyStatus.SUCCESS, VerifyStatus.INCORRECT):
                self.app.vault.refresh()
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.exception("Error during live verification")
            self.notify(f"Verification error: {exc}", title="Verify", severity="error")
        finally:
            button.label = "Verify"
            button.disabled = False


class AddKeyPressed(Message):
    """The user asked to add a key to the AP in view."""


class _CapturePanel(VerticalGroup):
    DEFAULT_CSS = """
    _CapturePanel { height: auto; max-width: 81; }
    _CapturePanel Rule.-horizontal { margin: 0; color: $panel-lighten-2; }
    _CapturePanel Rule.uncracked-rule { margin-top: 1; }
    _CapturePanel .status { width: 100%; text-align: center; margin-top: 1; }
    _CapturePanel .ssids { height: auto; }
    _CapturePanel .section-line { height: 1; }
    _CapturePanel .section { text-style: bold; color: $text-muted; width: auto; margin-right: 2; }
    _CapturePanel .ssids .section { width: 4; }
    _CapturePanel .ssid { width: 1fr; text-wrap: nowrap; text-overflow: ellipsis; }
    _CapturePanel .dates { width: auto; color: $text-muted; margin-left: 1; }
    _CapturePanel .none-yet { color: $text-muted; padding-left: 2; }
    _CapturePanel .tools { height: auto; }
    _CapturePanel .tools Button { margin-right: 1; }
    _CapturePanel .selected-count, _CapturePanel .exhausted { color: $text-muted; }
    _CapturePanel .uncracked { height: auto; max-height: 8; scrollbar-size-vertical: 1; }
    _CapturePanel .row { height: 1; }
    _CapturePanel .row > * { margin-right: 1; text-wrap: nowrap; }
    _CapturePanel .row Checkbox { width: 3; text-overflow: clip; }
    _CapturePanel .row:focus-within { background: $block-hover-background; }
    _CapturePanel .row .date { width: 12; color: $text-muted; }
    _CapturePanel .row .pair { width: 5; }
    _CapturePanel .row .client { width: 6; color: $text-muted; }
    _CapturePanel .row .verdict { width: 10; }
    _CapturePanel .row .live { width: auto; }
    _CapturePanel .row .count { width: 4; color: $text-muted; }
    _CapturePanel .row .row-ssid { width: 1fr; text-overflow: ellipsis; }
    _CapturePanel .authorized, _CapturePanel .verified { color: $text-success; }
    _CapturePanel .challenge { color: $text-warning; }
    _CapturePanel .rejected { color: #ffaf00; }
    """

    def __init__(self, state: ApState, choices: Optional[_UserChoices]) -> None:
        super().__init__()
        self._state = state
        self._choices = choices
        self._groups = hashline_groups(state.uncracked)

    def compose(self) -> ComposeResult:
        state = self._state
        yield Static(Content.from_markup(self._status_markup()), classes="status")
        yield Rule()
        with Vertical(classes="ssids"):
            yield from self._compose_ssids()
            yield Rule()
        with Horizontal(classes="section-line"):
            yield Label("KEYS", classes="section")
            yield Button("Add key", compact=True, classes="add-key", tooltip="Add a PSK, WPS PIN or WEP key")
        for key in state.keys:
            yield _KeyRow(key, state, self._key_row_classes(key))
        if not state.keys:
            yield Label("none yet", classes="none-yet")
        if state.uncracked:
            yield Rule(classes="uncracked-rule")
            yield from self._compose_uncracked()

    def _key_row_classes(self, key: Key) -> str:
        choices = self._choices
        if choices is None:
            return ""
        if _key_id(key) in choices.expanded_keys:
            return "-expanded"
        return "-collapsed" if _key_id(key) in choices.collapsed_keys else ""

    def _status_markup(self) -> str:
        state = self._state
        status = (f"[bold {_STATUS_STYLE[state.status]}]{state.status.value}[/]")
        key = state.status_key
        if key is None:
            return status
        chip = f"[{_KEY_CHIP_STYLE[state.status]}] {_KEY_LABEL[key.capture_type]}: {escape(key_text(key))} [/]"
        return f"{chip} {status}"

    def _compose_ssids(self) -> ComposeResult:
        ssids = self._state.ssids
        if len(ssids) <= 1:
            with Horizontal(classes="section-line"):
                yield Label("SSID", classes="section")
                yield Label(ssids[0].ssid if ssids else "‹hidden›", classes="ssid", markup=False)
            return
        for i, history in enumerate(ssids):
            first, last = when(history.first_seen), when(history.last_seen)
            dates = first if first == last else f"{first} → {last}"
            with Horizontal(classes="section-line"):
                yield Label("" if i else "SSID", classes="section")
                yield Label(history.ssid, classes="ssid", markup=False)
                yield Label(dates, classes="dates")

    def _compose_uncracked(self) -> ComposeResult:
        state = self._state
        uncracked = state.uncracked
        with Horizontal(classes="section-line"):
            yield Label("UNCRACKED", classes="section")
            yield Label(f"[dim]({len(uncracked)}/{len(state.hashlines)} captures)[/]")
        unchecked = self._choices.unchecked_hashline_ids if self._choices else frozenset()
        checked = [not all(h.id in unchecked for h in group) for group in self._groups]
        selected = sum(len(group) for group, ticked in zip(self._groups, checked) if ticked)
        capture = state.hashline_capture
        crackers = [t for t in self.app.vault.manager.tools.values() if capture and t.can_crack(capture)]
        with Horizontal(classes="tools"):
            for tool in crackers:
                yield Button(tool.label, "primary", classes=f"tool-btn launch-tool-{tool.name}",
                             disabled=selected == 0)
        yield Label(self._selected_markup(selected), classes="selected-count")
        exhausted = exhausted_wordlist_names(state.bssid, [h.id for h in uncracked])
        if exhausted:
            names = [name if count == len(uncracked) else f"{name} ({count}/{len(uncracked)})"
                     for name, count in exhausted.items()]
            yield Static(f"exhausted: {escape(', '.join(names))}", classes="exhausted")
        with VerticalScroll(classes="uncracked"):
            for i, group in enumerate(self._groups):
                yield Horizontal(Checkbox("", checked[i], compact=True, id=f"hashlines-{i}"),
                                 *_hashline_columns(group, state), classes="row")

    @staticmethod
    def _selected_markup(count: int) -> str:
        return f"{count} capture{'' if count == 1 else 's'} selected to crack"

    def _selected_hashlines(self) -> list[str]:
        return [h.raw for i, group in enumerate(self._groups)
                if self.query_one(f"#hashlines-{i}", Checkbox).value for h in group]

    def user_choices(self, scroll_y: float) -> _UserChoices:
        """What the user expanded, collapsed and unticked, and where the pane and list are scrolled."""
        rows = list(self.query(_KeyRow).results(_KeyRow))
        unchecked = frozenset(h.id for i, group in enumerate(self._groups)
                              if not self.query_one(f"#hashlines-{i}", Checkbox).value for h in group)
        uncracked_scroll_y = next((w.scroll_y for w in self.query(".uncracked").results(VerticalScroll)), 0.0)
        return _UserChoices(frozenset(_key_id(r.key) for r in rows if r.has_class("-expanded")),
                            frozenset(_key_id(r.key) for r in rows if r.has_class("-collapsed")),
                            unchecked, scroll_y, uncracked_scroll_y)

    def restore_scroll(self) -> None:
        if self._choices is not None:
            for widget in self.query(".uncracked").results(VerticalScroll):
                widget.scroll_to(y=self._choices.uncracked_scroll_y, animate=False)

    @on(Checkbox.Changed)
    def _selection_changed(self, event: Checkbox.Changed) -> None:
        count = len(self._selected_hashlines())
        self.query_one(".selected-count", Label).update(self._selected_markup(count))
        for button in self.query(".tool-btn").results(Button):
            button.disabled = count == 0

    def cancel_verification(self) -> None:
        for row in self.query(_KeyRow):
            row.cancel_verification()

    @on(Button.Pressed, ".add-key")
    def _add_key(self, event: Button.Pressed) -> None:
        event.stop()
        self.post_message(AddKeyPressed())

    @on(Button.Pressed, ".tool-btn")
    def _launch_tool(self, event: Button.Pressed) -> None:
        event.stop()
        capture = self._state.hashline_capture
        tool_name = next((c.removeprefix("launch-tool-") for c in event.button.classes
                          if c.startswith("launch-tool-")), None)
        if capture is None or tool_name is None:
            return
        modal_cls = UI_TOOLS.get(tool_name)
        if not modal_cls:
            logger.error(f"Unable to launch tool: No entry in UI_TOOLS for {tool_name}")
            self.notify(f"No UI configured for tool: {tool_name}", severity="error")
            return
        hashlines = self._selected_hashlines()

        def _on_config(config: dict | None) -> None:
            if not config:
                return
            job_id = self.app.vault.manager.submit_job(
                tool_name, capture, self.app.vault.add_probed_ssids(config), hashlines=hashlines)
            self.notify(f"Queued job: {job_id}")

        self.app.push_screen(modal_cls(capture=capture, probed_ssids=self.app.vault.probed_ssids()),
                             _on_config)


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

    def __init__(self, id: Optional[str] = None) -> None:
        super().__init__(id=id)
        self._bssid = ""
        self._ssid: Optional[str] = None
        self._state: Optional[ApState] = None
        self._choices: Optional[_UserChoices] = None

    def cancel_verification(self) -> None:
        """Cancel any running live verification."""
        for panel in self.query(_CapturePanel):
            panel.cancel_verification()

    def load(self, bssid: str, ssid: Optional[str], captures: list[PersistedCapture]) -> None:
        """Show this AP; reloading the AP in view keeps what the user expanded, ticked and scrolled."""
        state = load_ap_state(bssid, captures) if bssid else None
        if (bssid, ssid, state) == (self._bssid, self._ssid, self._state):
            return
        panels = list(self.query(_CapturePanel).results(_CapturePanel))
        if bssid == self._bssid and panels:
            self._choices = panels[0].user_choices(self.scroll_y)
        else:
            self.cancel_verification()
            self._choices = None
        self._bssid, self._ssid, self._state = bssid, ssid, state
        self.refresh(recompose=True)

    async def recompose(self) -> None:
        await super().recompose()
        if self._choices is not None:
            self.call_after_refresh(self._restore_scroll, self._choices.scroll_y)

    def _restore_scroll(self, scroll_y: float) -> None:
        self.scroll_to(y=scroll_y, animate=False)
        for panel in self.query(_CapturePanel).results(_CapturePanel):
            panel.restore_scroll()

    def compose(self) -> ComposeResult:
        if self._state is None:
            self.border_title = "Vault Detail"
            yield Label("Select an AP to view its captures", id="vault-item-empty")
            return

        name = self._ssid or "‹hidden›"
        title = Content.from_markup(f"[$background bold on $primary] {escape(name)} [/]")
        title = title.append(Content.from_text(f" ({self._bssid}) "))
        self.border_title = title
        yield _CapturePanel(self._state, self._choices)
