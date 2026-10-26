from __future__ import annotations

import asyncio
import logging
import time
from itertools import groupby
from typing import Optional

from rich.markup import escape
from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalGroup, VerticalScroll
from textual.content import Content
from textual.events import Resize
from textual.message import Message
from textual.reactive import reactive
from textual.widgets import Button, Checkbox, Collapsible, Label, Rule, Static

from wifit3.campaigns.pin import EMPTY_PIN_LABEL
from wifit3.models import PersistedCapture
from wifit3.persist.crack_state import (
    CrackState,
    Hashline,
    Key,
    KeyKind,
    PasswordStatus,
    load_crack_state,
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
_KEY_LABEL = {KeyKind.PSK: "PSK", KeyKind.WPS: "PIN", KeyKind.WEP: "Key"}
_KEY_BADGE_STYLE = {KeyKind.PSK: "$text-success", KeyKind.WPS: "$text-accent", KeyKind.WEP: "$text-secondary"}
_AUTHORIZED_TOOLTIP = "authorized: PMKID or M3/M4, the AP accepted this password"
_CHALLENGE_TOOLTIP = "challenge: no M3/M4, could be a wrong password"
_COMPACT_TOOL_BUTTONS_BELOW = 60


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
    if key.kind == KeyKind.WEP:
        return _hex_to_ascii(key.value) or key.value
    if key.kind == KeyKind.WPS:
        return key.value or EMPTY_PIN_LABEL
    return key.value


def when(epoch: int) -> str:
    """``today 19:37``, ``Oct 22 19:37``, ``Oct 22 2025``; ``no date`` for 0."""
    if not epoch:
        return "no date"
    moment, now = time.localtime(epoch), time.localtime()
    if moment.tm_year != now.tm_year:
        return time.strftime("%b %d %Y", moment)
    if moment.tm_yday == now.tm_yday:
        return time.strftime("today %H:%M", moment)
    return time.strftime("%b %d %H:%M", moment)


def hashline_groups(hashlines: tuple[Hashline, ...]) -> list[list[Hashline]]:
    """Runs of hashlines from the same minute, message pair, client and SSID."""
    def same(h: Hashline) -> tuple:
        return h.first_captured // 60, h.pair_label, h.client, h.ssid, h.authorized
    return [list(group) for _, group in groupby(hashlines, same)]


def _hashline_row(group: list[Hashline], state: CrackState) -> Content:
    first = group[0]
    client = f" …{first.client}" if len({h.client for h in state.hashlines}) > 1 else ""
    verdict = "[$text-success]authorized[/]" if first.authorized else "[$text-warning]challenge[/]"
    times = f" [dim]×{len(group)}[/]" if len(group) > 1 else ""
    ssid = f" {escape(first.ssid)}" if len(state.ssids) > 1 else ""
    return Content.from_markup(
        f"[dim]{when(first.first_captured)}[/] {first.pair_label:5}{client} {verdict}{times}{ssid}")


class _KeyRow(VerticalGroup):
    DEFAULT_CSS = """
    _KeyRow { height: auto; }
    _KeyRow .key-line { height: 1; }
    _KeyRow .no-toggle { width: 3; }
    _KeyRow .key-text { width: 1fr; text-wrap: nowrap; text-overflow: ellipsis; }
    _KeyRow Button { margin-left: 1; }
    _KeyRow .history { height: auto; padding-left: 2; }
    _KeyRow .history-rows { height: auto; max-height: 8; scrollbar-size-vertical: 1; }
    _KeyRow .history-rows Static { text-wrap: nowrap; text-overflow: ellipsis; }
    """

    def __init__(self, key: Key, state: CrackState) -> None:
        super().__init__()
        self.key = key
        self._state = state
        self._verify_task: Optional[asyncio.Task] = None

    def _history(self) -> list[tuple[int, Content, Optional[str]]]:
        rows: list[tuple[int, Content, Optional[str]]] = [
            (v.at, Content.from_markup(
                f"[dim]{when(v.at)}[/] " + ("[$text-success]✓ verified live[/]" if v.correct
                                            else "[#ffaf00]✗ rejected live[/]")), None)
            for v in self.key.live_verifications]
        matched = tuple(h for h in self._state.hashlines if h.id in self.key.hashline_ids)
        for group in hashline_groups(matched):
            tooltip = _AUTHORIZED_TOOLTIP if group[0].authorized else _CHALLENGE_TOOLTIP
            rows.append((group[0].first_captured, _hashline_row(group, self._state), tooltip))
        return sorted(rows, key=lambda row: row[0], reverse=True)

    def compose(self) -> ComposeResult:
        history = self._history()
        with Horizontal(classes="key-line"):
            if history:
                yield Button("▶", compact=True, classes="toggle", tooltip="Show captures and verifications")
            else:
                yield Label("", classes="no-toggle")
            yield Label(Content.from_markup(self._summary_markup()), classes="key-text")
            yield Button("Copy", compact=True, classes="copy-btn")
            yield Button("Verify", compact=True, variant="primary", classes="verify-btn",
                         tooltip="Connect to the live AP and verify this key")
        if history:
            with Vertical(classes="history") as body:
                body.display = False
                with VerticalScroll(classes="history-rows"):
                    for _, row, tooltip in history:
                        static = Static(row)
                        static.tooltip = tooltip
                        yield static

    def _summary_markup(self) -> str:
        key = self.key
        markup = (f"[bold {_KEY_BADGE_STYLE[key.kind]}]{key.kind.value}[/] "
                  f"[black bold on lightgreen] {escape(key_text(key))} [/]")
        total = len(self._state.hashlines)
        if key.kind == KeyKind.PSK and total:
            markup += f" [dim]({len(key.hashline_ids)}/{total} captures)[/]"
            authorized = any(h.authorized for h in self._state.hashlines if h.id in key.hashline_ids)
            if not authorized and not any(v.correct for v in key.live_verifications):
                markup += " [#ffaf00]unverified[/]"
        return markup

    @on(Button.Pressed, ".toggle")
    def _toggle(self, event: Button.Pressed) -> None:
        event.stop()
        body = self.query_one(".history")
        body.display = not body.display
        event.button.label = "▼" if body.display else "▶"

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
                self.key.capture, self.app.array, target_type=self.key.verify_type)
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
    _CapturePanel .status { width: 100%; text-align: center; }
    _CapturePanel .section-line { height: 1; }
    _CapturePanel .section { text-style: bold; color: $text-muted; width: auto; margin-right: 2; }
    _CapturePanel .ssid { width: 1fr; text-wrap: nowrap; text-overflow: ellipsis; }
    _CapturePanel .dates { width: auto; color: $text-muted; margin-left: 1; }
    _CapturePanel Collapsible { padding: 0; border: none; background: transparent; }
    _CapturePanel Collapsible > Contents { padding: 0 0 0 2; }
    _CapturePanel .none-yet { color: $text-muted; padding-left: 2; }
    _CapturePanel .tools { height: auto; }
    _CapturePanel .tools Button { margin-right: 1; }
    _CapturePanel .selected-count, _CapturePanel .exhausted { color: $text-muted; }
    _CapturePanel .uncracked { height: auto; max-height: 8; scrollbar-size-vertical: 1; }
    _CapturePanel Checkbox { width: 100%; }
    """

    def __init__(self, state: CrackState) -> None:
        super().__init__()
        self._state = state
        self._groups = hashline_groups(state.uncracked)

    def compose(self) -> ComposeResult:
        state = self._state
        yield Static(Content.from_markup(self._status_markup()), classes="status")
        yield Rule()
        yield from self._compose_ssids()
        yield Rule()
        with Horizontal(classes="section-line"):
            yield Label("KEYS", classes="section")
            yield Button("Add key", compact=True, classes="add-key", tooltip="Add a PSK, WPS PIN or WEP key")
        for key in state.keys:
            yield _KeyRow(key, state)
        if not state.keys:
            yield Label("none yet", classes="none-yet")
        if state.uncracked:
            yield Rule()
            yield from self._compose_uncracked()

    def _status_markup(self) -> str:
        state = self._state
        status = (f"[bold {_STATUS_STYLE[state.status]}]{state.status.value}[/]")
        key = state.status_key
        if key is None:
            return status
        chip = f"[{_KEY_CHIP_STYLE[state.status]}] {_KEY_LABEL[key.kind]}: {escape(key_text(key))} [/]"
        return f"{chip} {status}"

    def _compose_ssids(self) -> ComposeResult:
        ssids = self._state.ssids
        if len(ssids) <= 1:
            with Horizontal(classes="section-line"):
                yield Label("SSID", classes="section")
                yield Label(escape(ssids[0].ssid) if ssids else "‹hidden›", classes="ssid")
            return
        with Collapsible(title=f"SSIDs ({len(ssids)}): {ssids[0].ssid}", collapsed=True):
            for i, span in enumerate(ssids):
                with Horizontal(classes="section-line"):
                    yield Label(escape(span.ssid), classes="ssid")
                    if i:
                        yield Label(f"{when(span.first_seen)} → {when(span.last_seen)}", classes="dates")

    def _compose_uncracked(self) -> ComposeResult:
        state = self._state
        uncracked = state.uncracked
        with Horizontal(classes="section-line"):
            yield Label("UNCRACKED", classes="section")
            yield Label(f"[dim]({len(uncracked)}/{len(state.hashlines)} captures)[/]")
        capture = state.hashline_capture
        crackers = [t for t in self.app.vault.manager.tools.values() if capture and t.can_crack(capture)]
        with Horizontal(classes="tools"):
            for tool in crackers:
                yield Button(tool.label, "primary", classes=f"tool-btn launch-tool-{tool.name}")
        yield Label(self._selected_markup(len(uncracked)), classes="selected-count")
        exhausted = exhausted_wordlist_names(state.bssid, [h.id for h in uncracked])
        if exhausted:
            names = [name if count == len(uncracked) else f"{name} ({count}/{len(uncracked)})"
                     for name, count in exhausted.items()]
            yield Static(f"exhausted: {escape(', '.join(names))}", classes="exhausted")
        with VerticalScroll(classes="uncracked"):
            for i, group in enumerate(self._groups):
                tooltip = _AUTHORIZED_TOOLTIP if group[0].authorized else _CHALLENGE_TOOLTIP
                yield Checkbox(_hashline_row(group, state), True, compact=True, id=f"hashlines-{i}",
                               tooltip=tooltip)

    @staticmethod
    def _selected_markup(count: int) -> str:
        return f"{count} capture{'' if count == 1 else 's'} selected to crack"

    def _selected_hashlines(self) -> list[str]:
        return [h.raw for i, group in enumerate(self._groups)
                if self.query_one(f"#hashlines-{i}", Checkbox).value for h in group]

    def on_resize(self, event: Resize) -> None:
        for button in self.query(".tool-btn").results(Button):
            button.compact = event.size.width < _COMPACT_TOOL_BUTTONS_BELOW

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

    _state: reactive[tuple] = reactive(("", None, ()), recompose=True)

    def cancel_verification(self) -> None:
        """Cancel any running live verification."""
        for panel in self.query(_CapturePanel):
            panel.cancel_verification()

    def load(self, bssid: str, ssid: Optional[str], captures: list[PersistedCapture]) -> None:
        self.cancel_verification()
        self._state = (bssid, ssid, tuple(captures))

    def compose(self) -> ComposeResult:
        bssid, ssid, captures = self._state
        if not bssid:
            self.border_title = "Vault Detail"
            yield Label("Select an AP to view its captures", id="vault-item-empty")
            return

        name = ssid or "‹hidden›"
        title = Content.from_markup(f"[$background bold on $primary] {escape(name)} [/]")
        title = title.append(Content.from_text(f" ({bssid}) "))
        self.border_title = title
        yield _CapturePanel(load_crack_state(bssid, list(captures)))
