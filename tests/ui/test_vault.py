"""Vault drawer overlay and VaultItemView detail pane, driven through a real WifiteApp.
The autouse _captures_to_tmp fixture points Config.captures_dir at tmp_path, and WifiteApp builds its Vault from there.
"""
import asyncio
import os

import pytest
from textual.containers import VerticalScroll
from textual.widgets import Button, Checkbox, DataTable, Input, Label, Static

from wifit3.campaigns.live_check import LiveKeyVerifier, VerifyResult, VerifyStatus
from wifit3.models import AccessPoint, CaptureType, PersistedCapture, ToolName
from wifit3.models.jobs import JobState, ToolStatus
from wifit3.persist.ap_state import PasswordStatus
from wifit3.persist.meta import meta_path, read_meta, update_meta
from wifit3.persist.save import SaveResult
from wifit3.ui.app import WifiteApp
from wifit3.ui.screens.vault_drawer import VaultDrawer
from wifit3.ui.screens.vault_item import VaultItemView, _ApStatePanel, _CrackerButton, _HashlineGroupCheckbox, _KeyRow
from wifit3.ui.vault.modals.add_credential import AddCredentialModal, ManualCredential
from wifit3.ui.vault.modals.confirm import ConfirmModal
from wifit3.ui.vault.modals.nickname import NicknameModal
from tests.hashline_dates import write_hashline_dates

_EAPOL_LINE = ("WPA*02*" + "0" * 32 + "*aabbccddeeff*112233445566*5465737431*" + "a" * 64 + "*"
               + "00" * 99 + "*02\n")
_PMKID_LINE = "WPA*01*" + "0" * 32 + "*aabbccddeeff*112233445566*5465737431***\n"
_WEP_TXT = "SSID: HomeNet\nBSSID: aa:bb:cc:dd:ee:ff\nWEP key (hex):   6162636465\n"
_LONG_WEP_TXT = "SSID: HomeNet\nBSSID: aa:bb:cc:dd:ee:ff\nWEP key (hex):   " + "61" * 26 + "\n"

def _write(d, name, content):
    (d / name).write_text(content, encoding="utf-8")

async def _open_vault(app, pilot, bssid: str | None = None) -> VaultDrawer:
    """Push the drawer and wait until it has laid out its content and slid open."""
    await app.push_screen(VaultDrawer(bssid))
    drawer = app.screen
    while not drawer.has_class("open"):
        await pilot.pause()
    await pilot.wait_for_animation()
    return drawer


class _RecordingApp(WifiteApp):
    """Records what it copies (never touching the system clipboard) and each notification."""

    def __init__(self) -> None:
        super().__init__()
        self.copied: list[str] = []
        self.notified: list[str] = []

    def copy_to_clipboard(self, text: str) -> None:
        self.copied.append(text)

    def notify(self, message, *args, **kwargs) -> None:
        self.notified.append(str(message))
        super().notify(message, *args, **kwargs)


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
@pytest.mark.parametrize(("height", "full_screen"), [(35, True), (36, False)])
async def test_short_vault_uses_full_screen(height, full_screen):
    app = WifiteApp()
    async with app.run_test(size=(100, height)) as pilot:
        view = await _open_vault(app, pilot)
        content = view.query_one("#vault-content")

        assert (content.region.height == view.size.height) is full_screen


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
@pytest.mark.parametrize(("width", "stacked"), [(104, True), (105, False)])
async def test_narrow_vault_stacks_ap_list_above_details(width, stacked):
    app = WifiteApp()
    async with app.run_test(size=(width, 40)) as pilot:
        view = await _open_vault(app, pilot)
        table = view.query_one("#vault-table").region
        item = view.query_one("#vault-item").region

        if stacked:
            assert table.x == item.x
            assert table.width == item.width == width
            assert table.bottom == item.y
        else:
            assert table.y == item.y
            assert table.right == item.x


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_toast_on_job_completion(tmp_path):
    from unittest.mock import patch
    from wifit3.models.jobs import JobState, ToolStatus

    def make(status, msg):
        return JobState(job_id="j1", tool_name="hashcat", capture_path="x", hashlines_path="x",
                        status=status, progress_msg=msg, display_name="hashcat (ASUS)")

    app = WifiteApp()
    async with app.run_test():
        job = make(ToolStatus.RUNNING, "Running (5%)")
        app.active_jobs = [job]
        with patch.object(app, "notify") as notify:
            app._notify_completions()          # first sight: record RUNNING, no toast
            notify.assert_not_called()
            job.status = ToolStatus.SUCCESS
            job.progress_msg = "Cracked! Key: 0xdeadbeef"
            job.key = "0xdeadbeef"
            app._notify_completions()          # RUNNING -> SUCCESS: toast
            assert notify.call_count == 1
            args, kwargs = notify.call_args
            assert "PSK: 0xdeadbeef" in args[0]
            assert kwargs["title"] == "hashcat (ASUS)"

        # A job already terminal when first seen is not announced.
        app.active_jobs = [JobState(job_id="j2", tool_name="hashcat", capture_path="y", hashlines_path="y",
                                    status=ToolStatus.SUCCESS, progress_msg="Cracked! Key: k",
                                    display_name="hashcat (X)")]
        with patch.object(app, "notify") as notify2:
            app._notify_completions()
            notify2.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
@pytest.mark.parametrize("status", [ToolStatus.FAILURE, ToolStatus.STOPPED, ToolStatus.ERROR])
async def test_an_automatic_job_that_finds_no_key_is_not_toasted(tmp_path, status):
    from unittest.mock import patch

    app = WifiteApp()
    async with app.run_test():
        job = JobState(job_id="j1", tool_name="cpu_crack", capture_path="x", hashlines_path="x",
                       status=ToolStatus.RUNNING, progress_msg="Running", auto_crack=True)
        app.active_jobs = [job]
        with patch.object(app, "notify") as notify:
            app._notify_completions()
            job.status = status
            app._notify_completions()
            notify.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_an_automatic_job_success_toasts_and_posts_job_cracked_to_the_screen(tmp_path):
    from unittest.mock import patch

    app = WifiteApp()
    async with app.run_test():
        job = JobState(job_id="j1", tool_name="cpu_crack", capture_path="x", hashlines_path="x",
                       status=ToolStatus.RUNNING, progress_msg="Running", auto_crack=True)
        app.active_jobs = [job]
        with patch.object(app, "notify") as notify, \
                patch.object(app.screen, "post_message") as post_message:
            app._notify_completions()
            job.status = ToolStatus.SUCCESS
            job.key = "password1"
            app._notify_completions()
            assert "PSK: password1" in notify.call_args.args[0]
            posted = post_message.call_args.args[0]
            assert isinstance(posted, WifiteApp.JobCracked) and posted.job is job


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_vault_keeps_emoji_named_mac_octets_literal(tmp_path):
    _write(tmp_path, "HomeNet_aa-cd-11-22-33-44_1000_wep_key.txt", _WEP_TXT)
    _write(tmp_path, "HomeNet_bb-cc-11-22-33-44_1000_wep_key.txt", _WEP_TXT)
    app = WifiteApp()
    async with app.run_test() as pilot:
        view = await _open_vault(app, pilot)
        cell = view.query_one("#vault-aps", DataTable).get_row("aa:cd:11:22:33:44")[0]

        assert cell.plain == "HomeNet ✓WEP aa:cd:11:22:33:44"
        assert "💿" not in cell.plain
        title = view.query_one("VaultItemView")._border_title
        assert title.plain == " HomeNet  (aa:cd:11:22:33:44) "
        assert all(span.end <= title.plain.index("aa:cd") for span in title.spans)


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_open_vault_focuses_ap_list_and_search_returns_to_it(tmp_path):
    _write(tmp_path, "HomeNet_aa-bb-cc-dd-ee-ff_1000_wep_key.txt", _WEP_TXT)
    _write(tmp_path, "Cafe_11-22-33-44-55-66_1000_wep_key.txt", _WEP_TXT)
    app = WifiteApp()
    async with app.run_test() as pilot:
        view = await _open_vault(app, pilot)
        table = view.query_one("#vault-aps", DataTable)
        search = view.query_one("#vault-search", Input)
        assert app.focused is table

        await pilot.press("f")
        assert app.focused is search
        await pilot.press("h", "o", "m", "e")
        await pilot.pause(0)
        assert search.value == "home" and table.row_count == 1
        await pilot.press("escape")
        assert app.focused is table and app.screen is view

        await pilot.press("/")
        assert app.focused is search
        await pilot.press("backspace", "backspace", "backspace", "backspace", "enter")
        await pilot.pause(0)
        assert app.focused is table and table.row_count == 2

        await pilot.press("escape")
        await pilot.pause(0.4)
        assert app.screen is not view


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_nickname_shows_in_the_row_and_title_and_n_edits_it(tmp_path):
    _write(tmp_path, "HomeNet_aa-bb-cc-dd-ee-ff_1000_wep_key.txt", _WEP_TXT)
    _write(tmp_path, "Other_11-22-33-44-55-66_1000_wep_key.txt", _WEP_TXT)
    update_meta("HomeNet", "aa:bb:cc:dd:ee:ff", nickname="Upstairs")
    app = WifiteApp()
    async with app.run_test() as pilot:
        view = await _open_vault(app, pilot)
        table = view.query_one("#vault-aps", DataTable)
        assert table.get_row_at(0)[0].plain == "Upstairs (HomeNet) ✓WEP"
        assert view.query_one("VaultItemView")._border_title.plain.startswith(" Upstairs (HomeNet)")

        await pilot.press("n")
        await pilot.pause(0)
        assert isinstance(app.screen, NicknameModal)
        assert app.screen.query_one("#nickname", Input).value == "Upstairs"
        app.screen.query_one("#nickname", Input).value = "[Den]"
        await pilot.press("enter")
        await pilot.pause(0)
        assert app.screen is view
        assert read_meta(meta_path("HomeNet", "aa:bb:cc:dd:ee:ff"))["nickname"] == "[Den]"
        assert table.get_row_at(0)[0].plain == "[Den] (HomeNet) ✓WEP"

        assert table.row_count == 2
        await pilot.press("f", "d", "e", "n")
        await pilot.pause(0)
        assert table.row_count == 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_show_directory_warns_when_there_are_no_captures_yet(tmp_path, mocker):
    app = WifiteApp()
    async with app.run_test() as pilot:
        view = await _open_vault(app, pilot)
        mocker.patch.object(app.vault, "open_directory", side_effect=FileNotFoundError)
        notify = mocker.patch.object(view, "notify")

        view.action_show_directory()

        notify.assert_called_once_with("No captures yet", severity="warning")


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
@pytest.mark.parametrize(("answer", "deleted"), [("#yes", True), ("#no", False)])
async def test_d_asks_then_deletes_every_file_of_the_selected_ap(tmp_path, answer, deleted):
    _write(tmp_path, "HomeNet_aa-bb-cc-dd-ee-ff_1000_wep_key.txt", _WEP_TXT)
    _write(tmp_path, "HomeNet_aa-bb-cc-dd-ee-ff.hc22000", _PMKID_LINE)
    app = _RecordingApp()
    async with app.run_test(size=(100, 40)) as pilot:
        drawer = await _open_vault(app, pilot, "aa:bb:cc:dd:ee:ff")
        await pilot.press("d")
        await pilot.pause()
        assert isinstance(app.screen, ConfirmModal)
        assert "Delete HomeNet? 1 capture, 1 key" in str(app.screen.query_one("#prompt", Label).content)
        await pilot.click(answer)
        await pilot.pause()

        assert app.screen is drawer
        assert (drawer.query_one("#vault-aps", DataTable).row_count == 0) is deleted
        assert (list(tmp_path.glob("HomeNet_*")) == []) is deleted
        assert ("Deleted HomeNet" in app.notified) is deleted


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_add_credential_prefills_the_row_and_saves_a_psk_the_capture_refutes_as_stale(
        tmp_path, mocker):
    _write(tmp_path, "HomeNet_aa-bb-cc-dd-ee-ff.hc22000", _PMKID_LINE)
    write_hashline_dates("HomeNet", "aa:bb:cc:dd:ee:ff", {_PMKID_LINE: 1_700_000_000})
    app = WifiteApp()
    async with app.run_test() as pilot:
        view = await _open_vault(app, pilot)
        notify = mocker.patch.object(view, "notify")

        await pilot.press("a")
        await pilot.pause(0)
        modal = app.screen
        assert isinstance(modal, AddCredentialModal)
        assert modal.query_one("#ssid", Input).value == "HomeNet"
        assert modal.query_one("#bssid", Input).value == "aa:bb:cc:dd:ee:ff"
        modal.query_one("#value", Input).focus()
        modal.query_one("#value", Input).value = "wrongpass"
        await pilot.press("enter")
        await pilot.pause(0)

        assert app.screen is view
        assert notify.call_args.args[0] == "PSK doesn't match the saved captures; added unverified"
        assert notify.call_args.kwargs["severity"] == "warning"
        assert [c.value for c in app.vault.persisted("aa:bb:cc:dd:ee:ff")
                if c.type == CaptureType.WPA_PSK] == ["wrongpass"]
        state = app.vault.ap_state("aa:bb:cc:dd:ee:ff")
        assert (state.status, state.status_key) == (PasswordStatus.STALE, None)
        assert app.vault.known_psk(AccessPoint(bssid="aa:bb:cc:dd:ee:ff")) is None   # refuted, not held

        verify = mocker.patch.object(app.vault, "verify_wpa_psk", return_value=True)
        propagate = mocker.patch.object(app.vault, "propagate_verified_psk",
                                        return_value=["02:00:00:00:00:10"])
        view._credential_added(ManualCredential(CaptureType.WPA_PSK, "HomeNet",
                                                "aa:bb:cc:dd:ee:ff", "rightpass"))
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert "rightpass" in {c.value for c in app.vault.persisted("aa:bb:cc:dd:ee:ff")}
        propagate.assert_called_once_with("aa:bb:cc:dd:ee:ff", "HomeNet", "rightpass")
        assert [c.args[0] for c in notify.call_args_list[-2:]] == [
            "Credential verified and added to Vault",
            "PSK also verified and saved for 1 related APs"]

        verify.return_value = None
        view._credential_added(ManualCredential(CaptureType.WPA_PSK, "HomeNet",
                                                "aa:bb:cc:dd:ee:ff", "uncheckable"))
        assert notify.call_args.args == ("Credential added to Vault",)

        view._credential_added(ManualCredential(CaptureType.WPS_PIN, "Other",
                                                "02:00:00:00:00:20", "1234"))
        pin = app.vault.persisted("02:00:00:00:00:20")[0]
        assert pin.pin == "1234" and pin.value is None



@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_a_wep_key_shows_and_copies_as_ascii_and_is_the_current_password(tmp_path):
    _write(tmp_path, "HomeNet_aa-bb-cc-dd-ee-ff_1000_wep_key.txt", _WEP_TXT)
    app = _RecordingApp()
    async with app.run_test(size=(50, 30)) as pilot:
        view = await _open_vault(app, pilot)
        row = view.query_one(_KeyRow)

        assert "abcde" in str(row.query_one(".key-text", Label).content)
        assert row.has_class("-current")
        assert "CURRENT PASSWORD" in str(view.query_one(".status", Static).content)
        assert "Key: abcde" in str(view.query_one(".status", Static).content)
        row.copy_button.press()
        await pilot.pause()
        assert app.copied == ["abcde"]


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
@pytest.mark.parametrize("pin", [None, "12345670"])
async def test_a_wps_recovered_psk_is_the_current_password_on_the_chip(tmp_path, pin):
    app = WifiteApp()
    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", ssid="HomeNet")
    if pin is None:
        app.vault.save_wps_pbc(ap, "hunter22")
    else:
        app.vault.save_wps_pin(ap, pin, "hunter22")
    async with app.run_test(size=(80, 40)) as pilot:
        view = await _open_vault(app, pilot)

        status = str(view.query_one(".status", Static).content)
        assert "PSK: hunter22" in status and "CURRENT PASSWORD" in status
        keys = [row.key for row in view.query(_KeyRow).results(_KeyRow)]
        assert sorted((k.type, k.value) for k in keys) == sorted(
            [(CaptureType.WPA_PSK, "hunter22")] + ([(CaptureType.WPS_PIN, pin)] if pin else []))


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_a_long_wep_key_ellipsizes_without_pushing_copy_and_verify_off_the_pane(tmp_path):
    _write(tmp_path, "HomeNet_aa-bb-cc-dd-ee-ff_1000_wep_key.txt", _LONG_WEP_TXT)
    app = WifiteApp()
    async with app.run_test(size=(50, 30)) as pilot:
        view = await _open_vault(app, pilot)
        panel = view.query_one(_ApStatePanel)
        for button in view.query_one(_KeyRow).query(Button).results(Button):
            assert button.region.right <= panel.content_region.right


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_open_vault_updates_when_handshake_is_saved(tmp_path, mocker):
    app = WifiteApp()
    async with app.run_test() as pilot:
        view = await _open_vault(app, pilot)
        table = view.query_one("#vault-aps", DataTable)
        assert table.row_count == 0

        capture_path = tmp_path / "HomeNet_aa-bb-cc-dd-ee-ff.hc22000"
        mocker.patch(
            "wifit3.persist.vault.save.save_handshake",
            return_value=SaveResult(capture_path, was_new=True),
        )
        app.vault.save_handshake(
            AccessPoint(bssid="aa:bb:cc:dd:ee:ff", ssid="HomeNet"),
            "11:22:33:44:55:66",
        )

        await pilot.pause()
        assert table.row_count == 1
        assert "✓HS" in str(table.get_row_at(0)[0])


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_rapid_selection_shows_the_final_ap(tmp_path):
    for index, name in enumerate(("Alpha", "Bravo", "Charlie")):
        bssid = f"00-11-22-33-44-{index:02x}"
        _write(tmp_path, f"{name}_{bssid}_1000_wep_key.txt",
               f"SSID: {name}\nBSSID: {bssid.replace('-', ':')}\nWEP key (hex): 6162\n")
    app = WifiteApp()
    async with app.run_test() as pilot:
        drawer = await _open_vault(app, pilot)
        table = drawer.query_one("#vault-aps", DataTable)
        item = drawer.query_one(VaultItemView)

        table.move_cursor(row=0)
        table.move_cursor(row=1)
        table.move_cursor(row=2)
        while "Charlie" not in str(item.border_title):
            await pilot.pause()

        assert "(00:11:22:33:44:02)" in str(item.border_title)


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_selection_restored_after_reload(tmp_path):
    _write(tmp_path, "Alpha_aa-bb-cc-dd-ee-ff_1000_wep_key.txt",
           "SSID: Alpha\nBSSID: aa:bb:cc:dd:ee:ff\nWEP key (hex): 6162\n")
    _write(tmp_path, "Bravo_11-22-33-44-55-66_1000_wep_key.txt",
           "SSID: Bravo\nBSSID: 11:22:33:44:55:66\nWEP key (hex): 6364\n")
    app = WifiteApp()
    async with app.run_test() as pilot:
        app.push_screen(VaultDrawer("11:22:33:44:55:66"))
        await pilot.pause()
        table = app.screen.query_one("#vault-aps", DataTable)
        assert table.row_count == 2

        def cursor_bssid() -> str:
            return table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value

        assert cursor_bssid() == "11:22:33:44:55:66"

        table.move_cursor(row=0)
        await pilot.pause(0)
        app.screen.query_one("#vault-table").reload_table()
        await pilot.pause(0)
        assert cursor_bssid() == "aa:bb:cc:dd:ee:ff"


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
@pytest.mark.parametrize("width", [80, 100, 120])
async def test_a_hashline_capture_offers_each_cracker_by_its_label(tmp_path, width):
    from wifit3.ui.vault.modals.cpu_crack import CpuCrackConfigModal

    _write(tmp_path, "HomeNet_aa-bb-cc-dd-ee-ff.hc22000", _EAPOL_LINE)
    app = WifiteApp()
    async with app.run_test(size=(width, 40)) as pilot:
        view = await _open_vault(app, pilot)
        bssid = "aa:bb:cc:dd:ee:ff"
        view.query_one("VaultItemView").load(bssid, app.vault.ssid(bssid))
        await pilot.pause(0)

        panel = view.query_one(_ApStatePanel)
        buttons = list(panel.query(_CrackerButton).results(_CrackerButton))
        assert [str(b.label) for b in buttons] == ["Hashcat", "CPU Crack", "Hashtopolis"]
        assert [(str(b.label), b.region.right) for b in panel.query(Button).results(Button) if b.region.right > panel.content_region.right] == []

        buttons[1].press()
        await pilot.pause(0)
        assert isinstance(app.screen, CpuCrackConfigModal)


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
@pytest.mark.parametrize(("width", "height"), [(40, 1), (80, 3)])
async def test_cracker_buttons_are_one_line_on_one_row_only_in_a_tiny_drawer(tmp_path, width, height):
    _write(tmp_path, "HomeNet_aa-bb-cc-dd-ee-ff.hc22000", _EAPOL_LINE)
    app = WifiteApp()
    async with app.run_test(size=(width, 40)) as pilot:
        view = await _open_vault(app, pilot)

        buttons = list(view.query(_CrackerButton).results(_CrackerButton))
        assert [str(button.label) for button in buttons] == ["Hashcat", "CPU Crack", "Hashtopolis"]
        assert [button.region.height for button in buttons] == [height] * 3
        assert buttons[0].region.y == buttons[1].region.y == buttons[2].region.y


_OTHER_CLIENT_LINE = _EAPOL_LINE.replace("112233445566", "112233445577")
_LIVE_CHECK = {"kind": "WEP", "key": "6162636465", "correct": True}


def _write_a_checked_wep_key_and_three_hashlines(tmp_path) -> None:
    _write(tmp_path, "HomeNet_aa-bb-cc-dd-ee-ff.hc22000", _EAPOL_LINE + _OTHER_CLIENT_LINE + _PMKID_LINE)
    _write(tmp_path, "HomeNet_aa-bb-cc-dd-ee-ff_1000_wep_key.txt", _WEP_TXT)
    _write(tmp_path, "Cafe_02-00-00-00-00-01_1000_wep_key.txt", _WEP_TXT.replace("aa:bb:cc:dd:ee:ff", "02:00:00:00:00:01"))
    update_meta("HomeNet", "aa:bb:cc:dd:ee:ff", live_verifications=[{**_LIVE_CHECK, "at": 1000}])


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_a_refresh_shows_the_new_state_and_keeps_expansion_ticks_and_scroll(tmp_path):
    _write_a_checked_wep_key_and_three_hashlines(tmp_path)
    app = WifiteApp()
    async with app.run_test(size=(80, 40)) as pilot:
        drawer = await _open_vault(app, pilot, "aa:bb:cc:dd:ee:ff")
        item = drawer.query_one("#vault-item")
        drawer.query_one(_KeyRow).toggle_button.press()
        drawer.query(_HashlineGroupCheckbox).first(_HashlineGroupCheckbox).value = False
        await pilot.pause()
        scrolled = item.max_scroll_y
        assert scrolled > 0
        item.scroll_to(y=scrolled, animate=False)
        await pilot.pause()

        update_meta("HomeNet", "aa:bb:cc:dd:ee:ff",
                    live_verifications=[{**_LIVE_CHECK, "at": 1000}, {**_LIVE_CHECK, "at": 2000}])
        app.vault.refresh()
        await pilot.pause()

        row = drawer.query_one(_KeyRow)
        assert row.has_class("-expanded")
        assert len(row.query(".row")) == 2
        assert [c.value for c in drawer.query(Checkbox).results(Checkbox)] == [False, True, True]
        assert "2 captures selected" in str(drawer.query_one(".selected-count", Label).content)
        assert item.scroll_y == scrolled


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_another_aps_capture_leaves_the_pane_alone(tmp_path):
    _write_a_checked_wep_key_and_three_hashlines(tmp_path)
    app = WifiteApp()
    async with app.run_test(size=(80, 40)) as pilot:
        drawer = await _open_vault(app, pilot, "aa:bb:cc:dd:ee:ff")
        table = drawer.query_one("#vault-aps", DataTable)
        checkbox = drawer.query(_HashlineGroupCheckbox).last(_HashlineGroupCheckbox)
        checkbox.focus()
        drawer.query_one(_KeyRow).toggle_button.press()
        await pilot.pause()

        app.vault.save_wpa_psk("Cafe", "02:00:00:00:00:01", "cafepass")
        await pilot.pause()

        assert "✓PSK" in str(table.get_row("02:00:00:00:00:01")[0])
        assert app.focused is checkbox
        assert drawer.query_one(_KeyRow).expanded


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_only_the_verdict_carries_the_tooltip(tmp_path):
    _write_a_checked_wep_key_and_three_hashlines(tmp_path)
    app = WifiteApp()
    async with app.run_test(size=(80, 40)) as pilot:
        drawer = await _open_vault(app, pilot, "aa:bb:cc:dd:ee:ff")
        rows = list(drawer.query(".uncracked .row"))

        assert [str(row.query_one(".verdict").tooltip) for row in rows] == [
            "PMKID or M3/M4: the AP accepted this password"] * 3
        assert all(row.tooltip is None and row.query_one(".date").tooltip is None for row in rows)


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_unchecked_hashlines_are_left_out_of_the_crack_job(tmp_path, mocker):
    _write(tmp_path, "HomeNet_aa-bb-cc-dd-ee-ff.hc22000", _EAPOL_LINE + _OTHER_CLIENT_LINE + _PMKID_LINE)
    app = WifiteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        view = await _open_vault(app, pilot)
        submit = mocker.patch.object(app.vault.manager, "submit_job", return_value="job")
        panel = view.query_one(_ApStatePanel)
        checkboxes = list(panel.query(_HashlineGroupCheckbox).results(_HashlineGroupCheckbox))
        assert len(checkboxes) == 3
        assert "3 captures selected to crack" in str(panel.query_one(".selected-count", Label).content)

        checkboxes[0].value = False
        await pilot.pause(0)
        assert "2 captures selected to crack" in str(panel.query_one(".selected-count", Label).content)
        next(b for b in panel.query(_CrackerButton).results(_CrackerButton) if b.tool.name == "cpu_crack").press()
        await pilot.pause()
        app.screen.dismiss({"wordlists": []})
        await pilot.pause()

        chosen = submit.call_args.kwargs["hashlines"]
        assert len(chosen) == 2 and checkboxes[0].group[0].raw not in chosen

        for checkbox in checkboxes:
            checkbox.value = False
        await pilot.pause(0)
        assert all(button.disabled for button in panel.query(_CrackerButton).results(_CrackerButton))


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
@pytest.mark.parametrize(("size", "expanded", "ssid_shown"), [((160, 50), True, True), ((80, 40), False, False)])
async def test_a_tall_wide_drawer_starts_key_histories_expanded_and_shows_the_ssid(
        tmp_path, size, expanded, ssid_shown):
    _write_a_checked_wep_key_and_three_hashlines(tmp_path)
    app = WifiteApp()
    async with app.run_test(size=size) as pilot:
        drawer = await _open_vault(app, pilot, "aa:bb:cc:dd:ee:ff")
        history = drawer.query_one(_KeyRow).query_one(".history")
        assert history.display is expanded
        assert drawer.query_one(".ssids").display is ssid_shown

        drawer.query_one(_KeyRow).toggle_button.press()
        await pilot.pause()
        assert history.display is not expanded


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_a_burst_of_vault_changes_reloads_the_table_once(mocker):
    app = WifiteApp()
    async with app.run_test(size=(100, 40)) as pilot:
        drawer = await _open_vault(app, pilot)
        table = drawer.query_one("#vault-table")
        reload_table = mocker.patch.object(table, "reload_table", wraps=table.reload_table)

        for bssid in ("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:01"):
            app.vault.notify_changed(bssid)
        await pilot.pause()

        assert reload_table.call_count == 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_a_vault_change_from_another_thread_reloads_the_table(mocker):
    app = WifiteApp()
    async with app.run_test(size=(100, 40)) as pilot:
        drawer = await _open_vault(app, pilot)
        table = drawer.query_one("#vault-table")
        reload_table = mocker.patch.object(table, "reload_table", wraps=table.reload_table)

        await asyncio.to_thread(app.vault.notify_changed, "aa:bb:cc:dd:ee:01")
        await pilot.pause()

        assert reload_table.call_count == 1


class _HeldVerifier(LiveKeyVerifier):
    """Answers SUCCESS once ``release`` is set; records each capture it was asked to check."""

    def __init__(self) -> None:
        self.release = asyncio.Event()
        self.checked: list[PersistedCapture] = []
        self.cancelled = False

    async def verify_credential(self, capture, array, target_type=None) -> VerifyResult:
        self.checked.append(capture)
        try:
            await self.release.wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        return VerifyResult(VerifyStatus.SUCCESS, "Verified", "still works")


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_one_live_check_runs_at_a_time_even_across_a_refresh(tmp_path):
    _write_a_checked_wep_key_and_three_hashlines(tmp_path)
    app = WifiteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        app.vault.save_wpa_psk("HomeNet", "aa:bb:cc:dd:ee:ff", "hunter22")
        drawer = await _open_vault(app, pilot, "aa:bb:cc:dd:ee:ff")
        verifier = _HeldVerifier()
        drawer.query_one(VaultItemView).key_verifier = verifier
        rows = list(drawer.query(_KeyRow).results(_KeyRow))
        assert len(rows) == 2

        rows[0].verify_button.press()
        await pilot.pause()
        update_meta("HomeNet", "aa:bb:cc:dd:ee:ff",
                    live_verifications=[{**_LIVE_CHECK, "at": 1000}, {**_LIVE_CHECK, "at": 2000}])
        app.vault.notify_changed("aa:bb:cc:dd:ee:ff")
        await pilot.pause()

        rows = list(drawer.query(_KeyRow).results(_KeyRow))
        assert [(str(r.verify_button.label), r.verify_button.disabled) for r in rows] == [
            ("Verifying…", True), ("Verify", True)]
        rows[1].verify_button.press()
        await pilot.pause()
        assert len(verifier.checked) == 1

        verifier.release.set()
        await app.workers.wait_for_complete()
        await pilot.pause()
        rows = list(drawer.query(_KeyRow).results(_KeyRow))
        assert [(str(r.verify_button.label), r.verify_button.disabled) for r in rows] == [
            ("Verify", False), ("Verify", False)]
        checked = next(k for k in app.vault.ap_state("aa:bb:cc:dd:ee:ff").keys if k.value == rows[0].key.value)
        assert len(checked.live_verifications) == len(rows[0].key.live_verifications) > 0


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_copying_an_empty_pin_copies_nothing_and_says_so(tmp_path):
    app = _RecordingApp()
    async with app.run_test(size=(120, 40)) as pilot:
        app.vault.save_wps_pin(AccessPoint(bssid="aa:bb:cc:dd:ee:ff", ssid="HomeNet"), "", None)
        drawer = await _open_vault(app, pilot, "aa:bb:cc:dd:ee:ff")

        drawer.query_one(_KeyRow).copy_button.press()
        await pilot.pause()

        assert app.copied == [""]
        assert app.notified[-1] == "PIN is empty"


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_growing_the_drawer_expands_histories_the_user_has_not_toggled(tmp_path):
    _write_a_checked_wep_key_and_three_hashlines(tmp_path)
    app = WifiteApp()
    async with app.run_test(size=(80, 40)) as pilot:
        app.vault.save_wpa_psk("HomeNet", "aa:bb:cc:dd:ee:ff", "hunter22")
        drawer = await _open_vault(app, pilot, "aa:bb:cc:dd:ee:ff")
        rows = list(drawer.query(_KeyRow).results(_KeyRow))
        assert [r.expanded for r in rows] == [False, False]
        rows[0].toggle_button.press()
        rows[0].toggle_button.press()
        await pilot.pause()

        await pilot.resize_terminal(160, 50)
        await pilot.pause()
        assert [r.expanded for r in drawer.query(_KeyRow).results(_KeyRow)] == [False, True]


def _write_two_aps_with_wep_keys(tmp_path) -> None:
    _write(tmp_path, "HomeNet_aa-bb-cc-dd-ee-ff_1000_wep_key.txt", _WEP_TXT)
    _write(tmp_path, "Cafe_02-00-00-00-00-01_1000_wep_key.txt", _WEP_TXT.replace("aa:bb:cc:dd:ee:ff", "02:00:00:00:00:01"))


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_another_aps_verify_reads_busy_while_a_live_check_runs(tmp_path):
    _write_two_aps_with_wep_keys(tmp_path)
    app = WifiteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        drawer = await _open_vault(app, pilot, "aa:bb:cc:dd:ee:ff")
        item = drawer.query_one(VaultItemView)
        item.key_verifier = verifier = _HeldVerifier()
        drawer.query_one(_KeyRow).verify_button.press()
        await pilot.pause()

        table = drawer.query_one("#vault-aps", DataTable)
        table.move_cursor(row=table.get_row_index("02:00:00:00:00:01"))
        while "Cafe" not in str(item.border_title):
            await pilot.pause()
        await pilot.pause()
        button = drawer.query_one(_KeyRow).verify_button
        assert (str(button.label), button.disabled, button.tooltip) == (
            "Busy", True, "A live check is running on another AP")

        verifier.release.set()
        await app.workers.wait_for_complete()
        await pilot.pause()
        button = drawer.query_one(_KeyRow).verify_button
        assert (str(button.label), button.disabled) == ("Verify", False)


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_closing_the_drawer_cancels_a_running_live_check(tmp_path):
    _write_two_aps_with_wep_keys(tmp_path)
    app = WifiteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        drawer = await _open_vault(app, pilot, "aa:bb:cc:dd:ee:ff")
        item = drawer.query_one(VaultItemView)
        item.key_verifier = verifier = _HeldVerifier()
        drawer.query_one(_KeyRow).verify_button.press()
        await pilot.pause()
        assert item.verifying is not None

        await pilot.press("escape")
        while app.screen is drawer or item.verifying is not None:
            await pilot.pause()

        assert verifier.cancelled
        assert app.vault.ap_state("aa:bb:cc:dd:ee:ff").keys[0].live_verifications == ()


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_the_title_names_the_ssid_of_the_newest_capture_even_when_it_is_not_utf8(tmp_path):
    newest_line = _EAPOL_LINE.replace("5465737431", b"Caf\xe9".hex())
    older_line = _PMKID_LINE.replace("5465737431", b"Old".hex())
    _write(tmp_path, "Caf__aa-bb-cc-dd-ee-ff.hc22000", newest_line)
    _write(tmp_path, "Old_aa-bb-cc-dd-ee-ff.hc22000", older_line)
    os.utime(tmp_path / "Caf__aa-bb-cc-dd-ee-ff.hc22000", (1_600_000_000, 1_600_000_000))
    write_hashline_dates("Caf_", "aa:bb:cc:dd:ee:ff", {newest_line: 1_700_000_000})
    write_hashline_dates("Old", "aa:bb:cc:dd:ee:ff", {older_line: 1_600_000_000})
    app = WifiteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        drawer = await _open_vault(app, pilot, "aa:bb:cc:dd:ee:ff")
        assert "Caf�" in str(drawer.query_one(VaultItemView).border_title)


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_a_collapsed_keys_history_is_built_when_first_expanded(tmp_path):
    _write_a_checked_wep_key_and_three_hashlines(tmp_path)
    app = WifiteApp()
    async with app.run_test(size=(80, 40)) as pilot:
        drawer = await _open_vault(app, pilot, "aa:bb:cc:dd:ee:ff")
        row = drawer.query_one(_KeyRow)
        assert not row.expanded and len(row.query(".row")) == 0

        row.toggle_button.press()
        await pilot.pause()

        assert len(row.query(".row")) == 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_hashtopolis_is_offered_only_for_a_selection_holding_a_line_it_can_upload(tmp_path):
    ft_pmkid_line = _PMKID_LINE.replace("WPA*01*", "WPA*03*")
    _write(tmp_path, "HomeNet_aa-bb-cc-dd-ee-ff.hc22000", ft_pmkid_line + _OTHER_CLIENT_LINE)
    app = WifiteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        drawer = await _open_vault(app, pilot, "aa:bb:cc:dd:ee:ff")
        hashtopolis = next(b for b in drawer.query(_CrackerButton).results(_CrackerButton)
                           if b.tool.name == ToolName.HASHTOPOLIS)
        assert not hashtopolis.disabled

        for checkbox in drawer.query(_HashlineGroupCheckbox).results(_HashlineGroupCheckbox):
            checkbox.value = checkbox.group[0].line.kind == "03"
        await pilot.pause()

        assert hashtopolis.disabled


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_a_refresh_keeps_the_uncracked_lists_scroll_and_the_focused_checkbox(tmp_path):
    lines = "".join(_EAPOL_LINE.replace("112233445566", f"1122334455{n:02x}") for n in range(12))
    _write(tmp_path, "HomeNet_aa-bb-cc-dd-ee-ff.hc22000", lines)
    _write(tmp_path, "HomeNet_aa-bb-cc-dd-ee-ff_1000_wep_key.txt", _WEP_TXT)
    app = WifiteApp()
    async with app.run_test(size=(80, 40)) as pilot:
        drawer = await _open_vault(app, pilot, "aa:bb:cc:dd:ee:ff")
        uncracked = drawer.query_one(".uncracked", VerticalScroll)
        uncracked.scroll_to(y=uncracked.max_scroll_y, animate=False)
        last = list(drawer.query(_HashlineGroupCheckbox).results(_HashlineGroupCheckbox))[-1]
        last.focus()
        await pilot.pause()
        scrolled, focused_group = uncracked.scroll_y, last.group
        assert scrolled > 0

        update_meta("HomeNet", "aa:bb:cc:dd:ee:ff", live_verifications=[{**_LIVE_CHECK, "at": 2000}])
        app.vault.notify_changed("aa:bb:cc:dd:ee:ff")
        while drawer.query_one(_KeyRow).key.live_verifications == ():
            await pilot.pause()
        await pilot.pause()

        assert drawer.query_one(".uncracked", VerticalScroll).scroll_y == scrolled
        assert isinstance(app.focused, _HashlineGroupCheckbox) and app.focused.group == focused_group
