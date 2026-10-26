"""Vault drawer overlay and VaultItemView detail pane, driven through a real WifiteApp.
The autouse _captures_to_tmp fixture points Config.captures_dir at tmp_path, and WifiteApp builds its Vault from there.
"""
import pytest
from textual.widgets import Button, Checkbox, DataTable, Input, Label, Static

from wifit3.models import AccessPoint, CaptureType
from wifit3.models.jobs import JobState, ToolStatus
from wifit3.persist.meta import meta_path, read_meta, update_meta
from wifit3.persist.save import SaveResult
from wifit3.ui.app import WifiteApp
from wifit3.ui.screens.vault_drawer import VaultDrawer
from wifit3.ui.screens.vault_item import _CapturePanel, _KeyRow
from wifit3.ui.vault.modals.add_credential import AddCredentialModal, ManualCredential
from wifit3.ui.vault.modals.nickname import NicknameModal

_HS_LINE = "WPA*02*" + "0" * 32 + "*aabbccddeeff*112233445566*5465737431***2\n"
_EAPOL_LINE = ("WPA*02*" + "0" * 32 + "*aabbccddeeff*112233445566*5465737431*" + "a" * 64 + "*"
               + "00" * 99 + "*02\n")
_PMKID_LINE = "WPA*01*" + "0" * 32 + "*aabbccddeeff*112233445566*5465737431***\n"
_WEP_TXT = "SSID: HomeNet\nBSSID: aa:bb:cc:dd:ee:ff\nWEP key (hex):   6162636465\n"
_LONG_WEP_TXT = "SSID: HomeNet\nBSSID: aa:bb:cc:dd:ee:ff\nWEP key (hex):   " + "61" * 26 + "\n"

def _write(d, name, content):
    (d / name).write_text(content, encoding="utf-8")

async def _open_vault(app) -> VaultDrawer:
    app.action_toggle_vault()
    return app.screen


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
@pytest.mark.parametrize(("height", "full_screen"), [(35, True), (36, False)])
async def test_short_vault_uses_full_screen(height, full_screen):
    app = WifiteApp()
    async with app.run_test(size=(100, height)) as pilot:
        view = await _open_vault(app)
        await pilot.pause(0)
        content = view.query_one("#vault-content")

        assert (content.region.height == view.size.height) is full_screen


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
@pytest.mark.parametrize(("width", "stacked"), [(104, True), (105, False)])
async def test_narrow_vault_stacks_ap_list_above_details(width, stacked):
    app = WifiteApp()
    async with app.run_test(size=(width, 40)) as pilot:
        view = await _open_vault(app)
        await pilot.pause(0)
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
        return JobState(job_id="j1", tool_name="hashcat", capture_path="x",
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
        app.active_jobs = [JobState(job_id="j2", tool_name="hashcat", capture_path="y",
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
        job = JobState(job_id="j1", tool_name="cpu_crack", capture_path="x",
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
        job = JobState(job_id="j1", tool_name="cpu_crack", capture_path="x",
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
        view = await _open_vault(app)
        await pilot.pause()
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
        view = await _open_vault(app)
        await pilot.pause()
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
        view = await _open_vault(app)
        await pilot.pause()
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
        view = await _open_vault(app)
        await pilot.pause()
        mocker.patch.object(app.vault, "open_directory", side_effect=FileNotFoundError)
        notify = mocker.patch.object(view, "notify")

        view.action_show_directory()

        notify.assert_called_once_with("No captures yet", severity="warning")


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_add_credential_prefills_the_row_and_rejects_a_psk_the_handshake_refutes(
        tmp_path, mocker):
    _write(tmp_path, "HomeNet_aa-bb-cc-dd-ee-ff.hc22000", _PMKID_LINE)
    app = WifiteApp()
    async with app.run_test() as pilot:
        view = await _open_vault(app)
        await pilot.pause()
        verify = mocker.patch.object(app.vault, "verify_wpa_psk", return_value=False)
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
        verify.assert_called_once_with("aa:bb:cc:dd:ee:ff", "wrongpass")
        assert notify.call_args.kwargs["severity"] == "error"
        assert not app.vault.has_psk(AccessPoint(bssid="aa:bb:cc:dd:ee:ff"))

        verify.return_value = True
        propagate = mocker.patch.object(app.vault, "propagate_verified_psk",
                                        return_value=["02:00:00:00:00:10"])
        view._credential_added(ManualCredential(CaptureType.WPA_PSK, "HomeNet",
                                                "aa:bb:cc:dd:ee:ff", "rightpass"))
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert app.vault.known_psk(AccessPoint(bssid="aa:bb:cc:dd:ee:ff")) == "rightpass"
        propagate.assert_called_once_with("aa:bb:cc:dd:ee:ff", "HomeNet", "rightpass")
        assert [c.args[0] for c in notify.call_args_list[-2:]] == [
            "Credential verified and added to Vault",
            "PSK also verified and saved for 1 related APs"]

        view._credential_added(ManualCredential(CaptureType.WPS_PIN, "Other",
                                                "02:00:00:00:00:20", "1234"))
        pin = app.vault.persisted("02:00:00:00:00:20")[0]
        assert pin.pin == "1234" and pin.value is None



@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_a_wep_key_shows_and_copies_as_ascii_and_is_the_current_password(tmp_path, mocker):
    _write(tmp_path, "HomeNet_aa-bb-cc-dd-ee-ff_1000_wep_key.txt", _WEP_TXT)
    app = WifiteApp()
    async with app.run_test(size=(50, 30)) as pilot:
        view = await _open_vault(app)
        await pilot.pause()
        copy = mocker.patch.object(app, "copy_to_clipboard")
        row = view.query_one(_KeyRow)

        assert "abcde" in str(row.query_one(".key-text", Label).content)
        assert "CURRENT PASSWORD" in str(view.query_one(".status", Static).content)
        assert "Key: abcde" in str(view.query_one(".status", Static).content)
        row.query_one(".copy-btn", Button).press()
        await pilot.pause(0)
        copy.assert_called_once_with("abcde")


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_a_long_wep_key_ellipsizes_without_pushing_copy_and_verify_off_the_pane(tmp_path):
    _write(tmp_path, "HomeNet_aa-bb-cc-dd-ee-ff_1000_wep_key.txt", _LONG_WEP_TXT)
    app = WifiteApp()
    async with app.run_test(size=(50, 30)) as pilot:
        view = await _open_vault(app)
        await pilot.pause()
        panel = view.query_one(_CapturePanel)
        for button in view.query_one(_KeyRow).query(Button).results(Button):
            assert button.region.right <= panel.content_region.right


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_open_vault_updates_when_handshake_is_saved(tmp_path, mocker):
    app = WifiteApp()
    async with app.run_test() as pilot:
        view = await _open_vault(app)
        await pilot.pause()
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
async def test_rapid_selection_only_loads_the_final_ap(tmp_path, mocker):
    for index, name in enumerate(("Alpha", "Bravo", "Charlie")):
        bssid = f"00-11-22-33-44-{index:02x}"
        _write(tmp_path, f"{name}_{bssid}_1000_wep_key.txt",
               f"SSID: {name}\nBSSID: {bssid.replace('-', ':')}\nWEP key (hex): 6162\n")
    app = WifiteApp()
    async with app.run_test() as pilot:
        app.push_screen(VaultDrawer())
        await pilot.pause()
        drawer = app.screen
        table = drawer.query_one("#vault-aps", DataTable)
        load_widget = mocker.patch.object(drawer, "_load_widget")

        table.move_cursor(row=0)
        table.move_cursor(row=1)
        table.move_cursor(row=2)
        await pilot.pause(0.02)
        load_widget.assert_not_called()

        await pilot.pause(0.1)
        load_widget.assert_called_once_with("00:11:22:33:44:02")


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
        view = await _open_vault(app)
        await pilot.pause()
        bssid, (ssid, caps) = next(iter(view.query_one("#vault-table")._aps.items()))
        view.query_one("VaultItemView").load(bssid, ssid, caps)
        await pilot.pause(0)

        panel = view.query_one(_CapturePanel)
        buttons = list(panel.query(".tool-btn").results(Button))
        assert [str(b.label) for b in buttons] == ["Hashcat", "CPU Crack", "Hashtopolis"]
        assert [(str(b.label), b.region.right) for b in panel.query(Button).results(Button) if b.region.right > panel.content_region.right] == []

        buttons[1].press()
        await pilot.pause(0)
        assert isinstance(app.screen, CpuCrackConfigModal)


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_cracker_buttons_go_compact_on_one_row_in_a_narrow_pane(tmp_path):
    _write(tmp_path, "HomeNet_aa-bb-cc-dd-ee-ff.hc22000", _EAPOL_LINE)
    app = WifiteApp()
    async with app.run_test(size=(40, 40)) as pilot:
        view = await _open_vault(app)
        await pilot.pause()

        buttons = list(view.query_one(_CapturePanel).query(".tool-btn").results(Button))
        assert [str(button.label) for button in buttons] == ["Hashcat", "CPU Crack", "Hashtopolis"]
        assert all(button.compact for button in buttons)
        assert buttons[0].region.y == buttons[1].region.y == buttons[2].region.y


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_unchecked_hashlines_are_left_out_of_the_crack_job(tmp_path, mocker):
    other_client = _EAPOL_LINE.replace("112233445566", "112233445577")
    _write(tmp_path, "HomeNet_aa-bb-cc-dd-ee-ff.hc22000", _EAPOL_LINE + other_client + _PMKID_LINE)
    app = WifiteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        view = await _open_vault(app)
        await pilot.pause()
        submit = mocker.patch.object(app.vault.manager, "submit_job", return_value="job")
        panel = view.query_one(_CapturePanel)
        checkboxes = list(panel.query(Checkbox).results(Checkbox))
        assert len(checkboxes) == 3
        assert "3 captures selected to crack" in str(panel.query_one(".selected-count", Label).content)

        checkboxes[0].value = False
        await pilot.pause(0)
        assert "2 captures selected to crack" in str(panel.query_one(".selected-count", Label).content)
        panel.query_one(".launch-tool-cpu_crack", Button).press()
        await pilot.pause()
        app.screen.dismiss({"wordlists": []})
        await pilot.pause()

        chosen = submit.call_args.kwargs["hashlines"]
        assert len(chosen) == 2 and panel._groups[0][0].raw not in chosen

        for checkbox in checkboxes:
            checkbox.value = False
        await pilot.pause(0)
        assert all(button.disabled for button in panel.query(".tool-btn").results(Button))
