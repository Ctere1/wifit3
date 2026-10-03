from datetime import datetime

from wifit3.ui.screens.vault_item import relative_time


def test_relative_time_singular_minute():
    now = int(datetime.now().timestamp())
    assert relative_time(now - 60) == "1 minute ago"


def test_relative_time_plural_minutes():
    now = int(datetime.now().timestamp())
    assert relative_time(now - 300) == "5 minutes ago"


def test_capture_panel_cancel_verification():
    from unittest.mock import MagicMock
    from wifit3.ui.screens.vault_item import _CapturePanel
    from wifit3.models import CaptureType, PersistedCapture

    cap = PersistedCapture(
        type=CaptureType.WPA_PSK,
        timestamp=1000,
        path="/tmp/test.cap",
        bssid="00:11:22:33:44:55",
        value="secret",
    )
    panel = _CapturePanel("WPA PSKs", [cap])
    mock_task = MagicMock()
    mock_task.done.return_value = False
    panel._verify_task = mock_task

    panel.cancel_verification()
    mock_task.cancel.assert_called_once()
    assert panel._verify_task is None


def test_vault_item_view_cancel_verification():
    from unittest.mock import MagicMock
    from wifit3.ui.screens.vault_item import VaultItemView

    view = VaultItemView()
    mock_panel = MagicMock()
    view.query = MagicMock(return_value=[mock_panel])

    view.cancel_verification()
    mock_panel.cancel_verification.assert_called_once()
