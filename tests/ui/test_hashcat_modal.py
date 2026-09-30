import pytest

import wifit3.ui.vault.modals.hashcat as mod
from wifit3.persist.config import Config, ConfigError
from wifit3.ui.vault.modals.hashcat import HashcatConfigModal, _default_hashcat_path


@pytest.fixture(autouse=True)
def _unset_saved_paths(monkeypatch):
    """These live on Config as process-wide state; pin them so test order can't matter."""
    monkeypatch.setattr(Config, "hashcat_path", None)
    monkeypatch.setattr(Config, "wordlist_path", None)


def test_default_path_prefers_which(monkeypatch):
    monkeypatch.setattr(mod.shutil, "which", lambda _: "/somewhere/hashcat")
    assert _default_hashcat_path() == "/somewhere/hashcat"


def test_default_path_falls_back_per_os(monkeypatch):
    monkeypatch.setattr(mod.shutil, "which", lambda _: None)
    monkeypatch.setattr(mod.sys, "platform", "linux")
    assert _default_hashcat_path() == "/usr/bin/hashcat"
    monkeypatch.setattr(mod.sys, "platform", "darwin")
    assert _default_hashcat_path() == "/opt/homebrew/bin/hashcat"
    monkeypatch.setattr(mod.sys, "platform", "win32")
    assert _default_hashcat_path() == r"C:\hashcat\hashcat.exe"


def test_saved_path_outranks_a_hashcat_found_on_path(monkeypatch):
    """Someone who points wifit3 at a specific build must not be silently overridden by
    whatever happens to be on $PATH."""
    monkeypatch.setattr(mod.shutil, "which", lambda _: "/somewhere/hashcat")
    monkeypatch.setattr(Config, "hashcat_path", r"D:\tools\hashcat\hashcat.exe")
    assert _default_hashcat_path() == r"D:\tools\hashcat\hashcat.exe"


def test_launching_remembers_both_paths(monkeypatch):
    saved = []
    monkeypatch.setattr(Config, "save", classmethod(lambda cls: saved.append(True)))

    HashcatConfigModal()._remember(r"D:\hashcat.exe", r"D:\rockyou.txt")

    assert (Config.hashcat_path, Config.wordlist_path) == (r"D:\hashcat.exe", r"D:\rockyou.txt")
    assert saved, "the paths are useless unless they reach disk"


def test_an_unwritable_config_warns_but_keeps_the_paths(monkeypatch):
    """A failed save must not cost the user their launch."""
    def _boom(cls):
        raise ConfigError("disk full")
    monkeypatch.setattr(Config, "save", classmethod(_boom))

    modal = HashcatConfigModal()
    warnings = []
    monkeypatch.setattr(modal, "notify", lambda *a, **k: warnings.append((a, k)))
    modal._remember(r"D:\hashcat.exe", r"D:\rockyou.txt")

    assert Config.hashcat_path == r"D:\hashcat.exe"
    assert warnings and warnings[0][1].get("title") == "Config Error"
