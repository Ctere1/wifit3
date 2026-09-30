# Wifit3 — Features & QoL Backlog

Known bugs live in `BUGS.md`.

---

### About page / Check-for-updates

If the user has internet connection, it's trivial to query
[the releases page](https://github.com/derv82/wifit3/releases) to fectch the latest version,
compare with the current version, and show a Toast notification about the newest version,
clicking Toast notification -> opens releases page.

We could automate this as well (opt-**in**), in Preferences: `[x] Automatically check for updates`

------------

### Vault tool: WPA-Sec submission / polling

[wpa-sec.stanev.org](https://wpa-sec.stanev.org/) is a free distributed cracking pool: submit a
handshake with an API key, poll for a result. pwnagotchi already does exactly this
([dadav's `wpa-sec.py` plugin](https://github.com/dadav/pwnagotchi-custom-plugins/blob/master/wpa-sec.py)).
Raised in [D#25](https://github.com/derv82/wifit3/discussions/25).

Why it fits: turnaround is reportedly bimodal (minutes, or never), which makes it a *free*
background attempt to fire off the moment a capture lands. Especially valuable for mobile /
low-power users who have no GPU to run hashcat against. Costs nothing while it waits.

Shape: a `VaultTool` (`vault/tools/base.py`) whose `launch()` is an HTTP POST rather than a
subprocess, and whose `poll_status()` queries the site instead of tailing a log. The ABC already
anticipates this ("executes local process ... or API request"), so no new subsystem is needed.

Open items:
- **Ask the WPA-Sec operators for permission before shipping this.** Not optional.
- API key storage (Preferences? SUbmission form? separate secrets file?).
- Opt-**in** only: This uploads the user's captured traffic to a third party.
- Dedupe: Don't re-submit a capture already submitted, and survive a restart.

### Vault tool: Hashtopolis submission / polling

[D#52](https://github.com/derv82/wifit3/discussions/52): distribute one crack across several
machines via a Hashtopolis server, instead of one local hashcat.

Same `VaultTool` shape as WPA-Sec (submit + poll a remote API), but self-hosted so no permissions issues.
Needs a server URL + voucher/API key in Preferences, and a mapping from our capture types onto
Hashtopolis task creation.

### Vault: "add" and "Check" features

- **"Add"**: User enters credential (PSK/WPS) for a known AP (with an option to `Check` the PSK/PIN).
- **"Check"**: Authenticate against the live AP to confirm a stored PSK/PIN/WEP key still works.

------------

### EAP-MSCHAPv2 / PEAP via Evil Twin

Most enterprise Wi-Fi is PEAP-MSCHAPv2, which cracks with hashcat `-m 5500` (DES half near-
instant via crack.sh): recovering the *domain* credential is a far higher value than a PSK,
PEAP wraps MSCHAPv2 in TLS, so it **can't be captured passively**. Stand up an Evil Twin 
so the client auths to *you*.

Some things we'll need:
- target-ESSID beacons,
- RADIUS/EAP state machine
- cert handling.

When a second hashcat mode lands (`-m 4800`/`5500`), the save layer needs a per-attack
(mode + line-format) map instead of the hardcoded `-m 22000`.

------------

## Undecided

### Captive Portal

Evil Twin + a fake router login page: punt the client onto an open twin, serve a password form,
the user types the real PSK, then verify it against a captured handshake.

Asked for repeatedly: [issue #55](https://github.com/derv82/wifit3/issues/55) (well-written, with mockups),
and it was the 3rd or 4th such request; [D#34](https://github.com/derv82/wifit3/discussions/34)
covers the same ground from the plugin-system angle.

**For:**
- Demand is real and growing: several independent requests, plus follow-ups asking for a
  *generic* (non-brand-specific) form page à la airgeddon.
- It's the only practical vector left when the PSK is a modern random ISP default: offline
  cracking is mathematically dead there, and not every such router exposes WPS ([D#61](https://github.com/derv82/wifit3/discussions/61)).
- Not blind phishing: the entered password is verified against a real captured handshake, so
  the attack self-confirms instead of guessing.
- Someone already built it: #55's author ran a modified wifit3 and offered the source; laxdog's
  `feat/eviltwin-improvements` was already headed at open-AP + portal-HTML cloning (D#34).
  *(#55 also has a MEGA link to a binary+source drop)*

**Against:**
- Wrong layer, wrong target. Captive Portal is a *client*-side phishing attack; wifite/2/3 has
  always been *AccessPoint*-based attacks at the 802.11 layer.
- Enormous scope. Evil Twin currently tops out at Auth/Assoc/M1 (roughly Layer 2). A portal
  means a whole working AP: DHCP, DNS, IP routing, TCP, HTTP, TLS certs, ports 80/443, client
  session lifecycle, and per-client captive-portal-detection quirks.
- It's a subsystem to maintain forever, natively, without `hostapd` or `apache`; both of which
  are ridiculously complex for a reason. Plus per-brand HTML templates that go stale.
- It pushes wifit3 way up a stack the maintainer isn't well-versed in.
- *"we're an 802.11 auditing tool, not an entire wifi attack stack."*

**Where this stands:** still leaning **no**, mostly on the scope/maintenance argument, not on the
demand one. Issue #55 is intentionally left open to keep gauging demand.

------------

## Deferred / Chopping Block

### WPS improvements - Low priority (who even has a vulnerable WPS router?)

The WPS engine is built, offline-proven, and HW-validated (full PIN crack on AirLink). Gaps:
- **Lock-cycle matrix** — only AirLink soft-lock tested; exercise no-lock, long cooldowns, hard-lock.
- **PixieDust (PRNG seed recovery)** — Phase 1 (Null Secret) and Phase 2 (Static Secrets)
  landed natively in `campaigns/wps/pixie.py`. Advanced PRNG seed-search modes (Broadcom
  timestamp search, Realtek/MediaTek LCG) remain deferred due to the CPU cost of
  evaluating 32-bit seed spaces in pure Python.
