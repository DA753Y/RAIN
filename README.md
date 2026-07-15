<p align="center">
  <img src="icons/icon128.png" width="110" alt="RAIN — a miniature dachshund on a deep teal shield">
</p>

<h1 align="center">RAIN</h1>
<p align="center"><strong>Right-click Analyst's IOC Navigator</strong></p>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.1.1-C28A5C" alt="Version 2.1.1">
  <img src="https://img.shields.io/badge/manifest-V3-2E8CA8" alt="Manifest V3">
  <img src="https://img.shields.io/badge/Chromium-116%2B-2E8CA8" alt="Chromium 116+">
</p>

RAIN is a small Chromium extension for analysts who are tired of copying the same indicator into five different tabs.

Highlight an IP, domain, URL, hash, account, CVE, or User-Agent string. RAIN cleans up common defanging, works out what you selected, and sends it to the hunting tool you choose. For Microsoft Defender, it can open Advanced Hunting and insert a ready-to-review KQL query.

It is named after a particularly relentless miniature dachshund. Small, fast, and unwilling to let go of a scent.

## What it does

- Hunts selected text from the right-click menu, floating button, keyboard shortcut, or side panel.
- Refangs indicators such as `hxxps://evil[.]example/path` before searching.
- Recognises IPv4, IPv6, domains, URLs, MD5, SHA-1, SHA-256, accounts, email addresses, CVEs, and common User-Agent strings.
- Opens individual tools or uses **Yeet Search** to open a whole category in one collapsed tab group.
- Inserts customisable KQL into Microsoft Defender Advanced Hunting. RAIN never runs the query for you.
- Keeps templates and settings in local extension storage. There is no RAIN account, backend, or telemetry.

## Install

### Chrome Web Store

[Install RAIN from the Chrome Web Store](https://chromewebstore.google.com/detail/rain/fbpbdcfggnebbgfhdlopfbengnhdbanl).

### Load it yourself

1. Download the latest package from [GitHub Releases](https://github.com/DA753Y/RAIN/releases/latest) and extract it, or clone this repository.
2. Open `chrome://extensions` or `edge://extensions`.
3. Enable **Developer mode**.
4. Choose **Load unpacked** and select the RAIN folder.
5. Refresh any tabs that were already open.

RAIN requires Chrome 116 or another compatible Chromium browser.

## Use

Select an indicator, then use whichever route suits the page:

- Right-click and choose **RAIN - Hunt IOC**.
- Click the dachshund button that appears beside selected text.
- Press the hunt shortcut (`Alt+R` by default).
- Open the RAIN side panel and paste an indicator manually.

If a site replaces the browser's context menu, hold **Shift** while right-clicking to get the native menu back.

RAIN's classification is only a starting point. The hunt menu lets you switch the indicator type before opening a tool.

## Hunting tools

| Indicator | Tools |
|---|---|
| IP | Talos, VirusTotal, URLScan, AbuseIPDB, Shodan, Censys, Defender AHQ |
| Domain or URL | VirusTotal, URLScan, Talos, URLVoid, MXToolbox, Crt.sh, Censys, Defender AHQ |
| File hash | VirusTotal, Hybrid Analysis, AlienVault OTX, Defender AHQ |
| Account or email | Have I Been Pwned, Defender AHQ |
| CVE | NIST NVD, CISA KEV, MITRE CVE, Defender AHQ |
| User-Agent | Defender AHQ, CyberChef, Google, GitHub |
| Anything | CyberChef |

## Defender Advanced Hunting

Choosing a Defender hunt opens the Advanced Hunting page and inserts a KQL query after the editor loads.

- The query is inserted, not executed. Read it before pressing **Run**.
- You need an active Defender session with access to Advanced Hunting.
- Templates for each indicator type can be changed from RAIN's options page.
- Keep the documented placeholder as a standalone quoted value or bare token. RAIN places the indicator in a separately escaped KQL string declaration so selected text cannot change the query structure.

## Privacy and permissions

RAIN runs a content script on pages you visit so it can show the floating hunt button, read selected text when you invoke the shortcut, and restore the native context menu. It also runs inside frames because security portals and document applications often put useful text there.

RAIN does not collect telemetry or send data to its own service. Settings stay in local extension storage. An indicator leaves the browser only when you deliberately open one of the listed third-party services.

The only site where RAIN injects anything is `https://security.microsoft.com`, and the injected action only fills the Advanced Hunting editor.

The full details are in the [privacy policy](PRIVACY.md).

### A short OPSEC warning

Public reputation services receive the indicator you submit. Avoid sending internal hostnames, employee accounts, or sensitive incident indicators to public tools unless that fits your team's policy. The dachshund cannot un-bark.

## Troubleshooting

- **RAIN is missing from a page:** refresh tabs that were open before installation. Chromium also blocks extensions on browser pages, the Web Store, and some built-in viewers.
- **A site has its own right-click menu:** hold **Shift** while right-clicking, use the floating button, or use the shortcut.
- **The shortcut does nothing:** another extension or the browser may already use it. Change it at `chrome://extensions/shortcuts`.
- **No KQL appears in Defender:** make sure you are signed in and that the Advanced Hunting editor has loaded.
- **The side panel opens without your selection:** some canvas-based applications and protected browser pages do not expose selected text. Paste the indicator into the panel instead.

## Contributing

Issues and pull requests are welcome. Good places to start are missing defang patterns, hunting tools that would be useful to other analysts, and browser pages where one of the hunt surfaces behaves badly.

Please keep additions focused. RAIN is meant to stay small.

## Support

RAIN is a hobby project. If it saves you a few minutes during triage and you feel like supporting it:

[![Buy me a coffee](https://img.shields.io/badge/Buy_me_a_coffee-datesy-C28A5C?logo=buymeacoffee&logoColor=white)](https://buymeacoffee.com/datesy)

---

