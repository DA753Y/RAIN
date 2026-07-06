<p align="center">
  <img src="icons/icon128.png" width="110" alt="RAIN, a miniature dachshund on a deep teal shield">
</p>

<h1 align="center">RAIN</h1>
<p align="center"><strong>Right-click Analyst's IOC Navigator</strong></p>
<p align="center"><em>Highlight. Hunt. Done.</em></p>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-C28A5C" alt="Version 2.0.0">
  <img src="https://img.shields.io/badge/manifest-V3-2E8CA8" alt="Manifest V3">
  <img src="https://img.shields.io/badge/chrome-114%2B-2E8CA8" alt="Chrome 114+">
</p>

---

Every SOC analyst knows the dance. Copy the IP out of the alert. Fix the `[.]` someone defanged it with. Open VirusTotal in a new tab. Paste. Search. Open AbuseIPDB. Paste again. Open Shodan. Paste *again*. Somewhere around tab fourteen you forget which indicator you were even chasing.

RAIN kills that dance. Highlight an indicator anywhere in your browser, and RAIN cleans it, classifies it, and launches it into the tools you actually use, including a ready-to-run KQL query dropped straight into Microsoft Defender Advanced Hunting.

It is named after a particularly relentless miniature dachshund. Like her, it is small, fast, and does not let go of a scent.

## Four ways to hunt

RAIN meets you wherever you are on the page. All four surfaces share the same cleaning, classification, and tool set.

| Surface | How | Best for |
|---|---|---|
| **Right-click menu** | Highlight, right-click, `RAIN - Hunt IOC` | The classic. Works everywhere Chrome menus work, even inside frames and shadow DOM, because the browser supplies the selected text itself. |
| **Floating button** | Highlight text, click the dachshund that appears beside it | Fastest pointer-driven flow. Auto-classifies the indicator and shows the matching tools. |
| **Hunt hotkey** (`Alt+R` by default) | Highlight, press the key | Keyboard-first analysts. Opens the same menu without touching the mouse. |
| **Side panel** | Opens automatically when the in-page menu isn't possible, or open it yourself from Chrome's side panel menu | Browser pages, canvas apps like Google Docs, stubborn portals, or pasting an IOC from anywhere. |

Some sites replace the right-click menu with their own. Hold **Shift** while right-clicking and RAIN forces the browser's native menu through anyway.

If RAIN guesses the indicator type wrong (or can't classify it at all), every menu includes a type switcher: one click flips the same indicator to IP, Domain, Hash, Account, or CVE.

## Automatic refanging

Threat intel is shared defanged; hunting tools want it fanged. RAIN translates on the fly, so what you highlight is never what limits you.

| You highlight | RAIN hunts |
|---|---|
| `hxxps://evil[.]com/payload` | `https://evil.com/payload` |
| `192[.]168(.)10[.]50` | `192.168.10.50` |
| `meow://c2(.)badguys[dot]net` | `http://c2.badguys.net` |
| `admin[at]corp[.]com` | `admin@corp.com` |
| `"suspicious.exe"` (stray quotes/brackets) | `suspicious.exe` |

Covered: `hxxp`/`hxxps`/`meow`/`meows` protocols, bracketed and verbal dots (`[.]` `(.)` `{.}` `[dot]` `(dot)`), colons (`[:]` `(:)`), at-signs (`[@]` `(@)` `[at]` `(at)`), and wrapping quotes, parentheses, brackets, and angle brackets.

## Classification

RAIN recognises five indicator families automatically:

- **IP addresses**, IPv4 and IPv6
- **Domains and URLs**, from bare domains to full paths
- **File hashes**, MD5, SHA-1, and SHA-256, detected by length
- **Accounts and emails**, addresses and UPNs
- **CVE identifiers**, like `CVE-2024-21412`

## Yeet Search

Sometimes you don't want one opinion, you want all of them. **Yeet Search** throws the indicator at every tool in its category simultaneously. The tabs open quietly in the background and land in a single collapsed, colour-coded tab group (blue for IPs, green for domains, orange for hashes, red for CVEs). Triage them when you're ready, then close the whole group in one click. Your tab bar stays civilised.

## The hunting directory

Seventeen integrations across five categories, plus one universal utility:

| Category | Tools |
|---|---|
| **IP** | Talos, VirusTotal, URLScan, AbuseIPDB, Shodan, Censys, Defender AHQ |
| **Domain/URL** | VirusTotal, URLScan, Talos, URLVoid, MXToolbox, Crt.sh, Censys, Defender AHQ |
| **File hash** | VirusTotal, Hybrid Analysis, AlienVault OTX, Defender AHQ |
| **Account/Email** | HaveIBeenPwned, Defender AHQ |
| **CVE** | NIST NVD, CISA KEV, MITRE CVE, Defender AHQ |
| **Universal** | CyberChef (indicator delivered pre-loaded as input) |

## Microsoft Defender Advanced Hunting

The headline act. Choose a Defender AHQ hunt and RAIN opens the Advanced Hunting portal, waits for the query editor to load, and inserts a complete KQL query with your indicator already substituted in.

- The query is **inserted, never executed**. You review it and press Run.
- You need an active Defender portal session with Advanced Hunting access.
- Every template is fully customisable per indicator type in the options page, using placeholders (`IP_VALUE`, `DOMAIN_VALUE`, `HASH_VALUE`, `ACCOUNT_VALUE`, `CVE_VALUE`).
- Indicators are sanitised before insertion so they can't break out of the KQL string literal.

Out of the box the templates pivot across `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceProcessEvents`, `EmailEvents`, `IdentityLogonEvents`, `DeviceTvmSoftwareVulnerabilities`, and more.

## Installation

To install via Chrome Webstore go here: [RAIN - Chrome Web Store](https://chromewebstore.google.com/detail/rain/fbpbdcfggnebbgfhdlopfbengnhdbanl)

To install yourself:
1. Clone or download this repository.
2. Open `chrome://extensions` (or `edge://extensions`).
3. Enable **Developer mode**.
4. Click **Load unpacked** and select the RAIN folder.
5. Refresh any tabs that were already open, then highlight something suspicious.

Works on Chrome, Edge, and other Chromium browsers, version 114 or newer.

## Settings

Click the RAIN icon (or open the options page) for the Analyst Control Center:

- **KQL Templates**: edit the query used for each indicator type, with save and reset.
- **Floating hunt button**: toggle the on-page button.
- **Force native right-click with Shift**: toggle the context menu bypass.
- **Hunt hotkey**: view your current binding and rebind it via Chrome's shortcut manager. Everything in the UI reads your *actual* binding, so the docs never lie to you.

## Permissions, honestly

| Permission | Why RAIN has it |
|---|---|
| `contextMenus` | The right-click hunt menu. |
| `scripting` | Inserts KQL into Defender; reads your selection when you press the hotkey. |
| `activeTab` | Scopes hotkey access to the single tab you invoked it on, instead of demanding standing access to every site. |
| `tabGroups` | Collects Yeet Search tabs into one tidy group. |
| `storage` | Your templates and settings, stored locally. |
| `sidePanel` | The docked hunt panel. |
| Host: `security.microsoft.com` | The only site RAIN injects queries into. |
| Content script on all sites | The floating button and Shift+right-click helper have to exist wherever you're reading intel. |

RAIN sends **no telemetry**, phones home to **nowhere**, and stores **nothing** outside your browser's local extension storage. The only data that ever leaves is the indicator you deliberately send to the tool you clicked.

## An OPSEC note

Every hunt sends the indicator to the external service you pick. Public platform searches can be visible to the platform, its users, and sometimes the adversary. Think twice before submitting internal hostnames, employee accounts, or indicators from targeted intrusions to public tools, and follow your team's OPSEC policy. The dachshund cannot un-bark.

## Troubleshooting

- **RAIN doesn't appear on a page**: tabs opened before install need a refresh. Browser pages (`chrome://`), the Web Store, and the built-in PDF viewer don't allow extensions; the hotkey opens the side panel there instead.
- **Hotkey opens the side panel even though text is highlighted**: some portals (including parts of Microsoft Defender) render content inside frames or shadow DOM where the selection can't always be read. RAIN prefills the panel when it can; otherwise paste the indicator in. The right-click menu still works on these pages.
- **A site shows its own right-click menu**: hold Shift while right-clicking, or use the floating button.
- **KQL didn't appear in Defender**: confirm you're signed in and the editor finished loading. RAIN waits up to 30 seconds.
- **Hotkey does nothing**: the combination may be taken. Rebind it at `chrome://extensions/shortcuts`.

## What's new in 2.0.0

- **Floating hunt button**: Grammarly-style, shadow DOM isolated, unbothered by hostile page CSS.
- **Hunt hotkey** with deep selection reading (inputs, textareas, shadow DOM).
- **Side panel**: a docked, granular hunt workspace that catches every case the in-page menu can't.
- **IOC type switcher** in every menu, for when classification guesses wrong or shrugs.
- **Shift+right-click** native menu passthrough for context-menu-hijacking sites.
- **Full UI redesign** built from the palette of the icon itself: deep navy, teal, and dachshund copper.
- Yeet Search now includes Defender AHQ, service worker restarts no longer drop pending KQL injections, custom templates survive updates, and the permission footprint shrank (`tabs` is gone).

## Contributing

Found a defang pattern RAIN doesn't chew through? Want your team's favourite reputation service in the directory? Issues and pull requests are welcome. Tool additions are one small object in `background.js`; the menus, panel, and Yeet Search pick them up automatically.

---

<p align="center"><em>Stay dry out there. 🌧️</em></p>
