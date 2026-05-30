<img width="440" height="280" alt="RAIN440-280" src="https://github.com/user-attachments/assets/adf98df7-8fb8-40fa-9450-5c3fe98a84d5" />

# RAIN (Right-click Analyst's IOC Navigator)

Named after a particularly relentless miniature dachshund, RAIN is a dedicated SOC analyst tool designed to speed up the OSINT hunting of Indicators of Compromise (IOCs). Built to eliminate the daily friction of manual copy-pasting and excessive tab switching, RAIN bridges the gap between raw web text and actionable threat intelligence.

Simply highlight an IOC on any webpage and open your right-click context menu. RAIN automatically cleans the string and empowers you to immediately launch investigations.

## Core Capabilities

*   **Automatic Refanging & Cleaning**: Threat feeds intentionally defang indicators to prevent accidental clicks. RAIN saves you time by automatically refanging highlighted text on the fly.
    *   **Protocol Refanging**: Converts decoy markers like `hxxps://`, `hxxp://`, `meows://`, and `meow://` back to standard `https://` and `http://` protocols.
    *   **Obfuscated Dots & Colons**: Replaces bracketed or parenthesized periods and colons (e.g., `[.]`, `(.)`, `[:]`, `(:)`) with standard periods and colons.
    *   **Surrounding Trimming**: Cleanly strips away leading/trailing quotation marks, parenthesis, or brackets accidentally highlighted alongside the IOC.
*   **Microsoft Defender KQL Auto-Injection**: Selecting a Defender lookup instantly opens Microsoft Defender Advanced Hunting and injects a fully customized, category-optimized KQL query directly into the Monaco code editor. This includes a built-in reinforcement engine to bypass Defender's Single Page Application (SPA) state-restoration race conditions.
*   **"Yeet Search" (Bulk Lookup Tab Groups)**: Conduct comprehensive reputation assessments by querying every threat intelligence tool in a category simultaneously. To prevent browser clutter, RAIN automatically packages all opened tabs into a collapsed Chrome Tab Group. These groups are colored by category: IP is blue, Domain is green, Hash is orange, Account is purple, and CVE is red.
*   **Unified Control Center**: Includes a sleek, dark-themed options dashboard built for speed.
    *   **Interactive KQL Customizer**: Edit and save custom KQL templates to Chrome's local storage.
    *   **OSINT Hunting Directory**: An integrated directory mapping to 17 pre-configured threat engines.

## Supported Integrations

RAIN maps to 17 industry-standard OSINT reputation suites. 

| IOC Category | Supported Tools |
| :--- | :--- |
| **IP Addresses** | Cisco Talos, VirusTotal, URLScan.io, AbuseIPDB, Shodan, Censys, Microsoft Defender. |
| **Domains & URLs** | VirusTotal, URLScan.io, Cisco Talos, URLVoid, MXToolbox, Crt.sh, Censys, Microsoft Defender. |
| **File Hashes** | VirusTotal, Hybrid Analysis, AlienVault OTX, Microsoft Defender. |
| **Accounts & Emails** | HaveIBeenPwned, Microsoft Defender. |
| **CVEs** | NIST NVD, CISA KEV, MITRE CVE, Microsoft Defender. |
| **Universal Processing** | GCHQ CyberChef (with modernized base64url UTF-8 conversion). |

## Security & Privacy 

RAIN is designed with strict security guidelines to protect enterprise SOC environments:

*   **Strict Script Injection Bounds**: The service worker restricts script injection specifically to the `MAIN` world of `https://security.microsoft.com/*` using robust `URL` constructor origin checks. RAIN will never execute scripts on untrusted domains.
*   **Robust Input Sanitization**: All dynamic indicator selections undergo KQL-safe character escaping (escaping backslashes, double-quotes, single-quotes, and backticks) to prevent KQL injection payloads.
*   **Local Storage Isolation**: Custom KQL templates are stored strictly within the extension's local chrome isolation (`chrome.storage.local`).
*   **Principle of Least Privilege**:
    *   `contextMenus`: Required to construct categories dynamically.
    *   `scripting`: Required to inject KQL queries into the Defender Monaco editor.
    *   `storage`: Required to fetch analyst custom query overrides.
    *   `tabs` & `tabGroups`: Required to cluster bulk lookup tabs safely.
