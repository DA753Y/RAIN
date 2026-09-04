const TEMPLATE_SCHEMA_VERSION = 4;

const DEFAULT_SETTINGS = {
  floatingButton: true,
  forceNativeMenu: true
};

const kqlTemplates = {
  ip: `// RAIN Hunt: IP Address
let IOC = "IP_VALUE";
DeviceNetworkEvents
| where RemoteIP == IOC or LocalIP == IOC
| project Timestamp, DeviceName, ActionType, LocalIP, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| sort by Timestamp desc | take 100`,

  domain: `// RAIN Hunt: Domain/URL
let IOC = "DOMAIN_VALUE";
union
(DeviceNetworkEvents | where RemoteUrl has IOC | project Timestamp, DeviceName, ActionType, RemoteUrl, InitiatingProcessFileName),
(EmailUrlInfo | where Url has IOC | project Timestamp, NetworkMessageId, Url)
| sort by Timestamp desc | take 100`,

  hash: `// RAIN Hunt: File Hash (MD5/SHA1/SHA256)
let IOC = "HASH_VALUE";
union
(DeviceFileEvents | where MD5 == IOC or SHA1 == IOC or SHA256 == IOC | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName),
(DeviceProcessEvents | where MD5 == IOC or SHA1 == IOC or SHA256 == IOC | project Timestamp, DeviceName, ActionType, FileName, SHA256, InitiatingProcessParentFileName),
(DeviceImageLoads | where MD5 == IOC or SHA1 == IOC or SHA256 == IOC | project Timestamp, DeviceName, ActionType = "ImageLoaded", FileName, SHA256, InitiatingProcessFileName)
| sort by Timestamp desc | take 100`,

  account: `// RAIN Hunt: Account or Email
let IOC = "ACCOUNT_VALUE";
union
(IdentityLogonEvents | where AccountName has IOC or AccountUpn has IOC | project Timestamp, ActionType, AccountName, AccountUpn, IPAddress, DeviceName),
(EmailEvents | where SenderMailFromAddress has IOC or RecipientEmailAddress has IOC | project Timestamp, Subject, SenderMailFromAddress, RecipientEmailAddress, NetworkMessageId)
| sort by Timestamp desc | take 100`,

  cve: `// RAIN Hunt: Vulnerability (CVE)
let IOC = "CVE_VALUE";
DeviceTvmSoftwareVulnerabilities
| where CveId == IOC
| project DeviceName, OSPlatform, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel
| take 100`,

  useragent: `// RAIN Parse: User-Agent
print useragent = "USERAGENT_VALUE"
| extend Parsed = parse_user_agent(
    useragent,
    dynamic(["browser", "os", "device"])
)
| project
    useragent,
    BrowserFamily = iff(isempty(tostring(Parsed.Browser.Family)), "unknown", tostring(Parsed.Browser.Family)),
    BrowserMajor = iff(isempty(tostring(Parsed.Browser.MajorVersion)), "unknown", tostring(Parsed.Browser.MajorVersion)),
    BrowserMinor = iff(isempty(tostring(Parsed.Browser.MinorVersion)), "unknown", tostring(Parsed.Browser.MinorVersion)),
    OSFamily = iff(isempty(tostring(Parsed.OperatingSystem.Family)), "unknown", tostring(Parsed.OperatingSystem.Family)),
    OSVersion = case(
        isempty(tostring(Parsed.OperatingSystem.MajorVersion)) and isempty(tostring(Parsed.OperatingSystem.MinorVersion)), "unknown",
        isempty(tostring(Parsed.OperatingSystem.MinorVersion)), tostring(Parsed.OperatingSystem.MajorVersion),
        isempty(tostring(Parsed.OperatingSystem.MajorVersion)), tostring(Parsed.OperatingSystem.MinorVersion),
        strcat(tostring(Parsed.OperatingSystem.MajorVersion), ".", tostring(Parsed.OperatingSystem.MinorVersion))
    ),
    DeviceFamily = iff(isempty(tostring(Parsed.Device.Family)), "unknown", tostring(Parsed.Device.Family)),
    DeviceBrand = iff(isempty(tostring(Parsed.Device.Brand)), "unknown", tostring(Parsed.Device.Brand)),
    DeviceModel = iff(isempty(tostring(Parsed.Device.Model)), "unknown", tostring(Parsed.Device.Model))`
};

const categoryLabels = {
  ip: "IP Address",
  domain: "Domain/URL",
  hash: "File Hash",
  account: "Account/Email",
  cve: "Vulnerability (CVE)",
  useragent: "User-Agent",
  general: "Universal Tools"
};

const categoryShortLabels = {
  ip: "IP",
  domain: "Domain",
  hash: "Hash",
  account: "Account",
  cve: "CVE",
  useragent: "UA"
};

const huntingTools = {
  ip: [
    {
      id: "hunt-ip-whatismyipaddress",
      title: "Hunt in WhatIsMyIpAddress",
      url: "https://whatismyipaddress.com/ip/"
    },
    {
      id: "hunt-ip-talos",
      title: "Hunt in Talos",
      url: "https://talosintelligence.com/reputation_center/lookup?search="
    },
    {
      id: "hunt-ip-vt",
      title: "Hunt in VirusTotal",
      url: "https://www.virustotal.com/gui/search/"
    },
    {
      id: "hunt-ip-urlscan",
      title: "Hunt in URLScan",
      url: "https://urlscan.io/search/#"
    },
    {
      id: "hunt-ip-abuseipdb",
      title: "Hunt in AbuseIPDB",
      url: "https://www.abuseipdb.com/check/"
    },
    {
      id: "hunt-ip-shodan",
      title: "Hunt in Shodan",
      url: "https://www.shodan.io/host/"
    },
    {
      id: "hunt-ip-censys",
      title: "Hunt in Censys",
      url: "https://platform.censys.io/search?q=host.ip%3D%22{IOC}%22"
    },
    {
      id: "hunt-ip-ahq",
      title: "Hunt IP in Defender AHQ",
      url: "https://security.microsoft.com/v2/advanced-hunting"
    }
  ],
  domain: [
    {
      id: "hunt-domain-securityheaders",
      title: "Hunt in Security Headers",
      url: "https://securityheaders.com/?q="
    },
    {
      id: "hunt-domain-vt",
      title: "Hunt in VirusTotal",
      url: "https://www.virustotal.com/gui/search/"
    },
    {
      id: "hunt-domain-urlscan",
      title: "Hunt in URLScan",
      url: "https://urlscan.io/search/#"
    },
    {
      id: "hunt-domain-talos",
      title: "Hunt in Talos",
      url: "https://talosintelligence.com/reputation_center/lookup?search="
    },
    {
      id: "hunt-domain-urlvoid",
      title: "Hunt in URLVoid",
      url: "https://www.urlvoid.com/scan/"
    },
    {
      id: "hunt-domain-mxtoolbox",
      title: "Hunt in MXToolbox (Blacklist)",
      url: "https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a"
    },
    {
      id: "hunt-domain-crt",
      title: "Hunt in Crt.sh (Subdomains)",
      url: "https://crt.sh/?q="
    },
    {
      id: "hunt-domain-censys",
      title: "Hunt in Censys",
      url: "https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q="
    },
    {
      id: "hunt-domain-ahq",
      title: "Hunt Domain in Defender AHQ",
      url: "https://security.microsoft.com/v2/advanced-hunting"
    }
  ],
  hash: [
    {
      id: "hunt-hash-vt",
      title: "Hunt in VirusTotal",
      url: "https://www.virustotal.com/gui/search/"
    },
    {
      id: "hunt-hash-hybrid",
      title: "Hunt in Hybrid Analysis",
      url: "https://www.hybrid-analysis.com/search?query="
    },
    {
      id: "hunt-hash-alienvault",
      title: "Hunt in AlienVault",
      url: "https://otx.alienvault.com/indicator/file/"
    },
    {
      id: "hunt-hash-ahq",
      title: "Hunt Hash in Defender AHQ",
      url: "https://security.microsoft.com/v2/advanced-hunting"
    }
  ],
  account: [
    {
      id: "hunt-account-hibp",
      title: "Hunt in HaveIBeenPwned",
      url: "https://haveibeenpwned.com/account/"
    },
    {
      id: "hunt-account-ahq",
      title: "Hunt Account in Defender AHQ",
      url: "https://security.microsoft.com/v2/advanced-hunting"
    }
  ],
  cve: [
    {
      id: "hunt-cve-nvd",
      title: "Hunt in NIST NVD",
      url: "https://nvd.nist.gov/vuln/detail/"
    },
    {
      id: "hunt-cve-cisa",
      title: "Hunt in CISA KEV Catalog",
      url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search={IOC}&field_date_added_wrapper=all&field_cve="
    },
    {
      id: "hunt-cve-mitre",
      title: "Hunt in MITRE CVE",
      url: "https://cve.mitre.org/cgi-bin/cvename.cgi?name="
    },
    {
      id: "hunt-cve-ahq",
      title: "Hunt CVE in Defender AHQ",
      url: "https://security.microsoft.com/v2/advanced-hunting"
    }
  ],
  useragent: [
    {
      id: "hunt-useragent-ahq",
      title: "Parse User-Agent in Defender AHQ",
      url: "https://security.microsoft.com/v2/advanced-hunting"
    },
    {
      id: "hunt-useragent-cyberchef",
      title: "Parse User-Agent in CyberChef",
      url: "https://gchq.github.io/CyberChef/#recipe=Parse_User_Agent()&input="
    },
    {
      id: "hunt-useragent-google",
      title: "Look up exact string on Google",
      url: "https://www.google.com/search?q=%22{IOC}%22"
    },
    {
      id: "hunt-useragent-github",
      title: "Look up exact string on GitHub",
      url: "https://github.com/search?q=%22{IOC}%22&type=code"
    }
  ],
  general: [
    {
      id: "hunt-general-cyberchef",
      title: "Send to CyberChef (Input)",
      url: "https://gchq.github.io/CyberChef/#input="
    }
  ]
};

const YEET_CATEGORIES = ["ip", "domain", "hash", "cve"];
const AHQ_PENDING_TTL_MS = 10 * 60 * 1000;
const KQL_PLACEHOLDER_SOURCE = "IP_VALUE|DOMAIN_VALUE|HASH_VALUE|ACCOUNT_VALUE|CVE_VALUE|USERAGENT_VALUE";
const KQL_IOC_VARIABLE = "RAIN_IOC_VALUE";

const knownUserAgentPattern = /^(?:Mozilla|Opera|Dalvik|curl|Wget|PostmanRuntime|python-requests|Go-http-client|Java|okhttp|Googlebot|bingbot|DuckDuckBot|YandexBot|facebookexternalhit|Slackbot(?:-LinkExpanding)?|Discordbot|TelegramBot|Amazonbot|Applebot)\/[^\s]+(?:\s|$)/i;
const genericUserAgentPattern = /^[a-z][a-z0-9._-]*\/[^\s()]+(?:\s+\([^)]*\)|\s+[a-z][a-z0-9._-]*\/[^\s()]+)+/i;

function looksLikeUserAgent(text) {
  return knownUserAgentPattern.test(text) || genericUserAgentPattern.test(text);
}

function cleanIOC(text) {
  if (!text) return "";
  let clean = text.trim();

  clean = clean.replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, ".");
  clean = clean.replace(/\[\:\]|\(\:\)/gi, ":");
  clean = clean.replace(/\[@\]|\(@\)|\[at\]|\(at\)/gi, "@");
  clean = clean.replace(/^hxxps/i, "https");
  clean = clean.replace(/^hxxp/i, "http");
  clean = clean.replace(/^meows/i, "https");
  clean = clean.replace(/^meow/i, "http");
  const unquoted = clean.replace(/^["']+|["']+$/g, "");
  if (looksLikeUserAgent(unquoted)) return unquoted;
  clean = clean.replace(/^["'(<\[]+|["')>\]]+$/g, "");

  return clean;
}

function base64ForUrl(str) {
  const bytes = new TextEncoder().encode(str);
  let binString = "";
  for (let i = 0; i < bytes.length; i++) {
    binString += String.fromCharCode(bytes[i]);
  }
  const b64 = btoa(binString);
  return encodeURIComponent(b64);
}

function isValidIpv4(text) {
  const parts = text.split(".");
  return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

function isValidHostname(hostname) {
  const host = hostname.replace(/^\[|\]$/g, "");
  if (!host || host.length > 253) return false;
  if (isValidIpv4(host)) return true;
  if (host.includes(":")) {
    return /^(?=.*:)(?:[a-fA-F0-9]{0,4}:){1,7}[a-fA-F0-9]{0,4}$/.test(host);
  }
  const labels = host.split(".");
  if (labels.length < 2) return false;
  return labels.every(label => (
    label.length >= 1 &&
    label.length <= 63 &&
    /^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(label)
  ));
}

function looksLikeDomainOrUrl(text) {
  if (/\s/.test(text)) return false;
  try {
    const parsed = new URL(/^https?:\/\//i.test(text) ? text : `https://${text}`);
    return (parsed.protocol === "http:" || parsed.protocol === "https:") && isValidHostname(parsed.hostname);
  } catch (_) {
    return false;
  }
}

function getUrlForTool(tool, selectedText) {
  const encoded = encodeURIComponent(selectedText);
  const targetUrl = tool.url;
  if (tool.id.includes("cyberchef")) {
    return targetUrl + base64ForUrl(selectedText);
  }
  if (targetUrl.includes("{IOC}")) {
    return targetUrl.replace("{IOC}", encoded);
  }
  return targetUrl + encoded;
}

function classifyIOC(text) {
  const clean = cleanIOC(text);
  if (!clean) return null;

  const ipv6Pattern = /^(?=.*:)(?:[a-fA-F0-9]{0,4}:){1,7}[a-fA-F0-9]{0,4}$/;
  const hashPattern = /^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$/;
  const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  const cvePattern = /^CVE-\d{4}-\d{4,}$/i;

  if (isValidIpv4(clean)) return "ip";
  if (ipv6Pattern.test(clean) && (clean.match(/::/g) || []).length <= 1 && !clean.includes(":::")) return "ip";
  if (cvePattern.test(clean)) return "cve";
  if (hashPattern.test(clean)) return "hash";
  if (emailPattern.test(clean)) return "account";
  if (looksLikeUserAgent(clean)) return "useragent";
  if (looksLikeDomainOrUrl(clean)) return "domain";

  return null;
}

function kqlStringLiteral(text) {
  const escaped = String(text)
    .replace(/[\r\n\u2028\u2029]+/g, " ")
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"');
  return `"${escaped}"`;
}

function kqlQuoteAt(text, offset) {
  let quote = null;
  for (let i = 0; i < offset; i++) {
    const char = text[i];
    if (char === "\\") {
      i++;
    } else if (quote) {
      if (char === quote) quote = null;
    } else if (char === '"' || char === "'") {
      quote = char;
    }
  }
  return quote;
}

// Attacker-controlled text appears only in a declaration built here. Templates
// receive a fixed variable name, so even unusual custom syntax cannot move IOC
// text out of the controlled string literal.
function renderKqlTemplate(template, ioc) {
  if (typeof template !== "string") throw new TypeError("KQL template must be text.");
  const anyPlaceholder = new RegExp(KQL_PLACEHOLDER_SOURCE);
  if (!anyPlaceholder.test(template)) {
    throw new Error("KQL template must include its documented IOC placeholder.");
  }
  if (template.includes(KQL_IOC_VARIABLE)) {
    throw new Error(`${KQL_IOC_VARIABLE} is reserved for RAIN.`);
  }
  const literal = kqlStringLiteral(ioc);
  const quotedPlaceholder = new RegExp(`(["'])(${KQL_PLACEHOLDER_SOURCE})\\1`, "g");
  let rendered = template.replace(quotedPlaceholder, (match, quote, placeholder, offset, source) => {
    if (kqlQuoteAt(source, offset)) {
      throw new Error(`${placeholder} must be a standalone quoted string or bare token.`);
    }
    return KQL_IOC_VARIABLE;
  });
  const remainingPlaceholder = new RegExp(KQL_PLACEHOLDER_SOURCE, "g");
  rendered = rendered.replace(remainingPlaceholder, (placeholder, offset, source) => {
    if (kqlQuoteAt(source, offset)) {
      throw new Error(`${placeholder} must be a standalone quoted string or bare token.`);
    }
    return KQL_IOC_VARIABLE;
  });
  return `let ${KQL_IOC_VARIABLE} = ${literal};\n${rendered}`;
}

function validateKqlTemplates(templates) {
  if (!templates || typeof templates !== "object" || Array.isArray(templates)) {
    throw new TypeError("KQL templates must be an object.");
  }

  const validated = {};
  for (const category of Object.keys(kqlTemplates)) {
    const template = templates[category];
    if (typeof template !== "string" || !template.trim()) {
      throw new Error(`${categoryLabels[category]} template cannot be empty.`);
    }
    try {
      renderKqlTemplate(template, "RAIN_TEMPLATE_VALIDATION");
    } catch (error) {
      throw new Error(`${categoryLabels[category]} template: ${error.message}`);
    }
    validated[category] = template;
  }
  return validated;
}

function saveKqlTemplates(templates, sendResponse) {
  let validated;
  try {
    validated = validateKqlTemplates(templates);
  } catch (error) {
    sendResponse({ ok: false, error: error.message });
    return;
  }

  chrome.storage.local.set({
    kqlTemplates: validated,
    templatesVersion: TEMPLATE_SCHEMA_VERSION
  }, () => {
    const error = chrome.runtime.lastError;
    if (error) {
      sendResponse({ ok: false, error: error.message || "Template storage failed." });
      return;
    }
    sendResponse({ ok: true });
  });
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(["kqlTemplates", "templatesVersion", "rainSettings"], (data) => {
    if (!data.kqlTemplates) {
      chrome.storage.local.set({ kqlTemplates: kqlTemplates, templatesVersion: TEMPLATE_SCHEMA_VERSION });
    } else {
      const migrated = { ...data.kqlTemplates };
      let changed = data.templatesVersion !== TEMPLATE_SCHEMA_VERSION;

      // One-time v1.0 -> v1.1 migration: only replace the CVE template if it is
      // the old broken default (identified by its header comment), never a custom one.
      if (!data.templatesVersion && migrated.cve && migrated.cve.includes("// RAIN Hunt: Vulnerability (CVE)") && migrated.cve.includes("Timestamp")) {
        migrated.cve = kqlTemplates.cve;
        changed = true;
      }
      if (!migrated.useragent) {
        migrated.useragent = kqlTemplates.useragent;
        changed = true;
      } else if (
        migrated.useragent.includes("// RAIN Parse: User-Agent") &&
        migrated.useragent.includes("| project UserAgent, Browser = Parsed.Browser, OperatingSystem = Parsed.OperatingSystem, Device = Parsed.Device")
      ) {
        // Replace only RAIN's original v3 UA template, never a custom query.
        migrated.useragent = kqlTemplates.useragent;
        changed = true;
      }
      if (changed) {
        chrome.storage.local.set({ kqlTemplates: migrated, templatesVersion: TEMPLATE_SCHEMA_VERSION });
      }
    }

    if (!data.rainSettings) {
      chrome.storage.local.set({ rainSettings: DEFAULT_SETTINGS });
    }
  });

  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: "rain-root",
      title: "RAIN - Hunt IOC",
      contexts: ["selection"]
    });

    for (const [type, title] of Object.entries(categoryLabels)) {
      chrome.contextMenus.create({
        id: `parent-${type}`,
        parentId: "rain-root",
        title: title,
        contexts: ["selection"]
      });

      if (YEET_CATEGORIES.includes(type)) {
        chrome.contextMenus.create({
          id: `hunt-${type}-yeet`,
          parentId: `parent-${type}`,
          title: "Yeet Search (all tools)",
          contexts: ["selection"]
        });
      }

      huntingTools[type].forEach(tool => {
        chrome.contextMenus.create({
          id: tool.id,
          parentId: `parent-${type}`,
          title: tool.title,
          contexts: ["selection"]
        });
      });
    }
  });
});

// Pending Defender AHQ injections live in storage.session so they survive
// service worker suspension while the (slow) portal tab is still loading.
function setPendingInjection(tabId, ioc, category) {
  chrome.storage.session.set({ [`ahq-${tabId}`]: { ioc, category, at: Date.now() } }, () => {
    if (chrome.runtime.lastError) {
      console.error("RAIN: Failed to retain pending Defender query:", chrome.runtime.lastError);
    }
  });
}

function isDefenderUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" && parsed.hostname === "security.microsoft.com";
  } catch (_) {
    return false;
  }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete") return;
  const key = `ahq-${tabId}`;
  chrome.storage.session.get(key, (data) => {
    const pending = data[key];
    if (!pending) return;
    if (pending.at && Date.now() - pending.at > AHQ_PENDING_TTL_MS) {
      chrome.storage.session.remove(key);
      return;
    }
    // Authentication pages may complete before Defender does. Keep the entry
    // through those redirects and consume it only once the target origin is ready.
    if (!isDefenderUrl(tab?.url || changeInfo.url || "")) return;
    injectKQLQuery(tabId, pending.ioc, pending.category, () => {
      chrome.storage.session.remove(key);
    });
  });
});

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove(`ahq-${tabId}`);
});

function injectKQLQuery(tabId, ioc, category, onScheduled) {
  chrome.tabs.get(tabId, (tab) => {
    const err = chrome.runtime.lastError;
    if (err || !tab || !tab.url) {
      console.error("RAIN: Failed to retrieve tab details or tab lacks URL:", err);
      return;
    }

    if (!isDefenderUrl(tab.url)) {
      console.error("RAIN: Script injection blocked. Target tab URL origin mismatch:", tab.url);
      return;
    }

    chrome.storage.local.get("kqlTemplates", (data) => {
      const stored = data.kqlTemplates || {};
      const activeTemplates = {};
      for (const key of Object.keys(kqlTemplates)) {
        activeTemplates[key] = stored[key] || kqlTemplates[key];
      }

      const queryTemplate = activeTemplates[category] || activeTemplates.ip;
      let finalQuery;
      try {
        finalQuery = renderKqlTemplate(queryTemplate, ioc);
      } catch (error) {
        console.warn("RAIN: Custom KQL template has an unsafe placeholder context; using the default template.", error);
        finalQuery = renderKqlTemplate(kqlTemplates[category] || kqlTemplates.ip, ioc);
      }
      const iocProbe = kqlStringLiteral(ioc);

      chrome.scripting.executeScript({
        target: { tabId: tabId },
        world: "MAIN",
        func: (queryValue, valueProbe) => {
          let attempts = 0;
          const interval = setInterval(() => {
            const models = window.monaco?.editor?.getModels?.();
            if (models?.length > 0) {
              models[0].setValue(queryValue);
              console.log("RAIN: KQL query injected successfully.");
              clearInterval(interval);

              // Preserve the original, known-working Defender injector. The
              // portal can reset Monaco several times while it finishes loading.
              [1000, 2500, 4000].forEach(delay => {
                setTimeout(() => {
                  if (models[0] && !models[0].getValue().includes(valueProbe)) {
                    models[0].setValue(queryValue);
                    console.log(`RAIN: Query reinforced after ${delay}ms`);
                  }
                }, delay);
              });
            } else {
              if (++attempts > 60) {
                console.warn("RAIN: Monaco editor not loaded in time.");
                clearInterval(interval);
              }
            }
          }, 500);
        },
        args: [finalQuery, iocProbe]
      }, () => {
        const injectErr = chrome.runtime.lastError;
        if (injectErr) {
          console.error("RAIN: Script injection failed:", injectErr);
          return;
        }
        if (onScheduled) onScheduled();
      });
    });
  });
}

function findTool(toolId) {
  return Object.values(huntingTools).flat().find(t => t.id === toolId) || null;
}

function categoryOfTool(toolId) {
  for (const [cat, tools] of Object.entries(huntingTools)) {
    if (tools.some(t => t.id === toolId)) return cat;
  }
  return null;
}

const TOOL_INITIALS = {
  "hunt-ip-talos": "TA",
  "hunt-ip-vt": "VT",
  "hunt-ip-urlscan": "US",
  "hunt-ip-abuseipdb": "AB",
  "hunt-ip-shodan": "SH",
  "hunt-ip-censys": "CE",
  "hunt-ip-ahq": "MD",
  "hunt-domain-vt": "VT",
  "hunt-domain-urlscan": "US",
  "hunt-domain-talos": "TA",
  "hunt-domain-urlvoid": "UV",
  "hunt-domain-mxtoolbox": "MX",
  "hunt-domain-crt": "CT",
  "hunt-domain-censys": "CE",
  "hunt-domain-ahq": "MD",
  "hunt-hash-vt": "VT",
  "hunt-hash-hybrid": "HA",
  "hunt-hash-alienvault": "OTX",
  "hunt-hash-ahq": "MD",
  "hunt-account-hibp": "HP",
  "hunt-account-ahq": "MD",
  "hunt-cve-nvd": "NVD",
  "hunt-cve-cisa": "KEV",
  "hunt-cve-mitre": "CVE",
  "hunt-cve-ahq": "MD",
  "hunt-useragent-ahq": "MD",
  "hunt-useragent-cyberchef": "CC",
  "hunt-useragent-google": "G",
  "hunt-useragent-github": "GH",
  "hunt-general-cyberchef": "CC"
};

function toolForClient(tool) {
  let faviconUrl = tool.faviconUrl || "";
  if (!faviconUrl) {
    try {
      faviconUrl = new URL(tool.url).origin;
    } catch (_) {}
  }
  return {
    id: tool.id,
    title: tool.title,
    initials: TOOL_INITIALS[tool.id] || "?",
    faviconUrl
  };
}

function createTabSafely(options) {
  return new Promise(resolve => {
    chrome.tabs.create(options, (newTab) => {
      const err = chrome.runtime.lastError;
      if (err || !newTab?.id) {
        console.error("RAIN: Failed to open hunting tab:", err || "No tab was returned.");
        resolve(null);
        return;
      }
      resolve(newTab);
    });
  });
}

function createToolTab(tool, ioc, category, active = true) {
  return createTabSafely({ url: tool.id.includes("ahq") ? tool.url : getUrlForTool(tool, ioc), active })
    .then(newTab => {
      if (newTab && tool.id.includes("ahq")) {
        setPendingInjection(newTab.id, ioc, category);
      }
      return newTab;
    });
}

function huntWithTool(toolId, ioc) {
  const tool = findTool(toolId);
  if (!tool || !ioc) return;
  return createToolTab(tool, ioc, categoryOfTool(toolId));
}

function yeetCategory(category, ioc) {
  const tools = huntingTools[category];
  if (!tools || !ioc) return;

  const createdTabIds = [];

  Promise.all(tools.map(tool => createToolTab(tool, ioc, category, false))).then(createdTabs => {
    createdTabs.forEach(tab => {
      if (tab?.id) createdTabIds.push(tab.id);
    });
    if (createdTabIds.length === 0) return;
    chrome.tabs.group({ tabIds: createdTabIds }, groupId => {
      const groupErr = chrome.runtime.lastError;
      if (groupErr || typeof groupId !== "number") {
        console.error("RAIN: Failed to group hunting tabs:", groupErr || "No group was returned.");
        return;
      }
      chrome.tabGroups.update(groupId, {
        title: `${category.charAt(0).toUpperCase() + category.slice(1)} Search`,
        color: {
          ip: "blue",
          domain: "green",
          hash: "orange",
          account: "purple",
          cve: "red"
        }[category] || "grey",
        collapsed: true
      }, () => {
        if (chrome.runtime.lastError) {
          console.error("RAIN: Failed to label hunting tab group:", chrome.runtime.lastError);
        }
      });
    });
  });
}

chrome.contextMenus.onClicked.addListener((info) => {
  const rawSelection = info.selectionText?.trim();
  if (!rawSelection) return;

  const selectedText = cleanIOC(rawSelection);
  const menuItemId = String(info.menuItemId);

  if (menuItemId.includes("yeet")) {
    yeetCategory(menuItemId.split("-")[1], selectedText);
    return;
  }

  huntWithTool(menuItemId, selectedText);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.action) {
    case "getDefaultTemplates":
      sendResponse({ defaultTemplates: kqlTemplates });
      break;

    case "saveKqlTemplates":
      saveKqlTemplates(message.templates, sendResponse);
      return true;

    case "classify": {
      const ioc = cleanIOC(message.text || "");
      const detected = classifyIOC(ioc);
      // The UI can override the detected type when classification is wrong
      // or the indicator wasn't recognized.
      const category = (message.overrideCategory && huntingTools[message.overrideCategory])
        ? message.overrideCategory
        : detected;
      const tools = category
        ? huntingTools[category].map(toolForClient)
        : [];
      sendResponse({
        ioc,
        category,
        detectedCategory: detected,
        categoryLabel: category ? categoryLabels[category] : "Select IOC type",
        tools,
        generalTools: huntingTools.general.map(toolForClient),
        canYeet: YEET_CATEGORIES.includes(category),
        categories: Object.keys(categoryShortLabels).map(id => ({
          id,
          label: categoryLabels[id],
          short: categoryShortLabels[id]
        }))
      });
      break;
    }

    case "hunt":
      huntWithTool(message.toolId, message.ioc);
      break;

    case "yeet":
      yeetCategory(message.category, message.ioc);
      break;

    case "openShortcuts":
      createTabSafely({ url: "chrome://extensions/shortcuts" });
      break;
  }
  // Only template persistence keeps the response channel open.
  return false;
});

function pendingPanelKey(windowId) {
  return `pendingPanelIoc-${windowId}`;
}

// Opens the RAIN side panel, optionally prefilled with an IOC. A global side
// panel is one instance per browser window, so pending state uses that same
// boundary and is consumed by the matching panel after it opens.
function openHuntPanel(tabId, windowId, ioc) {
  if (typeof windowId === "number") {
    chrome.storage.session.set({
      [pendingPanelKey(windowId)]: { ioc: ioc || "", at: Date.now() }
    }, () => {
      if (chrome.runtime.lastError) {
        console.error("RAIN: Failed to prefill side panel:", chrome.runtime.lastError);
      }
    });
  } else {
    console.warn("RAIN: Side-panel prefill skipped because the browser window was unavailable.");
  }
  chrome.sidePanel.open({ tabId }).catch(err => {
    console.error("RAIN: side panel failed to open:", err);
  });
}

// Injected into every frame to read the selection. Reaches into places a
// plain getSelection() misses: focused inputs/textareas, and shadow DOM
// selections via the Chromium-specific ShadowRoot.getSelection(), which
// portals like Microsoft Defender rely on for much of their UI.
function readSelectionDeep() {
  const sel = window.getSelection && window.getSelection();
  if (sel && String(sel).trim()) {
    const sel2 = String(sel).trim();
    // Check if selection is inside a hyperlink
    if (sel.rangeCount > 0) {
      let node = sel.anchorNode;
      if (node && node.nodeType === Node.TEXT_NODE) {
        node = node.parentElement;
      }
      if (node && node.closest) {
        const link = node.closest("a");

        if (link && link.href) {
          return link.href;
        }
      }
    }
    // No hyperlink, return highlighted text
    return sel2;
  } else {
    return "";
  }

  const el = document.activeElement;
  try {
    if (el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA") && el.selectionStart != null) {
      const s = String(el.value.substring(el.selectionStart, el.selectionEnd));
      if (s.trim()) return s;
    }
  } catch (e) {
    // Some input types don't support selection ranges.
  }

  let root = el && el.shadowRoot;
  while (root) {
    if (typeof root.getSelection === "function") {
      const s = String(root.getSelection());
      if (s.trim()) return s;
    }
    const inner = root.activeElement;
    root = inner ? inner.shadowRoot : null;
  }
  return "";
}

chrome.commands.onCommand.addListener((command, tab) => {
  if (command !== "hunt-selection" || !tab?.id) return;

  chrome.scripting.executeScript({
    target: { tabId: tab.id, allFrames: true },
    func: readSelectionDeep
  }, (results) => {
    if (chrome.runtime.lastError) {
      // Restricted page (chrome://, web store): the page can't host the
      // in-page menu, but the side panel can still hunt a pasted IOC.
      openHuntPanel(tab.id, tab.windowId, "");
      return;
    }

    const text = (results || []).map(r => r && r.result).find(t => t && t.trim()) || "";

    if (!text.trim()) {
      // Nothing readable on the page: hunt from the side panel instead.
      openHuntPanel(tab.id, tab.windowId, "");
      return;
    }

    chrome.tabs.sendMessage(tab.id, { action: "show-hunt-menu" }, () => {
      if (chrome.runtime.lastError) {
        // No frame could show the in-page menu (content script missing, or
        // the selection lives somewhere the page menu can't anchor to):
        // open the side panel with the selection prefilled.
        openHuntPanel(tab.id, tab.windowId, cleanIOC(text));
      }
    });
  });
});
