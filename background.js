const TEMPLATE_SCHEMA_VERSION = 2;

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
| take 100`
};

const categoryLabels = {
  ip: "IP Address",
  domain: "Domain/URL",
  hash: "File Hash",
  account: "Account/Email",
  cve: "Vulnerability (CVE)",
  general: "Universal Tools"
};

const categoryShortLabels = {
  ip: "IP",
  domain: "Domain",
  hash: "Hash",
  account: "Account",
  cve: "CVE"
};

const huntingTools = {
  ip: [
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
  general: [
    {
      id: "hunt-general-cyberchef",
      title: "Send to CyberChef (Input)",
      url: "https://gchq.github.io/CyberChef/#input="
    }
  ]
};

const YEET_CATEGORIES = ["ip", "domain", "hash", "cve"];

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
  clean = clean.replace(/^["'(<\[]+|["')>\]]+$/g, "");

  return clean;
}

function base64url(str) {
  const bytes = new TextEncoder().encode(str);
  let binString = "";
  for (let i = 0; i < bytes.length; i++) {
    binString += String.fromCharCode(bytes[i]);
  }
  const b64 = btoa(binString);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function getUrlForTool(tool, selectedText) {
  const encoded = encodeURIComponent(selectedText);
  if (tool.id.includes("cyberchef")) {
    return tool.url + base64url(selectedText);
  }
  if (tool.url.includes("{IOC}")) {
    return tool.url.replace("{IOC}", encoded);
  }
  return tool.url + encoded;
}

function classifyIOC(text) {
  const clean = cleanIOC(text);
  if (!clean) return null;

  const ipv4Pattern = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const ipv6Pattern = /^(?=.*:)(?:[a-fA-F0-9]{0,4}:){1,7}[a-fA-F0-9]{0,4}$/;
  const domainPattern = /^(?:https?:\/\/)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:\/.*)?$/;
  const hashPattern = /^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$/;
  const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  const cvePattern = /^CVE-\d{4}-\d{4,}$/i;

  if (ipv4Pattern.test(clean)) return "ip";
  if (ipv6Pattern.test(clean) && (clean.match(/::/g) || []).length <= 1 && !clean.includes(":::")) return "ip";
  if (cvePattern.test(clean)) return "cve";
  if (hashPattern.test(clean)) return "hash";
  if (emailPattern.test(clean)) return "account";
  if (domainPattern.test(clean)) return "domain";

  return null;
}

// Escape only what breaks out of a double-quoted KQL string literal;
// other escapes (', `) are not valid KQL sequences and would corrupt the IOC.
function sanitizeForKql(text) {
  return text
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"');
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(["kqlTemplates", "templatesVersion", "rainSettings"], (data) => {
    if (!data.kqlTemplates) {
      chrome.storage.local.set({ kqlTemplates: kqlTemplates, templatesVersion: TEMPLATE_SCHEMA_VERSION });
    } else if (!data.templatesVersion) {
      // One-time v1.0 -> v1.1 migration: only replace the CVE template if it is
      // the old broken default (identified by its header comment), never a custom one.
      const migrated = { ...data.kqlTemplates };
      if (migrated.cve && migrated.cve.includes("// RAIN Hunt: Vulnerability (CVE)") && migrated.cve.includes("Timestamp")) {
        migrated.cve = kqlTemplates.cve;
      }
      chrome.storage.local.set({ kqlTemplates: migrated, templatesVersion: TEMPLATE_SCHEMA_VERSION });
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
  chrome.storage.session.set({ [`ahq-${tabId}`]: { ioc, category } });
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status !== "complete") return;
  const key = `ahq-${tabId}`;
  chrome.storage.session.get(key, (data) => {
    if (data[key]) {
      chrome.storage.session.remove(key);
      injectKQLQuery(tabId, data[key].ioc, data[key].category);
    }
  });
});

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove(`ahq-${tabId}`);
});

function injectKQLQuery(tabId, ioc, category) {
  chrome.tabs.get(tabId, (tab) => {
    const err = chrome.runtime.lastError;
    if (err || !tab || !tab.url) {
      console.error("RAIN: Failed to retrieve tab details or tab lacks URL:", err);
      return;
    }

    try {
      const urlObj = new URL(tab.url);
      if (urlObj.protocol !== "https:" || urlObj.hostname !== "security.microsoft.com") {
        console.error("RAIN: Script injection blocked. Target tab URL origin mismatch:", tab.url);
        return;
      }
    } catch (e) {
      console.error("RAIN: Invalid target tab URL:", e);
      return;
    }

    chrome.storage.local.get("kqlTemplates", (data) => {
      const stored = data.kqlTemplates || {};
      const activeTemplates = {};
      for (const key of Object.keys(kqlTemplates)) {
        activeTemplates[key] = stored[key] || kqlTemplates[key];
      }

      const sanitizedIoc = sanitizeForKql(ioc);

      chrome.scripting.executeScript({
        target: { tabId: tabId },
        world: "MAIN",
        func: (iocValue, categoryValue, templates) => {
          const queryTemplate = templates[categoryValue] || templates.ip;
          // Function replacement so "$" sequences in the IOC are inserted literally.
          const finalQuery = queryTemplate.replace(/IP_VALUE|DOMAIN_VALUE|HASH_VALUE|ACCOUNT_VALUE|CVE_VALUE/g, () => iocValue);

          let attempts = 0;
          const interval = setInterval(() => {
            const models = window.monaco?.editor?.getModels?.();
            if (models?.length > 0) {
              models[0].setValue(finalQuery);
              console.log("RAIN: KQL query injected successfully.");
              clearInterval(interval);

              // The portal sometimes resets the editor while it finishes loading.
              // Only re-set if our IOC vanished, so analyst edits are never stomped.
              [1000, 2500, 4000].forEach(delay => {
                setTimeout(() => {
                  if (models[0] && !models[0].getValue().includes(iocValue)) {
                    models[0].setValue(finalQuery);
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
        args: [sanitizedIoc, category, activeTemplates]
      }, () => {
        const injectErr = chrome.runtime.lastError;
        if (injectErr) {
          console.error("RAIN: Script injection failed:", injectErr);
        }
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

function huntWithTool(toolId, ioc) {
  const tool = findTool(toolId);
  if (!tool || !ioc) return;

  if (tool.id.includes("ahq")) {
    chrome.tabs.create({ url: tool.url }, (newTab) => {
      setPendingInjection(newTab.id, ioc, categoryOfTool(toolId));
    });
  } else {
    chrome.tabs.create({ url: getUrlForTool(tool, ioc) });
  }
}

function yeetCategory(category, ioc) {
  const tools = huntingTools[category];
  if (!tools || !ioc) return;

  const createdTabIds = [];

  Promise.all(tools.map(tool => {
    return new Promise(resolve => {
      if (tool.id.includes("ahq")) {
        chrome.tabs.create({ url: tool.url, active: false }, newTab => {
          setPendingInjection(newTab.id, ioc, category);
          createdTabIds.push(newTab.id);
          resolve();
        });
      } else {
        chrome.tabs.create({ url: getUrlForTool(tool, ioc), active: false }, newTab => {
          createdTabIds.push(newTab.id);
          resolve();
        });
      }
    });
  })).then(() => {
    if (createdTabIds.length === 0) return;
    chrome.tabs.group({ tabIds: createdTabIds }, groupId => {
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

    case "classify": {
      const ioc = cleanIOC(message.text || "");
      const detected = classifyIOC(ioc);
      // The UI can override the detected type when classification is wrong
      // or the indicator wasn't recognized.
      const category = (message.overrideCategory && huntingTools[message.overrideCategory])
        ? message.overrideCategory
        : detected;
      const tools = category
        ? huntingTools[category].map(t => ({ id: t.id, title: t.title }))
        : [];
      sendResponse({
        ioc,
        category,
        detectedCategory: detected,
        categoryLabel: category ? categoryLabels[category] : "Select IOC type",
        tools,
        generalTools: huntingTools.general.map(t => ({ id: t.id, title: t.title })),
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
      chrome.tabs.create({ url: "chrome://extensions/shortcuts" });
      break;
  }
  // All responses above are synchronous; no open channel is kept.
});

// Opens the RAIN side panel, optionally prefilled with an IOC.
// storage.session is set fire-and-forget and sidePanel.open() is called in
// the same tick: open() requires the user-gesture context, which survives
// chrome API callbacks but should not wait on further async hops.
function openHuntPanel(tabId, ioc) {
  chrome.storage.session.set({ pendingPanelIoc: { ioc: ioc || "", at: Date.now() } });
  chrome.sidePanel.open({ tabId }).catch(err => {
    console.error("RAIN: side panel failed to open:", err);
  });
}

// Injected into every frame to read the selection. Reaches into places a
// plain getSelection() misses: focused inputs/textareas, and shadow DOM
// selections via the Chromium-specific ShadowRoot.getSelection(), which
// portals like Microsoft Defender rely on for much of their UI.
function readSelectionDeep() {
  const sel = window.getSelection && String(window.getSelection());
  if (sel && sel.trim()) return sel;

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
      openHuntPanel(tab.id, "");
      return;
    }

    const text = (results || []).map(r => r && r.result).find(t => t && t.trim()) || "";

    if (!text.trim()) {
      // Nothing readable on the page: hunt from the side panel instead.
      openHuntPanel(tab.id, "");
      return;
    }

    chrome.tabs.sendMessage(tab.id, { action: "show-hunt-menu" }, () => {
      if (chrome.runtime.lastError) {
        // No frame could show the in-page menu (content script missing, or
        // the selection lives somewhere the page menu can't anchor to):
        // open the side panel with the selection prefilled.
        openHuntPanel(tab.id, cleanIOC(text));
      }
    });
  });
});
