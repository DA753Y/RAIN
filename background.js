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
      title: "Hunt Domain in Defender Advanced Hunting",
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

const pendingAHQInjections = new Map();

function cleanIOC(text) {
  if (!text) return "";
  let clean = text.trim();
  
  clean = clean.replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, ".");
  clean = clean.replace(/\[\:\]|\(\:\)/gi, ":");
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

  const ipPattern = /^(?:^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$)|^(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}$/;
  const domainPattern = /^(?:https?:\/\/)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:\/.*)?$/;
  const md5Pattern = /^[a-fA-F0-9]{32}$/;
  const sha1Pattern = /^[a-fA-F0-9]{40}$/;
  const sha256Pattern = /^[a-fA-F0-9]{64}$/;
  const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  const cvePattern = /^CVE-\d{4}-\d{4,}$/i;

  if (ipPattern.test(clean)) return "ip";
  if (cvePattern.test(clean)) return "cve";
  if (md5Pattern.test(clean) || sha1Pattern.test(clean) || sha256Pattern.test(clean)) return "hash";
  if (emailPattern.test(clean)) return "account";
  if (domainPattern.test(clean)) return "domain";

  return null;
}

function sanitizeForKql(text) {
  return text
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/'/g, "\\'")
    .replace(/`/g, "\\`");
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get("kqlTemplates", (data) => {
    if (!data.kqlTemplates) {
      chrome.storage.local.set({ kqlTemplates: kqlTemplates });
      console.log("RAIN: Default KQL templates initialized in storage.");
    }
  });

  const categories = {
    ip: "IP Address",
    domain: "Domain/URL",
    hash: "File Hash",
    account: "Account/Email",
    cve: "Vulnerability (CVE)",
    general: "Universal Tools"
  };

  chrome.contextMenus.create({
    id: "rain-root",
    title: "RAIN - Hunt IOC",
    contexts: ["selection"]
  });

  for (const [type, title] of Object.entries(categories)) {
    chrome.contextMenus.create({
      id: `parent-${type}`,
      parentId: "rain-root",
      title: title,
      contexts: ["selection"]
    });

    if (type !== "general" && type !== "account") {
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
      let activeTemplates = data.kqlTemplates || kqlTemplates;
      
      if (activeTemplates.cve && activeTemplates.cve.includes("Timestamp")) {
        activeTemplates.cve = kqlTemplates.cve;
        chrome.storage.local.set({ kqlTemplates: activeTemplates });
        console.log("RAIN: Obsolete background CVE template migrated successfully.");
      }

      const sanitizedIoc = sanitizeForKql(ioc);

      chrome.scripting.executeScript({
        target: { tabId: tabId },
        world: "MAIN",
        func: (iocValue, categoryValue, templates) => {
          const queryTemplate = templates[categoryValue] || templates.ip;
          const finalQuery = queryTemplate.replace(/IP_VALUE|DOMAIN_VALUE|HASH_VALUE|ACCOUNT_VALUE|CVE_VALUE/g, iocValue);

          let attempts = 0;
          const interval = setInterval(() => {
            const models = window.monaco?.editor?.getModels?.();
            if (models?.length > 0) {
              models[0].setValue(finalQuery);
              console.log("RAIN: KQL query injected successfully.");
              clearInterval(interval);

              [1000, 2500, 4000].forEach(delay => {
                setTimeout(() => {
                  if (models[0] && models[0].getValue() !== finalQuery) {
                    models[0].setValue(finalQuery);
                    console.log(`RAIN: Query reinforced after ${delay}ms`);
                  }
                }, delay);
              });
            } else {
              console.log("RAIN: Waiting for Monaco editor... attempt", attempts);
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

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && pendingAHQInjections.has(tabId)) {
    const data = pendingAHQInjections.get(tabId);
    pendingAHQInjections.delete(tabId);
    injectKQLQuery(tabId, data.ioc, data.category);
  }
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  const rawSelection = info.selectionText?.trim();
  if (!rawSelection) return;

  const selectedText = cleanIOC(rawSelection);
  const menuItemId = info.menuItemId;

  if (menuItemId.includes("yeet")) {
    const category = menuItemId.split("-")[1];
    const toolsToOpen = huntingTools[category].filter(tool => !tool.id.includes("ahq"));
    const createdTabIds = [];

    Promise.all(toolsToOpen.map(tool => {
      return new Promise(resolve => {
        if (tool.id.includes("ahq")) {
          chrome.tabs.create({ url: tool.url, active: false }, newTab => {
            pendingAHQInjections.set(newTab.id, { ioc: selectedText, category: category });
            createdTabIds.push(newTab.id);
            resolve();
          });
        } else {
          const fullUrl = getUrlForTool(tool, selectedText);
          chrome.tabs.create({ url: fullUrl, active: false }, newTab => {
            createdTabIds.push(newTab.id);
            resolve();
          });
        }
      });
    })).then(() => {
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

    return;
  }

  const allTools = Object.values(huntingTools).flat();
  const tool = allTools.find(t => t.id === menuItemId);
  if (!tool) return;

  let category = "ip";
  for (const [cat, tools] of Object.entries(huntingTools)) {
    if (tools.some(t => t.id === menuItemId)) {
      category = cat;
      break;
    }
  }

  if (tool.id.includes("ahq")) {
    chrome.tabs.create({ url: tool.url }, (newTab) => {
      pendingAHQInjections.set(newTab.id, { ioc: selectedText, category: category });
    });
  } else {
    const fullUrl = getUrlForTool(tool, selectedText);
    chrome.tabs.create({ url: fullUrl });
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "getDefaultTemplates") {
    sendResponse({ defaultTemplates: kqlTemplates });
  }
  return true;
});
