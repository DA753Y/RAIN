const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const listeners = {};
let capturedScript = null;
const localData = {};
const sessionData = {};
const event = (name) => ({ addListener(fn) { listeners[name] = fn; } });
const chrome = {
  runtime: {
    lastError: null,
    getURL: (path) => `chrome-extension://rain-test/${path}`,
    onInstalled: event("installed"),
    onMessage: event("message")
  },
  tabs: {
    get: (_tabId, callback) => callback({ url: "https://security.microsoft.com/v2/advanced-hunting" }),
    onUpdated: event("tab-updated"),
    onRemoved: event("tab-removed")
  },
  contextMenus: { onClicked: event("context-clicked") },
  commands: { onCommand: event("command") },
  storage: {
    local: { get: (_key, callback) => callback(localData) },
    session: {
      get: (key, callback) => callback({ [key]: sessionData[key] }),
      set: (values, callback) => { Object.assign(sessionData, values); if (callback) callback(); },
      remove: (key, callback) => { delete sessionData[key]; if (callback) callback(); }
    }
  },
  sidePanel: {},
  scripting: { executeScript: (details, callback) => { capturedScript = details; callback(); } },
  tabGroups: {}
};

const context = vm.createContext({ chrome, console, URL, TextEncoder, btoa, setTimeout, setInterval, clearTimeout, clearInterval });
vm.runInContext(fs.readFileSync("background.js", "utf8"), context, { filename: "background.js" });

function classify(text, overrideCategory) {
  let response;
  listeners.message({ action: "classify", text, overrideCategory }, {}, value => { response = value; });
  return response;
}

const chromeUa = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
assert.equal(classify(chromeUa).category, "useragent");
assert.equal(classify("curl/8.10.1").category, "useragent");
assert.equal(classify("Googlebot/2.1 (+http://www.google.com/bot.html)").ioc.endsWith(")"), true);
assert.equal(classify('"Googlebot/2.1 (+http://www.google.com/bot.html)"').ioc.endsWith(")"), true);
assert.equal(classify("example.com/path").category, "domain");
assert.equal(classify("999.999.999.999").category, null);
assert.equal(classify("https://example.com:443/path").category, "domain");
assert.equal(classify("example.com?x=1").category, "domain");
assert.equal(classify("https://example.com/path with spaces").category, null);
assert.deepEqual(Array.from(classify(chromeUa).tools, tool => tool.id), [
  "hunt-useragent-ahq",
  "hunt-useragent-cyberchef",
  "hunt-useragent-google",
  "hunt-useragent-github"
]);
assert.equal(classify("unrecognized value", "useragent").category, "useragent");
for (const category of ["ip", "domain", "hash", "account", "cve", "useragent"]) {
  const response = classify("manual value", category);
  response.tools.forEach(tool => {
    assert.ok(tool.initials, `${tool.id} should have fallback initials`);
    assert.ok(tool.faviconUrl, `${tool.id} should have a favicon source`);
  });
}

const uaTemplate = vm.runInContext("kqlTemplates.useragent", context);
assert.match(uaTemplate, /parse_user_agent/);
assert.match(uaTemplate, /USERAGENT_VALUE/);
assert.match(uaTemplate, /BrowserFamily = iff\(isempty\(tostring\(Parsed\.Browser\.Family\)\), "unknown"/);
assert.match(uaTemplate, /OSVersion = case\(/);
assert.match(uaTemplate, /DeviceModel = iff\(isempty\(tostring\(Parsed\.Device\.Model\)\), "unknown"/);
const maliciousIoc = "x' or 1 == 1 or RemoteIP == 'x";
const safeCustomQuery = vm.runInContext(
  `renderKqlTemplate(${JSON.stringify("DeviceNetworkEvents | where RemoteIP == 'IP_VALUE'")}, ${JSON.stringify(maliciousIoc)})`,
  context
);
assert.equal(
  safeCustomQuery,
  `let __RAIN_IOC_VALUE = "x' or 1 == 1 or RemoteIP == 'x";\nDeviceNetworkEvents | where RemoteIP == __RAIN_IOC_VALUE`
);
assert.throws(() => vm.runInContext(
  `renderKqlTemplate(${JSON.stringify('print value = "prefix IP_VALUE suffix"')}, "test")`,
  context
), /standalone quoted string/);

vm.runInContext(`injectKQLQuery(7, ${JSON.stringify('Mozilla/5.0 "quoted"\nline\\path')}, "useragent")`, context);
assert.equal(capturedScript.args.length, 1);
assert.match(capturedScript.args[0], /parse_user_agent/);
assert.match(capturedScript.args[0], /Mozilla\/5\.0 \\"quoted\\" line\\\\path/);
assert.doesNotMatch(capturedScript.func.toString(), /models\[0\]/);
assert.doesNotMatch(capturedScript.func.toString(), /setTimeout/);
let injectedQuery = null;
const intervalCallbacks = [];
const inactiveEditor = {
  hasTextFocus: () => false,
  getDomNode: () => ({ isConnected: true, getClientRects: () => [] }),
  getModel: () => ({ setValue: () => assert.fail("inactive editor must not be changed") })
};
const activeEditor = {
  hasTextFocus: () => true,
  getDomNode: () => ({ isConnected: true, getClientRects: () => [{}] }),
  getModel: () => ({ setValue: value => { injectedQuery = value; } })
};
context.window = { monaco: { editor: { getEditors: () => [inactiveEditor, activeEditor] } } };
context.setInterval = fn => { intervalCallbacks.push(fn); return intervalCallbacks.length; };
context.clearInterval = () => {};
capturedScript.func(...capturedScript.args);
assert.equal(intervalCallbacks.length, 1);
intervalCallbacks[0]();
assert.equal(injectedQuery, capturedScript.args[0]);

// Some Defender tenants bundle a Monaco build that exposes query models but
// not editor instances. The production path must retain the working model API
// fallback instead of waiting forever for getEditors().
injectedQuery = null;
const fallbackModel = {
  isDisposed: () => false,
  getValue: () => injectedQuery || "",
  setValue: value => { injectedQuery = value; }
};
context.window = { monaco: { editor: { getModels: () => [fallbackModel] } } };
capturedScript.func(...capturedScript.args);
intervalCallbacks.at(-1)();
assert.equal(injectedQuery, capturedScript.args[0], "Defender's getModels-only Monaco API must still inject KQL");

localData.kqlTemplates = { ip: "DeviceNetworkEvents | where RemoteIP == 'IP_VALUE'" };
injectedQuery = null;
vm.runInContext(`injectKQLQuery(7, ${JSON.stringify(maliciousIoc)}, "ip")`, context);
assert.equal(capturedScript.args[0], safeCustomQuery);
capturedScript.func(...capturedScript.args);
intervalCallbacks.at(-1)();
assert.equal(injectedQuery, safeCustomQuery, "the real injection path must keep the IOC inside one KQL literal");
delete localData.kqlTemplates;

vm.runInContext(`setPendingInjection(11, "203.0.113.9", "ip")`, context);
listeners["tab-updated"](11, { status: "complete" }, { url: "https://login.microsoftonline.com/common/oauth2/authorize" });
assert.ok(sessionData["ahq-11"], "authentication redirects must retain the pending query");
listeners["tab-updated"](11, { status: "complete" }, { url: "https://security.microsoft.com/v2/advanced-hunting" });
assert.equal(sessionData["ahq-11"], undefined, "the pending query should be consumed after Defender injection is scheduled");
const cyberChefUrl = vm.runInContext(`getUrlForTool(huntingTools.useragent[1], ${JSON.stringify(chromeUa)})`, context);
assert.match(cyberChefUrl, /#recipe=Parse_User_Agent\(\)&input=/);
assert.equal(decodeURIComponent(cyberChefUrl.split("&input=")[1]), Buffer.from(chromeUa).toString("base64"));
assert.equal(fs.existsSync("vendor/ua-parser.min.js"), false);
assert.equal(fs.existsSync("useragent.html"), false);

// Reloading or updating an unpacked extension invalidates content scripts
// that are still attached to existing tabs. A later selection must make the
// stale script stop quietly rather than throwing from chrome.runtime.getURL().
const staleDocumentListeners = {};
const staleWindowListeners = {};
let staleCreateAttempts = 0;
class MockHTMLElement {}
const staleRuntime = {
  get id() { throw new Error("Extension context invalidated."); },
  getURL: () => { throw new Error("Extension context invalidated."); },
  sendMessage: () => { throw new Error("Extension context invalidated."); },
  onMessage: { addListener() {} }
};
const staleContentContext = vm.createContext({
  chrome: {
    runtime: staleRuntime,
    storage: {
      local: { get: (_key, callback) => callback({}) },
      onChanged: { addListener() {} }
    }
  },
  console,
  URL,
  HTMLElement: MockHTMLElement,
  MutationObserver: class { observe() {} },
  document: {
    documentElement: new MockHTMLElement(),
    createElement: () => { staleCreateAttempts++; throw new Error("stale context must not create UI"); },
    addEventListener: (name, callback) => { staleDocumentListeners[name] = callback; }
  },
  window: {
    innerWidth: 1200,
    innerHeight: 800,
    addEventListener: (name, callback) => { staleWindowListeners[name] = callback; },
    getSelection: () => ({
      toString: () => "203.0.113.5",
      rangeCount: 1,
      getRangeAt: () => ({ getBoundingClientRect: () => ({ left: 10, right: 80, top: 10, bottom: 25, width: 70, height: 15 }) })
    })
  },
  setTimeout: callback => { callback(); return 1; },
  clearTimeout() {}
});
vm.runInContext(fs.readFileSync("content.js", "utf8"), staleContentContext, { filename: "content.js" });
assert.doesNotThrow(() => staleDocumentListeners.mouseup({ button: 0, target: null }));
assert.equal(staleCreateAttempts, 0, "an invalidated content script must not recreate the RAIN overlay");

console.log("RAIN smoke tests passed");
