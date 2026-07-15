const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync("sidepanel.js", "utf8");
const shared = { data: {}, changeListeners: [] };

function classList() {
  return { add() {}, remove() {} };
}

function makeNode(tag = "div") {
  return {
    tag,
    value: "",
    textContent: "",
    className: "",
    title: "",
    children: [],
    listeners: {},
    classList: classList(),
    appendChild(child) { this.children.push(child); return child; },
    addEventListener(type, fn) { this.listeners[type] = fn; },
    remove() {},
    focus() {}
  };
}

function createPanel(name, windowId) {
  const elements = {
    "ioc-input": makeNode("input"),
    cats: makeNode(),
    "category-label": makeNode(),
    tools: makeNode(),
    "empty-state": makeNode()
  };
  const sent = [];
  const document = {
    getElementById(id) { return elements[id]; },
    createElement(tag) { return makeNode(tag); },
    querySelectorAll() { return []; }
  };
  const chrome = {
    runtime: {
      lastError: null,
      getURL(path) { return `chrome-extension://rain/${path}`; },
      sendMessage(message, callback) {
        sent.push(message);
        if (message.action === "classify" && callback) {
          callback({
            ioc: message.text,
            category: "ip",
            categoryLabel: "IP Address",
            categories: [],
            canYeet: false,
            tools: [{ id: "hunt-ip-vt", title: "Hunt in VirusTotal", initials: "VT", faviconUrl: "https://www.virustotal.com" }],
            generalTools: []
          });
        }
      }
    },
    windows: {
      getCurrent(callback) { callback({ id: windowId }); }
    },
    storage: {
      session: {
        get(key, callback) { callback({ [key]: shared.data[key] }); },
        remove(key, callback) {
          delete shared.data[key];
          if (callback) callback();
        }
      },
      onChanged: {
        addListener(fn) { shared.changeListeners.push(fn); }
      }
    },
    commands: { getAll(callback) { callback([]); } }
  };
  const context = vm.createContext({ chrome, document, console, URL, Date, setTimeout, clearTimeout });
  vm.runInContext(source, context, { filename: `sidepanel-${name}.js` });
  return { name, elements, sent };
}

function publishPending(windowId, pending) {
  const key = `pendingPanelIoc-${windowId}`;
  const oldValue = shared.data[key];
  shared.data[key] = pending;
  const changes = { [key]: { oldValue, newValue: pending } };
  for (const listener of shared.changeListeners) listener(changes, "session");
}

const panelA = createPanel("A", 101);
const panelB = createPanel("B", 202);
const fresh = { ioc: "203.0.113.77", at: Date.now() };
publishPending(101, fresh);

assert.equal(panelA.elements["ioc-input"].value, fresh.ioc);
assert.equal(panelB.elements["ioc-input"].value, "");
assert.equal(shared.data["pendingPanelIoc-101"], undefined, "fresh state should be consumed");

const panelC = createPanel("C", 101);
assert.equal(panelC.elements["ioc-input"].value, "", "consumed state must not replay");

publishPending(202, { ioc: "198.51.100.20", at: Date.now() - 60_000 });
assert.equal(panelB.elements["ioc-input"].value, "", "expired state must be ignored");
assert.equal(shared.data["pendingPanelIoc-202"], undefined, "expired state should be removed");

const toolButton = panelA.elements.tools.children.find(child => child.className === "tool-btn");
assert.ok(toolButton && toolButton.listeners.click, "fresh state should still render hunting tools");
toolButton.listeners.click();
assert.ok(panelA.sent.some(message => message.action === "hunt" && message.ioc === fresh.ioc));

console.log("RAIN side-panel state tests passed");
