const iocInput = document.getElementById("ioc-input");
const catsEl = document.getElementById("cats");
const categoryLabel = document.getElementById("category-label");
const toolsEl = document.getElementById("tools");
const emptyState = document.getElementById("empty-state");

// User's manual type choice; cleared whenever the indicator text changes.
let overrideCategory = null;
let debounceTimer = null;
let pendingPanelKey = null;
const PANEL_IOC_TTL_MS = 30 * 1000;

function refresh() {
  const text = iocInput.value.trim();

  if (!text) {
    catsEl.textContent = "";
    toolsEl.textContent = "";
    categoryLabel.classList.add("hidden");
    emptyState.classList.remove("hidden");
    return;
  }

  chrome.runtime.sendMessage({ action: "classify", text, overrideCategory }, (res) => {
    if (chrome.runtime.lastError || !res || !res.ioc) return;
    render(res);
  });
}

function render(res) {
  emptyState.classList.add("hidden");
  categoryLabel.classList.remove("hidden");
  catsEl.textContent = "";
  toolsEl.textContent = "";

  (res.categories || []).forEach(c => {
    const chip = document.createElement("button");
    chip.className = "chip" + (c.id === res.category ? " active" : "");
    chip.textContent = c.short;
    chip.title = c.label;
    chip.addEventListener("click", () => {
      overrideCategory = c.id;
      refresh();
    });
    catsEl.appendChild(chip);
  });

  const faviconUrl = (pageUrl) => {
    if (!pageUrl) return "";
    const url = new URL(chrome.runtime.getURL("_favicon/"));
    url.searchParams.set("pageUrl", pageUrl);
    url.searchParams.set("size", "32");
    return url.toString();
  };

  const createToolMark = (tool) => {
    const mark = document.createElement("span");
    mark.className = "tool-mark";
    const letters = document.createElement("span");
    letters.className = "tool-letters";
    letters.textContent = tool?.initials || "?";
    mark.appendChild(letters);
    if (tool?.faviconUrl) {
      const img = document.createElement("img");
      img.alt = "";
      img.addEventListener("load", () => mark.classList.add("has-icon"));
      img.addEventListener("error", () => img.remove());
      img.src = faviconUrl(tool.faviconUrl);
      mark.appendChild(img);
    }
    return mark;
  };

  const addTool = (label, onClick, extraClass, tool) => {
    const btn = document.createElement("button");
    btn.className = "tool-btn" + (extraClass ? " " + extraClass : "");
    btn.appendChild(createToolMark(tool || { initials: "YS" }));
    const labelEl = document.createElement("span");
    labelEl.className = "tool-label";
    labelEl.textContent = label;
    btn.appendChild(labelEl);
    btn.addEventListener("click", onClick);
    toolsEl.appendChild(btn);
  };

  if (res.canYeet) {
    addTool("Yeet Search (all tools)", () => {
      chrome.runtime.sendMessage({ action: "yeet", category: res.category, ioc: res.ioc });
    }, "yeet");
  }

  res.tools.forEach(tool => {
    addTool(tool.title, () => {
      chrome.runtime.sendMessage({ action: "hunt", toolId: tool.id, ioc: res.ioc });
    }, "", tool);
  });

  if (res.generalTools.length && (res.tools.length || res.canYeet)) {
    const label = document.createElement("div");
    label.className = "sec-label";
    label.textContent = "Universal";
    toolsEl.appendChild(label);
  }

  res.generalTools.forEach(tool => {
    addTool(tool.title, () => {
      chrome.runtime.sendMessage({ action: "hunt", toolId: tool.id, ioc: res.ioc });
    }, "", tool);
  });
}

iocInput.addEventListener("input", () => {
  overrideCategory = null;
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(refresh, 150);
});

function applyPendingIoc(pending) {
  if (!pending || typeof pending.ioc !== "string") return;
  iocInput.value = pending.ioc;
  overrideCategory = null;
  refresh();
  if (!pending.ioc) iocInput.focus();
}

function consumePendingIoc(key, pending) {
  if (!pending || typeof pending.ioc !== "string" || typeof pending.at !== "number") return;
  const isFresh = Date.now() - pending.at <= PANEL_IOC_TTL_MS;
  chrome.storage.session.remove(key, () => {
    if (chrome.runtime.lastError) {
      console.error("RAIN: Failed to consume pending side-panel state:", chrome.runtime.lastError);
      return;
    }
    if (isFresh) applyPendingIoc(pending);
  });
}

// Prefill from the hotkey (set by the background worker), and keep updating
// if the hotkey fires again while the panel is already open.
chrome.windows.getCurrent((currentWindow) => {
  if (chrome.runtime.lastError || typeof currentWindow?.id !== "number") {
    console.error("RAIN: Failed to identify the side panel's browser window:", chrome.runtime.lastError);
    iocInput.focus();
    return;
  }
  pendingPanelKey = `pendingPanelIoc-${currentWindow.id}`;
  chrome.storage.session.get(pendingPanelKey, (data) => {
    if (chrome.runtime.lastError) {
      console.error("RAIN: Failed to read pending side-panel state:", chrome.runtime.lastError);
      iocInput.focus();
      return;
    }
    if (data[pendingPanelKey]) {
      consumePendingIoc(pendingPanelKey, data[pendingPanelKey]);
    } else {
      iocInput.focus();
    }
  });
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "session" && pendingPanelKey && changes[pendingPanelKey]?.newValue) {
    consumePendingIoc(pendingPanelKey, changes[pendingPanelKey].newValue);
  }
});

// Keep the footer hotkey hint accurate to the user's actual binding.
if (chrome.commands && chrome.commands.getAll) {
  chrome.commands.getAll((commands) => {
    const cmd = commands.find(c => c.name === "hunt-selection");
    const label = (cmd && cmd.shortcut) ? cmd.shortcut : "Not set";
    document.querySelectorAll(".hotkey-display").forEach(el => {
      el.textContent = label;
    });
  });
}
