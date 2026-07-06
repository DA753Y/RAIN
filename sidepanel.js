const iocInput = document.getElementById("ioc-input");
const catsEl = document.getElementById("cats");
const categoryLabel = document.getElementById("category-label");
const toolsEl = document.getElementById("tools");
const emptyState = document.getElementById("empty-state");

// User's manual type choice; cleared whenever the indicator text changes.
let overrideCategory = null;
let debounceTimer = null;

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

  const addTool = (label, onClick, extraClass) => {
    const btn = document.createElement("button");
    btn.className = "tool-btn" + (extraClass ? " " + extraClass : "");
    btn.textContent = label;
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
    });
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
    });
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

// Prefill from the hotkey (set by the background worker), and keep updating
// if the hotkey fires again while the panel is already open.
chrome.storage.session.get("pendingPanelIoc", (data) => {
  if (data.pendingPanelIoc) {
    applyPendingIoc(data.pendingPanelIoc);
  } else {
    iocInput.focus();
  }
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "session" && changes.pendingPanelIoc && changes.pendingPanelIoc.newValue) {
    applyPendingIoc(changes.pendingPanelIoc.newValue);
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
