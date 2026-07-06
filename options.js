const textareaIp = document.getElementById("kql-ip");
const textareaDomain = document.getElementById("kql-domain");
const textareaHash = document.getElementById("kql-hash");
const textareaAccount = document.getElementById("kql-account");
const textareaCve = document.getElementById("kql-cve");

const btnSave = document.getElementById("btn-save");
const btnReset = document.getElementById("btn-reset");
const btnResetLabel = document.getElementById("btn-reset-label");
const btnShortcuts = document.getElementById("btn-shortcuts");
const toggleFloating = document.getElementById("toggle-floating");
const toggleNativeMenu = document.getElementById("toggle-nativemenu");
const saveToast = document.getElementById("save-toast");
const resetToast = document.getElementById("reset-toast");

const SETTINGS_KEY = "rainSettings";
const toastTimeouts = new Map();

function loadTemplates() {
  chrome.runtime.sendMessage({ action: "getDefaultTemplates" }, (response) => {
    const defaults = (response && response.defaultTemplates) ? response.defaultTemplates : {};
    chrome.storage.local.get("kqlTemplates", (data) => {
      const templates = data.kqlTemplates || defaults;
      textareaIp.value = templates.ip || defaults.ip || "";
      textareaDomain.value = templates.domain || defaults.domain || "";
      textareaHash.value = templates.hash || defaults.hash || "";
      textareaAccount.value = templates.account || defaults.account || "";
      textareaCve.value = templates.cve || defaults.cve || "";
    });
  });
}

function saveTemplates() {
  const customTemplates = {
    ip: textareaIp.value,
    domain: textareaDomain.value,
    hash: textareaHash.value,
    account: textareaAccount.value,
    cve: textareaCve.value
  };

  chrome.storage.local.set({ kqlTemplates: customTemplates }, () => {
    showToast(saveToast);
  });
}

// Show the analyst's actual key binding everywhere the hotkey is mentioned,
// so the docs stay correct after a rebind (or show "Not set" if unassigned).
function loadHotkeyDisplay() {
  if (!chrome.commands || !chrome.commands.getAll) return;
  chrome.commands.getAll((commands) => {
    const cmd = commands.find(c => c.name === "hunt-selection");
    const label = (cmd && cmd.shortcut) ? cmd.shortcut : "Not set";
    document.querySelectorAll(".hotkey-display").forEach(el => {
      el.textContent = label;
    });
  });
}

function loadSettings() {
  chrome.storage.local.get(SETTINGS_KEY, (data) => {
    const settings = { floatingButton: true, forceNativeMenu: true, ...(data[SETTINGS_KEY] || {}) };
    toggleFloating.checked = settings.floatingButton;
    toggleNativeMenu.checked = settings.forceNativeMenu;
  });
}

function saveSettings() {
  chrome.storage.local.set({
    [SETTINGS_KEY]: {
      floatingButton: toggleFloating.checked,
      forceNativeMenu: toggleNativeMenu.checked
    }
  }, () => {
    showToast(saveToast);
  });
}

// window.confirm() is unreliable inside extension popups, so the reset
// button arms on the first click and only resets on a second click.
let resetArmed = false;
let resetArmTimeout = null;

function resetTemplates() {
  if (!resetArmed) {
    resetArmed = true;
    btnReset.classList.add("armed");
    btnResetLabel.textContent = "Click again to confirm";
    resetArmTimeout = setTimeout(disarmReset, 4000);
    return;
  }

  disarmReset();
  chrome.runtime.sendMessage({ action: "getDefaultTemplates" }, (response) => {
    if (response && response.defaultTemplates) {
      const defaults = response.defaultTemplates;
      chrome.storage.local.set({ kqlTemplates: defaults }, () => {
        textareaIp.value = defaults.ip || "";
        textareaDomain.value = defaults.domain || "";
        textareaHash.value = defaults.hash || "";
        textareaAccount.value = defaults.account || "";
        textareaCve.value = defaults.cve || "";
        showToast(resetToast);
      });
    }
  });
}

function disarmReset() {
  resetArmed = false;
  btnReset.classList.remove("armed");
  btnResetLabel.textContent = "Reset Defaults";
  if (resetArmTimeout) {
    clearTimeout(resetArmTimeout);
    resetArmTimeout = null;
  }
}

function showToast(toastEl) {
  if (toastTimeouts.has(toastEl)) {
    clearTimeout(toastTimeouts.get(toastEl));
  }
  toastEl.classList.remove("show");
  void toastEl.offsetWidth;
  toastEl.classList.add("show");
  const timeoutId = setTimeout(() => {
    toastEl.classList.remove("show");
    toastTimeouts.delete(toastEl);
  }, 3000);
  toastTimeouts.set(toastEl, timeoutId);
}

document.querySelectorAll(".nav-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(tc => tc.classList.remove("active"));

    btn.classList.add("active");
    const targetTab = btn.getAttribute("data-tab");
    document.getElementById(targetTab).classList.add("active");
  });
});

document.querySelectorAll(".editor-tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".editor-tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".editor-container").forEach(ec => ec.classList.remove("active"));

    btn.classList.add("active");
    const targetEditor = btn.getAttribute("data-editor");
    document.getElementById(`editor-${targetEditor}`).classList.add("active");
  });
});

document.querySelectorAll(".textarea-wrapper").forEach(wrapper => {
  wrapper.addEventListener("click", () => {
    const textarea = wrapper.querySelector("textarea");
    if (textarea) {
      textarea.focus();
    }
  });
});

btnSave.addEventListener("click", saveTemplates);
btnReset.addEventListener("click", resetTemplates);
btnShortcuts.addEventListener("click", () => {
  chrome.runtime.sendMessage({ action: "openShortcuts" });
});
toggleFloating.addEventListener("change", saveSettings);
toggleNativeMenu.addEventListener("change", saveSettings);

function init() {
  loadTemplates();
  loadSettings();
  loadHotkeyDisplay();
  console.log("RAIN Control Center loaded. Sig: datesy");
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
