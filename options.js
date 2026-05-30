const textareaIp = document.getElementById("kql-ip");
const textareaDomain = document.getElementById("kql-domain");
const textareaHash = document.getElementById("kql-hash");
const textareaAccount = document.getElementById("kql-account");
const textareaCve = document.getElementById("kql-cve");

const btnSave = document.getElementById("btn-save");
const btnReset = document.getElementById("btn-reset");
const saveToast = document.getElementById("save-toast");
const resetToast = document.getElementById("reset-toast");

const toastTimeouts = new Map();

function loadTemplates() {
  chrome.runtime.sendMessage({ action: "getDefaultTemplates" }, (response) => {
    const defaults = (response && response.defaultTemplates) ? response.defaultTemplates : {};
    chrome.storage.local.get("kqlTemplates", (data) => {
      let templates = data.kqlTemplates || defaults;
      
      if (defaults.cve && templates.cve && templates.cve.includes("Timestamp")) {
        templates.cve = defaults.cve;
        chrome.storage.local.set({ kqlTemplates: templates });
        console.log("RAIN: Obsolete CVE template migrated successfully.");
      }
      
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

function resetTemplates() {
  if (confirm("Are you sure you want to reset all templates to default KQL queries? This will overwrite your custom queries.")) {
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

function init() {
  loadTemplates();
  console.log("RAIN Control Center loaded. Sig: datesy");
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
