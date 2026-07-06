// RAIN content script
// 1. Shift + right-click always yields the browser's native context menu,
//    even on sites that hijack it with their own menu.
// 2. A floating hunt button (shadow DOM overlay) appears next to selected
//    text, plus a hotkey-driven hunt menu / paste box.
(() => {
  "use strict";

  const SETTINGS_KEY = "rainSettings";
  let settings = { floatingButton: true, forceNativeMenu: true };

  chrome.storage.local.get(SETTINGS_KEY, (data) => {
    if (data && data[SETTINGS_KEY]) settings = { ...settings, ...data[SETTINGS_KEY] };
  });
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes[SETTINGS_KEY] && changes[SETTINGS_KEY].newValue) {
      settings = { ...settings, ...changes[SETTINGS_KEY].newValue };
      if (!settings.floatingButton) hideAll();
    }
  });

  // --- 1. Force-native right-click -----------------------------------------
  // Registered at document_start in the capture phase on window, so it runs
  // before any page handler can preventDefault() and swap in a custom menu.
  window.addEventListener("contextmenu", (e) => {
    if (settings.forceNativeMenu && e.shiftKey) {
      e.stopPropagation();
    }
  }, true);

  // --- 2. Floating hunt overlay --------------------------------------------

  const MAX_SELECTION_LEN = 500;
  const Z_MAX = "2147483647";

  let host = null;
  let ui = null; // { fab, menu }
  let currentText = "";
  let menuOpen = false;

  function ensureUi() {
    if (ui) return ui;
    if (!(document.documentElement instanceof HTMLElement)) return null;

    host = document.createElement("rain-ioc-hunter");
    host.style.cssText = `all:initial; position:fixed; top:0; left:0; width:0; height:0; z-index:${Z_MAX};`;
    const shadow = host.attachShadow({ mode: "closed" });

    shadow.innerHTML = `
      <style>
        :host { all: initial; }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        .rain-fab, .rain-menu {
          position: fixed;
          z-index: ${Z_MAX};
          font-family: -apple-system, "Segoe UI", system-ui, sans-serif;
        }
        .rain-fab {
          width: 30px; height: 30px;
          border-radius: 50%;
          border: 1px solid #1C3A50;
          background: #0B1B2A;
          box-shadow: 0 4px 14px rgba(0, 0, 0, 0.45);
          cursor: pointer;
          display: none;
          align-items: center;
          justify-content: center;
          padding: 0;
        }
        .rain-fab img { width: 24px; height: 24px; border-radius: 50%; display: block; }
        .rain-fab:hover { border-color: #C28A5C; transform: scale(1.08); }
        .rain-fab.visible { display: flex; }

        .rain-menu {
          min-width: 240px;
          max-width: 320px;
          background: #0B1B2A;
          border: 1px solid #1C3A50;
          border-radius: 10px;
          box-shadow: 0 12px 34px rgba(0, 0, 0, 0.55);
          overflow: hidden;
          display: none;
        }
        .rain-menu.visible { display: block; }

        .rain-head {
          padding: 9px 12px 8px;
          border-bottom: 1px solid #14293C;
          background: #0E2233;
        }
        .rain-cat {
          font-size: 10px;
          font-weight: 700;
          letter-spacing: 0.8px;
          text-transform: uppercase;
          color: #C28A5C;
        }
        .rain-ioc {
          margin-top: 2px;
          font-family: Consolas, "Cascadia Code", monospace;
          font-size: 11.5px;
          color: #E9F1F5;
          word-break: break-all;
          cursor: copy;
        }
        .rain-ioc:hover { color: #45A8C4; }

        .rain-cats {
          display: flex;
          flex-wrap: wrap;
          gap: 4px;
          margin-top: 7px;
        }
        .rain-chip {
          border: 1px solid #1C3A50;
          background: transparent;
          color: #8CA3B5;
          font-family: inherit;
          font-size: 10px;
          font-weight: 600;
          padding: 3px 8px;
          border-radius: 9999px;
          cursor: pointer;
        }
        .rain-chip:hover { color: #E9F1F5; border-color: #2E8CA8; }
        .rain-chip.active {
          background: #2E8CA8;
          border-color: #2E8CA8;
          color: #FFFFFF;
        }

        .rain-items {
          padding: 5px;
          max-height: 320px;
          overflow-y: auto;
          scrollbar-width: thin;
          scrollbar-color: #1C3A50 transparent;
        }
        .rain-items::-webkit-scrollbar { width: 8px; }
        .rain-items::-webkit-scrollbar-track { background: transparent; }
        .rain-items::-webkit-scrollbar-thumb {
          background: #1C3A50;
          border-radius: 9999px;
          border: 2px solid #0B1B2A;
        }
        .rain-items::-webkit-scrollbar-thumb:hover { background: #2E8CA8; }
        .rain-item {
          display: block;
          width: 100%;
          text-align: left;
          padding: 7px 9px;
          border: none;
          border-radius: 6px;
          background: transparent;
          color: #C9D8E2;
          font-size: 12.5px;
          font-family: inherit;
          cursor: pointer;
        }
        .rain-item:hover { background: #123044; color: #FFFFFF; }
        .rain-item.rain-yeet {
          color: #E8B98C;
          font-weight: 600;
        }
        .rain-item.rain-yeet:hover { background: rgba(194, 138, 92, 0.14); color: #F3D2B0; }
        .rain-sec-label {
          font-size: 9px;
          font-weight: 700;
          letter-spacing: 0.8px;
          text-transform: uppercase;
          color: #5F7889;
          padding: 7px 9px 3px;
        }

      </style>
      <button class="rain-fab" title="Hunt this IOC with RAIN">
        <img src="${chrome.runtime.getURL("icons/icon32.png")}" alt="RAIN">
      </button>
      <div class="rain-menu" role="menu"></div>
    `;

    ui = {
      fab: shadow.querySelector(".rain-fab"),
      menu: shadow.querySelector(".rain-menu")
    };

    ui.fab.addEventListener("click", (e) => {
      e.stopPropagation();
      openMenuAt(parseFloat(ui.fab.style.left), parseFloat(ui.fab.style.top) + 34, currentText);
      ui.fab.classList.remove("visible");
    });

    document.documentElement.appendChild(host);

    // A few aggressive sites prune foreign nodes; quietly re-attach.
    new MutationObserver(() => {
      if (host && !host.isConnected && document.documentElement) {
        document.documentElement.appendChild(host);
      }
    }).observe(document.documentElement, { childList: true });

    return ui;
  }

  function clamp(value, min, max) {
    return Math.max(min, Math.min(value, max));
  }

  function hideAll() {
    if (!ui) return;
    ui.fab.classList.remove("visible");
    ui.menu.classList.remove("visible");
    menuOpen = false;
  }

  function showFab(rect, text) {
    const u = ensureUi();
    if (!u) return;
    currentText = text;
    u.menu.classList.remove("visible");
    menuOpen = false;
    u.fab.style.left = clamp(rect.right + 6, 8, window.innerWidth - 40) + "px";
    u.fab.style.top = clamp(rect.bottom + 6, 8, window.innerHeight - 40) + "px";
    u.fab.classList.add("visible");
  }

  function truncateMiddle(text, max) {
    if (text.length <= max) return text;
    const half = Math.floor((max - 3) / 2);
    return text.slice(0, half) + "..." + text.slice(-half);
  }

  function openMenuAt(x, y, text, overrideCategory) {
    const u = ensureUi();
    if (!u || !text) return;
    currentText = text;

    chrome.runtime.sendMessage({ action: "classify", text, overrideCategory }, (res) => {
      if (chrome.runtime.lastError || !res || !res.ioc) return;

      const menu = u.menu;
      menu.textContent = "";

      const head = document.createElement("div");
      head.className = "rain-head";
      const cat = document.createElement("div");
      cat.className = "rain-cat";
      cat.textContent = res.categoryLabel;
      const iocEl = document.createElement("div");
      iocEl.className = "rain-ioc";
      iocEl.textContent = truncateMiddle(res.ioc, 60);
      iocEl.title = "Click to copy cleaned IOC";
      iocEl.addEventListener("click", () => {
        navigator.clipboard.writeText(res.ioc).catch(() => {});
        hideAll();
      });
      head.appendChild(cat);
      head.appendChild(iocEl);

      // IOC-type switcher: correct a wrong classification, or pick a type
      // when the indicator wasn't recognized.
      const chips = document.createElement("div");
      chips.className = "rain-cats";
      (res.categories || []).forEach(c => {
        const chip = document.createElement("button");
        chip.className = "rain-chip" + (c.id === res.category ? " active" : "");
        chip.textContent = c.short;
        chip.title = c.label;
        chip.addEventListener("click", (ev) => {
          ev.stopPropagation();
          openMenuAt(x, y, text, c.id);
        });
        chips.appendChild(chip);
      });
      head.appendChild(chips);
      menu.appendChild(head);

      const items = document.createElement("div");
      items.className = "rain-items";

      const addItem = (label, onClick, extraClass) => {
        const btn = document.createElement("button");
        btn.className = "rain-item" + (extraClass ? " " + extraClass : "");
        btn.textContent = label;
        btn.addEventListener("click", () => {
          onClick();
          hideAll();
        });
        items.appendChild(btn);
      };

      if (res.canYeet) {
        addItem("Yeet Search (all tools)", () => {
          chrome.runtime.sendMessage({ action: "yeet", category: res.category, ioc: res.ioc });
        }, "rain-yeet");
      }

      res.tools.forEach(tool => {
        addItem(tool.title, () => {
          chrome.runtime.sendMessage({ action: "hunt", toolId: tool.id, ioc: res.ioc });
        });
      });

      if (res.generalTools.length && (res.tools.length || res.canYeet)) {
        const label = document.createElement("div");
        label.className = "rain-sec-label";
        label.textContent = "Universal";
        items.appendChild(label);
      }

      res.generalTools.forEach(tool => {
        addItem(tool.title, () => {
          chrome.runtime.sendMessage({ action: "hunt", toolId: tool.id, ioc: res.ioc });
        });
      });

      menu.appendChild(items);

      menu.style.left = clamp(x, 8, window.innerWidth - 330) + "px";
      menu.style.top = clamp(y, 8, window.innerHeight - 120) + "px";
      u.fab.classList.remove("visible");
      menu.classList.add("visible");
      menuOpen = true;
    });
  }

  function selectionRectAndText() {
    const sel = window.getSelection();
    const text = sel ? sel.toString().trim() : "";
    if (!text || text.length < 2 || text.length > MAX_SELECTION_LEN || sel.rangeCount === 0) return null;
    const rect = sel.getRangeAt(0).getBoundingClientRect();
    if (!rect || (rect.width === 0 && rect.height === 0)) return null;
    return { rect, text };
  }

  document.addEventListener("mouseup", (e) => {
    if (!settings.floatingButton) return;
    if (host && e.target === host) return; // click inside our own overlay
    if (e.button !== 0) return;
    // Let the browser finalize the selection first.
    setTimeout(() => {
      const found = selectionRectAndText();
      if (found) {
        showFab(found.rect, found.text);
      } else if (!menuOpen) {
        hideAll();
      }
    }, 0);
  }, true);

  document.addEventListener("mousedown", (e) => {
    if (host && e.target === host) return;
    hideAll();
  }, true);

  window.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && ui && (menuOpen || ui.fab.classList.contains("visible"))) {
      hideAll();
    }
  }, true);

  window.addEventListener("scroll", () => {
    if (ui && !menuOpen) hideAll();
  }, true);

  document.addEventListener("selectionchange", () => {
    if (menuOpen || !ui) return;
    const sel = window.getSelection();
    if (!sel || !sel.toString().trim()) {
      ui.fab.classList.remove("visible");
    }
  });

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "show-hunt-menu") {
      const found = selectionRectAndText();
      if (found) {
        openMenuAt(found.rect.right + 6, found.rect.bottom + 6, found.text);
        sendResponse({ handled: true });
      }
    }
  });
})();
