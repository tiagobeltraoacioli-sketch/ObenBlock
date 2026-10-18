// obenblock.xyz home, downloads and brand pages: the mobile menu, the
// protocol tabs, copy buttons and the hero animation toggle. Kept out of
// inline <script> blocks so a strict CSP (script-src 'self') applies
// site-wide (audit WAL-3). Every part is a no-op on pages without it.
(() => {
  "use strict";

  // ---------------------------------------------------------------- menu
  const menu = document.getElementById("menu");
  const nav = document.getElementById("navigation");
  if (menu && nav) {
    const setOpen = (open, focus = false) => {
      nav.classList.toggle("open", open);
      menu.setAttribute("aria-expanded", String(open));
      menu.setAttribute("aria-label", open ? "Close menu" : "Open menu");
      if (focus) menu.focus();
    };
    menu.addEventListener("click", () => setOpen(menu.getAttribute("aria-expanded") !== "true"));
    for (const a of nav.querySelectorAll("a")) a.addEventListener("click", () => setOpen(false));
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && menu.getAttribute("aria-expanded") === "true") setOpen(false, true);
    });
    document.addEventListener("click", (e) => { if (!e.target.closest(".header")) setOpen(false); });
    window.matchMedia("(min-width: 801px)").addEventListener("change", (e) => { if (e.matches) setOpen(false); });
  }

  // ---------------------------------------------------------------- protocol tabs
  // Each tab names its panel (aria-controls); the panels are static markup.
  const tabs = Array.from(document.querySelectorAll('[role="tab"][aria-controls]'));
  const select = (index, focus = false) => {
    tabs.forEach((tab, i) => {
      const on = i === index;
      tab.setAttribute("aria-selected", String(on));
      tab.tabIndex = on ? 0 : -1;
      const panel = document.getElementById(tab.getAttribute("aria-controls"));
      if (panel) panel.hidden = !on;
    });
    if (focus) tabs[index].focus();
  };
  tabs.forEach((tab, i) => {
    tab.addEventListener("click", () => select(i));
    tab.addEventListener("keydown", (e) => {
      const last = tabs.length - 1;
      const next = { ArrowDown: i === last ? 0 : i + 1, ArrowRight: i === last ? 0 : i + 1,
        ArrowUp: i === 0 ? last : i - 1, ArrowLeft: i === 0 ? last : i - 1, Home: 0, End: last }[e.key];
      if (next !== undefined) { e.preventDefault(); select(next, true); }
    });
  });

  // ---------------------------------------------------------------- copy buttons
  // data-copy names the element whose text (or inline SVG) is copied.
  for (const btn of document.querySelectorAll("[data-copy]")) {
    btn.addEventListener("click", async () => {
      const src = document.getElementById(btn.dataset.copy);
      if (!src) return;
      const svg = src.querySelector("svg");
      const text = svg ? svg.outerHTML : src.textContent.trim();
      const label = btn.textContent;
      try {
        await navigator.clipboard.writeText(text);
        btn.textContent = "Copied";
      } catch (e) {
        const range = document.createRange();
        range.selectNodeContents(src);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        btn.textContent = "Selected";
      }
      setTimeout(() => { btn.textContent = label; }, 1600);
    });
  }

  // ---------------------------------------------------------------- hero animation
  const motion = document.getElementById("motion");
  if (motion) {
    motion.addEventListener("click", () => {
      const paused = document.body.classList.toggle("paused");
      motion.setAttribute("aria-pressed", String(paused));
      motion.setAttribute("aria-label", paused ? "Resume animation" : "Pause animation");
      motion.textContent = paused ? "▶" : "Ⅱ";
    });
  }
})();
