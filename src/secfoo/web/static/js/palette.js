// Command palette: Ctrl/Cmd+K (or "/") opens a filterable list of every
// sidebar page plus a few actions; arrow keys move, Enter opens, Esc
// closes. Items come from the page itself (sidebar links + the dialog's
// <template> of actions), so it never drifts from the real navigation.
(function () {
  var dialog, input, list, empty, items = [], active = 0;

  function collect() {
    var seen = {};
    var out = [];
    document.querySelectorAll(".sidebar .sidebar__link").forEach(function (a) {
      var section = a.closest("ul").previousElementSibling;
      var group = section && section.classList.contains("sidebar__section-label") ? section.textContent.trim() : "Pages";
      out.push({ label: a.textContent.trim(), href: a.getAttribute("href"), group: group, theme: null });
    });
    var tpl = dialog.querySelector(".palette__actions");
    tpl.content.querySelectorAll("a").forEach(function (a) {
      out.push({ label: a.textContent.trim(), href: a.getAttribute("href"), group: a.dataset.group, theme: a.dataset.themeChoice || null });
    });
    return out.filter(function (it) {
      var key = it.label + it.href + it.theme;
      if (seen[key]) return false;
      seen[key] = true;
      return true;
    });
  }

  function score(label, q) {
    label = label.toLowerCase();
    if (!q) return 1;
    if (label.indexOf(q) === 0) return 3;
    if (label.indexOf(q) !== -1) return 2;
    // subsequence match: "sfind" -> "SAST findings"
    var i = 0;
    for (var c = 0; c < label.length && i < q.length; c++) if (label[c] === q[i]) i++;
    return i === q.length ? 1 : 0;
  }

  function render() {
    var q = input.value.trim().toLowerCase();
    var matches = items
      .map(function (it) { return { it: it, s: score(it.label + " " + it.group, q) }; })
      .filter(function (m) { return m.s > 0; })
      .sort(function (a, b) { return b.s - a.s; });
    list.innerHTML = "";
    var lastGroup = null;
    matches.forEach(function (m, i) {
      if (!q && m.it.group !== lastGroup) {
        var head = document.createElement("li");
        head.className = "palette__group";
        head.textContent = m.it.group;
        head.setAttribute("role", "presentation");
        list.appendChild(head);
        lastGroup = m.it.group;
      }
      var li = document.createElement("li");
      li.className = "palette__item";
      li.setAttribute("role", "option");
      li.dataset.index = String(i);
      li.textContent = m.it.label;
      var hint = document.createElement("span");
      hint.className = "palette__hint";
      hint.textContent = m.it.theme ? "theme" : m.it.href;
      li.appendChild(hint);
      li._item = m.it;
      list.appendChild(li);
    });
    empty.hidden = matches.length > 0;
    active = 0;
    highlight();
  }

  function options() { return list.querySelectorAll(".palette__item"); }

  function highlight() {
    options().forEach(function (el, i) {
      el.setAttribute("aria-selected", String(i === active));
      if (i === active) el.scrollIntoView({ block: "nearest" });
    });
  }

  function choose(el) {
    if (!el) return;
    var it = el._item;
    if (it.theme) {
      dialog.close();
      var btn = document.querySelector('.sidebar [data-theme-choice="' + it.theme + '"]');
      if (btn) btn.click();
      return;
    }
    window.location.href = it.href;
  }

  function open() {
    if (dialog.open) return;
    items = collect();
    input.value = "";
    render();
    dialog.showModal();
    input.focus();
  }

  document.addEventListener("DOMContentLoaded", function () {
    dialog = document.querySelector("dialog.palette");
    if (!dialog || typeof dialog.showModal !== "function") return;
    input = dialog.querySelector(".palette__input");
    list = dialog.querySelector(".palette__list");
    empty = dialog.querySelector(".palette__empty");

    input.addEventListener("input", render);
    input.addEventListener("keydown", function (e) {
      var n = options().length;
      if (e.key === "ArrowDown") { e.preventDefault(); active = (active + 1) % Math.max(n, 1); highlight(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); active = (active - 1 + n) % Math.max(n, 1); highlight(); }
      else if (e.key === "Enter") { e.preventDefault(); choose(options()[active]); }
    });
    list.addEventListener("click", function (e) { choose(e.target.closest(".palette__item")); });
    list.addEventListener("mousemove", function (e) {
      var el = e.target.closest(".palette__item");
      if (el) { active = Number(el.dataset.index); highlight(); }
    });
    dialog.addEventListener("click", function (e) { if (e.target === dialog) dialog.close(); });
    document.querySelectorAll("[data-palette-open]").forEach(function (b) { b.addEventListener("click", open); });

    document.addEventListener("keydown", function (e) {
      var typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName) || document.activeElement.isContentEditable;
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); open(); }
      else if (e.key === "/" && !typing) { e.preventDefault(); open(); }
    });
  });
})();
