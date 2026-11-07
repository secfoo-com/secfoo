// Event delegation for row-navigation and delete actions, loaded once
// per page from base.html/admin_base.html.
//
// This exists ONLY because the portal (portal/security.py's
// SecurityHeadersMiddleware) sends a Content-Security-Policy with no
// 'unsafe-inline', which silently blocks inline onclick="..." attributes
// and inline <script> blocks in a real browser -- local `secfoo serve`
// sends no CSP at all, so the old inline-onclick pattern "worked" there
// and nowhere else. An external, same-origin script like this one is
// exactly what default-src 'self' is designed to allow.
//
// Markup contract:
//   <tr class="run-row" data-href="/some/url" tabindex="0">...</tr>
//     -- clicking anywhere in the row navigates to data-href, UNLESS the
//        click landed on a real <a> or <button> inside it (their own
//        native behavior/handler takes over instead; no per-element
//        stopPropagation needed the way the inline-onclick version required).
//        tabindex="0" puts the row in the Tab order, and pressing Enter
//        while the row itself has focus navigates too, so keyboard-only
//        users can open it.
//   <button data-delete-url="/some/url" data-confirm="Delete this?">...</button>
//     -- POSTs to data-delete-url and reloads the page on success, after
//        confirming with data-confirm.
//   <button type="submit" data-confirm="Are you sure?">...</button>
//     -- a normal form-submit button that just asks for confirmation
//        first; cancelling prevents the submit (replaces the old
//        onclick="return confirm(...)" pattern, also CSP-blocked).
//   <select name="status" data-autosubmit>...</select>
//     -- submits its enclosing form as soon as the selection changes
//        (replaces the old onchange="this.form.submit()" filter dropdowns,
//        which the CSP blocked the same way).
document.addEventListener("change", function (event) {
  const field = event.target.closest("[data-autosubmit]");
  if (field && field.form) {
    field.form.submit();
  }
});

document.addEventListener("click", function (event) {
  const deleteButton = event.target.closest("[data-delete-url]");
  if (deleteButton) {
    const message = deleteButton.dataset.confirm || "Are you sure?";
    if (!window.confirm(message)) return;
    fetch(deleteButton.dataset.deleteUrl, { method: "POST" }).then(function () {
      window.location.reload();
    });
    return;
  }

  const confirmButton = event.target.closest("[data-confirm]");
  if (confirmButton && !confirmButton.hasAttribute("data-delete-url")) {
    if (!window.confirm(confirmButton.dataset.confirm)) {
      event.preventDefault();
    }
    return;
  }

  // Real controls inside a row (links, buttons, the bulk-select
  // checkboxes) keep their own behavior instead of opening the row.
  if (event.target.closest("a, button, input, select, label")) return;

  const row = event.target.closest(".run-row[data-href]");
  if (row) {
    window.location.href = row.dataset.href;
  }
});

// Keyboard access for clickable rows. A <tr> isn't focusable, so without
// this Tab skips every .run-row and keyboard-only users can't open them.
// Done here rather than with tabindex="0" in each template: the rows only
// work through this script, so they only become focusable when it runs,
// and any new .run-row is covered automatically.
document.querySelectorAll(".run-row[data-href]").forEach(function (row) {
  if (!row.hasAttribute("tabindex")) row.tabIndex = 0;
});

document.addEventListener("keydown", function (event) {
  if (event.key !== "Enter") return;
  // Only when the row itself is focused -- Enter on a link or button
  // inside the row keeps that element's own behavior.
  const row = event.target;
  if (row.matches && row.matches(".run-row[data-href]")) {
    window.location.href = row.dataset.href;
  }
});

// Data-driven styles. The portal's CSP blocks inline style="..." attributes,
// but setting element.style from this same-origin script is allowed, so
// templates pass the value as a data attribute instead:
//   <div class="severity-bar__fill" data-bar-width="42.5"></div>
//     -- sets width: 42.5%
//   <div class="donut" data-donut-gradient="var(--color-error) 0 40%, ..."></div>
//     -- sets the --donut-gradient custom property donut.css reads
// This file is loaded at the end of <body>, so the elements already exist.
document.querySelectorAll("[data-bar-width]").forEach(function (el) {
  const percent = parseFloat(el.dataset.barWidth);
  el.style.width = (isFinite(percent) ? Math.max(0, Math.min(percent, 100)) : 0) + "%";
});
// <span data-flex-grow="3"> -- sets flex-grow (the overview's posture bar).
document.querySelectorAll("[data-flex-grow]").forEach(function (el) {
  const grow = parseFloat(el.dataset.flexGrow);
  el.style.flexGrow = isFinite(grow) && grow > 0 ? grow : 0;
});
document.querySelectorAll("[data-donut-gradient]").forEach(function (el) {
  el.style.setProperty("--donut-gradient", el.dataset.donutGradient);
});

// "Select all" checkbox for a column of row checkboxes:
//   <input type="checkbox" data-select-all="ids">  toggles every
//   <input type="checkbox" name="ids"> on the page.
document.addEventListener("change", function (event) {
  const all = event.target.closest("input[type=checkbox][data-select-all]");
  if (!all) return;
  document.querySelectorAll('input[type=checkbox][name="' + all.dataset.selectAll + '"]').forEach(function (box) {
    box.checked = all.checked;
  });
});

// Widget info buttons (<details class="info-tip">): one open at a time,
// closed by a click elsewhere or Escape (focus returns to the button).
document.addEventListener("toggle", function (event) {
  const tip = event.target;
  if (!(tip instanceof HTMLDetailsElement) || !tip.classList.contains("info-tip") || !tip.open) return;
  document.querySelectorAll("details.info-tip[open]").forEach(function (other) {
    if (other !== tip) other.open = false;
  });
}, true);
document.addEventListener("click", function (event) {
  document.querySelectorAll("details.info-tip[open]").forEach(function (tip) {
    if (!tip.contains(event.target)) tip.open = false;
  });
});
document.addEventListener("keydown", function (event) {
  if (event.key !== "Escape") return;
  document.querySelectorAll("details.info-tip[open]").forEach(function (tip) {
    tip.open = false;
    const trigger = tip.querySelector("summary");
    if (trigger) trigger.focus();
  });
});

