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
//   <tr class="run-row" data-href="/some/url">...</tr>
//     -- clicking anywhere in the row navigates to data-href, UNLESS the
//        click landed on a real <a> or <button> inside it (their own
//        native behavior/handler takes over instead; no per-element
//        stopPropagation needed the way the inline-onclick version required).
//   <button data-delete-url="/some/url" data-confirm="Delete this?">...</button>
//     -- POSTs to data-delete-url and reloads the page on success, after
//        confirming with data-confirm.
//   <button type="submit" data-confirm="Are you sure?">...</button>
//     -- a normal form-submit button that just asks for confirmation
//        first; cancelling prevents the submit (replaces the old
//        onclick="return confirm(...)" pattern, also CSP-blocked).
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

  if (event.target.closest("a, button")) return;

  const row = event.target.closest(".run-row[data-href]");
  if (row) {
    window.location.href = row.dataset.href;
  }
});
