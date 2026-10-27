// Theme switch for the dashboard (Light / System / Dark), loaded from
// <head> so the right theme is applied before first paint. "System"
// follows the OS setting; an explicit choice is remembered per browser.
// External file rather than inline for the same CSP reason as
// interactive.js.
(function () {
  var KEY = "secfoo-theme";
  var media = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

  function stored() {
    try { return localStorage.getItem(KEY) || "system"; } catch (e) { return "system"; }
  }

  function apply(choice) {
    var dark = choice === "dark" || (choice === "system" && media && media.matches);
    document.documentElement.setAttribute("data-theme", dark ? "dark" : "light");
    var options = document.querySelectorAll("[data-theme-choice]");
    for (var i = 0; i < options.length; i++) {
      options[i].setAttribute("aria-selected", String(options[i].getAttribute("data-theme-choice") === choice));
    }
  }

  apply(stored());
  if (media && media.addEventListener) {
    media.addEventListener("change", function () { if (stored() === "system") apply("system"); });
  }

  document.addEventListener("DOMContentLoaded", function () { apply(stored()); });
  document.addEventListener("click", function (event) {
    var option = event.target.closest("[data-theme-choice]");
    if (!option) return;
    var choice = option.getAttribute("data-theme-choice");
    try { localStorage.setItem(KEY, choice); } catch (e) {}
    apply(choice);
  });
})();
