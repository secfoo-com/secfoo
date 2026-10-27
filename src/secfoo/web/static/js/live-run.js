// Live progress for in-flight runs, replacing the old 5-second full-page
// <meta refresh>.
//
// Markup contract:
//   <ol data-live-run="/runs/<uuid>/status.json"> with <li data-step="i">
//     children -- the step list is re-rendered from the JSON each poll.
//   <span data-elapsed="<seconds>"> -- ticks up once a second.
//   <div data-live-runs="uuid1,uuid2"> -- on a page listing several runs
//     (assessment detail), polls each and reloads the page once any of
//     them finishes, so the new findings and report show up.
(function () {
  var POLL_MS = 3000;

  function fmt(seconds) {
    seconds = Math.max(0, Math.floor(seconds));
    var m = Math.floor(seconds / 60);
    var s = seconds % 60;
    return m + "m " + (s < 10 ? "0" : "") + s + "s";
  }

  function tickElapsed() {
    var nodes = document.querySelectorAll("[data-elapsed]");
    nodes.forEach(function (node) {
      if (node.getAttribute("data-elapsed-frozen") === "true") return;
      var value = parseFloat(node.getAttribute("data-elapsed")) + 1;
      node.setAttribute("data-elapsed", String(value));
      node.textContent = fmt(value);
    });
  }

  function renderSteps(list, steps) {
    var items = list.querySelectorAll("[data-step]");
    steps.forEach(function (step, i) {
      var item = items[i];
      if (!item) return;
      item.setAttribute("data-state", step.state);
      var label = item.querySelector(".run-steps__label");
      var detail = item.querySelector(".run-steps__detail");
      if (label) label.textContent = step.label;
      if (detail && step.state !== "live") detail.textContent = step.detail || "";
    });
  }

  function pollRun(list) {
    var url = list.getAttribute("data-live-run");
    fetch(url, { headers: { Accept: "application/json" } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        if (!data) return;
        renderSteps(list, data.steps);
        if (!data.active) {
          window.location.reload();
          return;
        }
        setTimeout(function () { pollRun(list); }, POLL_MS);
      })
      .catch(function () { setTimeout(function () { pollRun(list); }, POLL_MS * 2); });
  }

  function pollMany(node) {
    var ids = node.getAttribute("data-live-runs").split(",").filter(Boolean);
    Promise.all(ids.map(function (id) {
      return fetch("/runs/" + id + "/status.json").then(function (r) { return r.ok ? r.json() : { active: false }; });
    }))
      .then(function (results) {
        if (results.some(function (r) { return !r.active; })) {
          window.location.reload();
          return;
        }
        setTimeout(function () { pollMany(node); }, POLL_MS);
      })
      .catch(function () { setTimeout(function () { pollMany(node); }, POLL_MS * 2); });
  }

  document.addEventListener("DOMContentLoaded", function () {
    if (document.querySelector("[data-elapsed]")) setInterval(tickElapsed, 1000);
    document.querySelectorAll("[data-live-run]").forEach(function (list) {
      setTimeout(function () { pollRun(list); }, POLL_MS);
    });
    document.querySelectorAll("[data-live-runs]").forEach(function (node) {
      setTimeout(function () { pollMany(node); }, POLL_MS);
    });
  });
})();
