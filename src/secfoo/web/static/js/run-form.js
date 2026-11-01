// Starter templates on the Run Assessment form: clicking a card ticks the
// skills it names and sets the depth, so a common run is one click plus
// "Start run". Users can still adjust anything afterwards.
//
// Markup contract:
//   <button class="starter" data-starter-skills="a,b" data-starter-depth="quick">
(function () {
  document.addEventListener("click", function (event) {
    var starter = event.target.closest("[data-starter-skills]");
    if (!starter) return;
    event.preventDefault();
    var form = starter.closest("form") || document;
    var wanted = starter.getAttribute("data-starter-skills").split(",");
    form.querySelectorAll("input[name='skill']").forEach(function (box) {
      box.checked = wanted.indexOf(box.value) !== -1;
    });
    var depth = form.querySelector("select[name='depth']");
    if (depth && starter.getAttribute("data-starter-depth")) depth.value = starter.getAttribute("data-starter-depth");
    document.querySelectorAll("[data-starter-skills]").forEach(function (other) {
      other.setAttribute("aria-pressed", String(other === starter));
    });
  });
})();
