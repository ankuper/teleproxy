/* Comparison table: cell classification + sticky header offset.
 *
 * Column layout (hardcoded):
 *   0 = Feature, 1 = Original, 2 = Teleproxy, 3 = mtg, 4 = telemt
 */
document.addEventListener("DOMContentLoaded", function () {
  var table = document.querySelector(".comparison-table table");
  if (!table) return;

  /* ── Sticky header offset ──────────────────────────────────────────── */
  var header = document.querySelector(".md-header");
  if (header) {
    document.documentElement.style.setProperty(
      "--comparison-sticky-top",
      header.offsetHeight + "px"
    );
  }

  /* ── Cell classification ───────────────────────────────────────────── */
  var YES = ["Yes", "Да", "بله", "Có"];
  var NO = ["No", "Нет", "خیر", "Không"];
  var PARTIAL = ["Partial", "Частичн", "جزئی", "Một phần"];
  var WEAK = ["Weak", "Слабая", "ضعیف", "Yếu"];

  function classify(text) {
    var t = text.trim();
    for (var i = 0; i < YES.length; i++) if (t.indexOf(YES[i]) === 0) return "yes";
    for (var i = 0; i < NO.length; i++) if (t.indexOf(NO[i]) === 0) return "no";
    for (var i = 0; i < PARTIAL.length; i++) if (t.indexOf(PARTIAL[i]) === 0) return "partial";
    for (var i = 0; i < WEAK.length; i++) if (t.indexOf(WEAK[i]) === 0) return "weak";
    return null;
  }

  var rows = table.querySelectorAll("tbody tr");
  rows.forEach(function (row) {
    var cells = row.querySelectorAll("td");
    if (cells.length < 5) return;

    /* Classify each data cell (skip column 0 = feature name) */
    var types = [];
    for (var i = 0; i < cells.length; i++) {
      var type = classify(cells[i].textContent);
      if (type) cells[i].setAttribute("data-cell-type", type);
      types.push(type);
    }

    /* Mark unique Teleproxy wins:
     * Teleproxy (col 2) is "yes" AND none of the other three (1, 3, 4) are "yes" */
    if (types[2] === "yes") {
      var othersYes = types[1] === "yes" || types[3] === "yes" || types[4] === "yes";
      if (!othersYes) {
        cells[2].setAttribute("data-tp-win", "true");
      }
    }
  });
});
