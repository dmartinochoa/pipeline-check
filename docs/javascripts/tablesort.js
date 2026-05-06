/* Lightweight, dependency-free table sort for the docs site.
 *
 * Why custom (not a library):
 *   - No CDN call from a security tool's docs site (the home page
 *     advertises "no telemetry, no phone-home"). Avoiding an
 *     external script keeps the load profile honest.
 *   - The behavior we need is small: click a header, sort the
 *     rows. No multi-column, no filter UI. ~80 lines fit cleanly.
 *
 * Material's `navigation.instant` swaps page bodies without a full
 * reload, so binding once on DOMContentLoaded breaks after the
 * first navigation. Material exposes `document$` (a RxJS-ish
 * subject) that emits on every page swap; subscribing there covers
 * both initial load and subsequent navigations.
 *
 * Tables opt out by carrying class="no-sort" or being inside an
 * element with that class — this matters for tiny "Field |
 * Description" tables where sortable headers would just be visual
 * noise.
 */
(function () {
  "use strict";

  function isNumeric(value) {
    if (value === "" || value === "—" || value === "-") return false;
    // Strip common decorations: thousands separators, percent signs,
    // surrounding whitespace, leading "+" or currency markers.
    var stripped = String(value).replace(/[, %$+]/g, "").trim();
    if (stripped === "") return false;
    return !isNaN(Number(stripped));
  }

  function numericValue(value) {
    return Number(String(value).replace(/[, %$+]/g, "").trim());
  }

  // "12/31" or "12 / 31" — sort by the numerator, which is the
  // covered/total convention used in coverage tables. Falls back to
  // the whole string if it's not the fraction shape.
  function fractionNumerator(value) {
    var m = String(value).match(/^\s*(\d+(?:\.\d+)?)\s*\/\s*\d/);
    return m ? Number(m[1]) : null;
  }

  function cellSortKey(cell) {
    var text = (cell.textContent || "").trim();
    var frac = fractionNumerator(text);
    if (frac !== null) return { type: "num", value: frac };
    if (isNumeric(text)) return { type: "num", value: numericValue(text) };
    return { type: "alpha", value: text.toLowerCase() };
  }

  function compareKeys(a, b) {
    if (a.type === "num" && b.type === "num") return a.value - b.value;
    // Mixed or alpha: lexicographic. Empty-string cells sort last so
    // missing data ends up after the populated rows.
    if (a.value === "" && b.value !== "") return 1;
    if (b.value === "" && a.value !== "") return -1;
    return a.value < b.value ? -1 : a.value > b.value ? 1 : 0;
  }

  function sortTable(table, columnIndex, direction) {
    var tbody = table.tBodies[0];
    if (!tbody) return;
    var rows = Array.prototype.slice.call(tbody.rows);
    rows.sort(function (rowA, rowB) {
      var keyA = cellSortKey(rowA.cells[columnIndex]);
      var keyB = cellSortKey(rowB.cells[columnIndex]);
      var cmp = compareKeys(keyA, keyB);
      return direction === "desc" ? -cmp : cmp;
    });
    // Re-append in sorted order. appendChild moves existing nodes,
    // so this preserves attached event handlers and avoids a flicker.
    rows.forEach(function (row) { tbody.appendChild(row); });
  }

  function attach(table) {
    if (table.dataset.pgSortable === "1") return;
    table.dataset.pgSortable = "1";
    var headers = table.tHead && table.tHead.rows[0]
      ? table.tHead.rows[0].cells : [];
    Array.prototype.forEach.call(headers, function (th, idx) {
      th.classList.add("pg-sortable");
      th.setAttribute("role", "button");
      th.setAttribute("tabindex", "0");
      th.setAttribute("aria-sort", "none");
      function trigger() {
        var current = th.getAttribute("aria-sort");
        var next = current === "ascending" ? "descending" : "ascending";
        // Reset siblings.
        Array.prototype.forEach.call(headers, function (other) {
          other.setAttribute("aria-sort", "none");
          other.classList.remove("pg-sort-asc", "pg-sort-desc");
        });
        th.setAttribute("aria-sort", next);
        th.classList.add(next === "ascending" ? "pg-sort-asc" : "pg-sort-desc");
        sortTable(table, idx, next === "ascending" ? "asc" : "desc");
      }
      th.addEventListener("click", trigger);
      th.addEventListener("keydown", function (event) {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          trigger();
        }
      });
    });
  }

  function activate() {
    var tables = document.querySelectorAll("article table");
    Array.prototype.forEach.call(tables, function (table) {
      if (table.classList.contains("no-sort")) return;
      if (table.closest(".no-sort")) return;
      // Skip tables with a single body row — sorting one row is silly.
      var tbody = table.tBodies[0];
      if (!tbody || tbody.rows.length < 2) return;
      // Skip tables with no thead — they don't have header cells to
      // anchor a sort handler on.
      if (!table.tHead || !table.tHead.rows[0]) return;
      attach(table);
    });
  }

  if (typeof document$ !== "undefined" && document$ && document$.subscribe) {
    document$.subscribe(activate);
  } else if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", activate);
  } else {
    activate();
  }
})();
