(function () {
  "use strict";

  var observers = [];
  var scrollHandlers = [];
  var reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

  function cleanup() {
    observers.forEach(function (o) { o.disconnect(); });
    observers = [];
    scrollHandlers.forEach(function (h) {
      window.removeEventListener("scroll", h);
    });
    scrollHandlers = [];
  }

  // ── Module 1: Scroll Reveal ──────────────────────────────────

  function initReveal() {
    // Marker is a data attribute, not a class, so adding it to a
    // .md-typeset table:not([class]) target doesn't strip the
    // outline/border/striping rules keyed on that selector.
    var els = document.querySelectorAll("[data-reveal]:not([data-revealed])");
    if (!els.length) return;

    var obs = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.setAttribute("data-revealed", "");
          obs.unobserve(entry.target);
        }
      });
    }, { threshold: 0.15, rootMargin: "0px 0px -60px 0px" });

    els.forEach(function (el) { obs.observe(el); });
    observers.push(obs);
  }

  // ── Module 2: Stagger Grid Reveal ────────────────────────────

  function initStagger() {
    var containers = document.querySelectorAll("[data-stagger]:not([data-revealed])");
    if (!containers.length) return;

    var obs = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        var children = entry.target.children;
        for (var i = 0; i < children.length; i++) {
          children[i].style.setProperty("--stagger-i", i);
        }
        entry.target.setAttribute("data-revealed", "");
        obs.unobserve(entry.target);
      });
    }, { threshold: 0.1, rootMargin: "0px 0px -40px 0px" });

    containers.forEach(function (c) { obs.observe(c); });
    observers.push(obs);
  }

  // ── Module 2b: Inner-Page Auto-Tagging ───────────────────────

  function autoTagInnerPage() {
    if (document.querySelector(".pg-home")) return;

    var selectors = [
      ".md-typeset h2",
      ".md-typeset .admonition",
      ".md-typeset details",
      ".md-typeset table:not(.highlighttable)",
      ".md-typeset .highlight",
      ".md-typeset .codehilite"
    ];
    var els = document.querySelectorAll(selectors.join(","));
    var cutoff = 600;

    // Two-pass to avoid layout thrash: collect all read results first
    // (pure getBoundingClientRect calls, no attribute mutations), then
    // apply attributes in a second pass. Interleaving reads with writes
    // forces the browser to flush layout on every iteration, turning
    // a long provider/standards page into O(N) reflows during pageload.
    var pending = [];
    for (var i = 0; i < els.length; i++) {
      var el = els[i];
      if (el.hasAttribute("data-reveal")) continue;
      if (el.getBoundingClientRect().top < cutoff) continue;
      pending.push(el);
    }
    var cardGrids = document.querySelectorAll(".pg-doc-cards:not([data-stagger])");
    var pendingGrids = [];
    for (var g = 0; g < cardGrids.length; g++) {
      if (cardGrids[g].getBoundingClientRect().top >= cutoff) {
        pendingGrids.push(cardGrids[g]);
      }
    }

    for (var j = 0; j < pending.length; j++) {
      pending[j].setAttribute("data-reveal", "");
      pending[j].setAttribute("data-reveal-light", "");
    }
    for (var k = 0; k < pendingGrids.length; k++) {
      pendingGrids[k].setAttribute("data-stagger", "");
    }
  }

  // ── Module 3: Stat Counter ───────────────────────────────────

  function initCounters() {
    var nums = document.querySelectorAll("[data-count-to]:not([data-counted])");
    if (!nums.length) return;

    var obs = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        var el = entry.target;
        el.setAttribute("data-counted", "");
        obs.unobserve(el);

        var target = parseInt(el.getAttribute("data-count-to"), 10);
        var suffix = el.textContent.indexOf("+") !== -1 ? "+" : "";

        if (reducedMotion.matches) {
          el.textContent = target + suffix;
          return;
        }

        var duration = 1500;
        var start = performance.now();
        function tick(now) {
          var progress = Math.min((now - start) / duration, 1);
          var eased = 1 - Math.pow(1 - progress, 3);
          el.textContent = Math.floor(eased * target) + suffix;
          if (progress < 1) requestAnimationFrame(tick);
        }
        el.textContent = "0" + suffix;
        requestAnimationFrame(tick);
      });
    }, { threshold: 0.5 });

    nums.forEach(function (el) { obs.observe(el); });
    observers.push(obs);
  }

  // ── Module 4: Terminal Scan Player ───────────────────────────
  // The line reveal, typewriter, spinner, and grade stamp are all
  // CSS — they play on load and degrade to the final state with no
  // JS. This module adds the one thing CSS can't do (count the
  // numeric score up to its target in time with the score line
  // landing) and replays the whole sequence on re-entry.

  function initTerminal() {
    var terminal = document.querySelector(".pg-terminal");
    if (!terminal) return;

    var scoreEl = terminal.querySelector(".pg-terminal__score");
    var scoreTarget = scoreEl
      ? parseInt(scoreEl.getAttribute("data-score"), 10)
      : 0;

    // Kept in sync with the .l14 (score line) animation-delay in
    // extra.css so the count-up starts as the line lands.
    var SCORE_DELAY = 3600;
    var SCORE_DURATION = 1100;

    var seen = false;
    var timers = [];

    function clearTimers() {
      timers.forEach(function (t) { clearTimeout(t); });
      timers = [];
    }

    function countScore() {
      if (!scoreEl) return;
      var startT;
      scoreEl.textContent = "0";
      function tick(now) {
        if (startT === undefined) startT = now;
        var progress = Math.min((now - startT) / SCORE_DURATION, 1);
        var eased = 1 - Math.pow(1 - progress, 3);
        scoreEl.textContent = Math.round(eased * scoreTarget);
        if (progress < 1) requestAnimationFrame(tick);
      }
      requestAnimationFrame(tick);
    }

    // Restart the CSS-driven pieces by clearing then restoring each
    // element's inline animation, with a forced reflow in between.
    function restartCss() {
      var els = Array.prototype.slice.call(terminal.querySelectorAll(
        ".line, .pg-terminal__cmd, .pg-terminal__spin, .pg-terminal__grade"
      ));
      els.forEach(function (el) { el.style.animation = "none"; });
      void terminal.offsetWidth;
      els.forEach(function (el) { el.style.animation = ""; });
    }

    function scheduleCount() {
      if (scoreEl) scoreEl.textContent = "0";
      clearTimers();
      timers.push(setTimeout(countScore, SCORE_DELAY));
    }

    var obs = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        if (!seen) {
          // First view: the CSS reveal is already running from load,
          // so just time the score count-up to it.
          seen = true;
          scheduleCount();
          return;
        }
        // Re-entry: replay the full sequence.
        restartCss();
        scheduleCount();
      });
    }, { threshold: 0.3 });

    obs.observe(terminal);
    observers.push(obs);
  }

  // ── Module 5: Parallax Hero ──────────────────────────────────

  function initParallax() {
    var hero = document.querySelector(".pg-hero");
    if (!hero) return;
    if (window.innerWidth < 768) return;

    function onScroll() {
      var y = window.scrollY * 0.3;
      if (y > 150) y = 150;
      hero.style.setProperty("--parallax-y", y + "px");
    }

    window.addEventListener("scroll", onScroll, { passive: true });
    scrollHandlers.push(onScroll);
    onScroll();
  }

  // ── Orchestrator ─────────────────────────────────────────────

  function activate() {
    cleanup();

    autoTagInnerPage();
    initReveal();
    initStagger();
    initCounters();

    if (reducedMotion.matches) return;

    initTerminal();
    initParallax();
  }

  if (typeof document$ !== "undefined" && document$ && document$.subscribe) {
    document$.subscribe(activate);
  } else if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", activate);
  } else {
    activate();
  }
})();
