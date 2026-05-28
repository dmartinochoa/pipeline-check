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
      ".md-typeset table:not([class])",
      ".md-typeset .highlight",
      ".md-typeset .codehilite"
    ];
    var els = document.querySelectorAll(selectors.join(","));
    var cutoff = 600;

    els.forEach(function (el) {
      if (el.hasAttribute("data-reveal")) return;
      var rect = el.getBoundingClientRect();
      if (rect.top < cutoff) return;
      el.setAttribute("data-reveal", "");
      el.setAttribute("data-reveal-light", "");
    });

    var cardGrids = document.querySelectorAll(".pg-doc-cards:not([data-stagger])");
    cardGrids.forEach(function (grid) {
      var rect = grid.getBoundingClientRect();
      if (rect.top < cutoff) return;
      grid.setAttribute("data-stagger", "");
    });
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

  // ── Module 4: Terminal Replay ────────────────────────────────

  function initTerminalReplay() {
    var terminal = document.querySelector(".pg-terminal");
    if (!terminal) return;

    var hasPlayed = false;

    var obs = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        if (!hasPlayed) {
          hasPlayed = true;
          return;
        }

        var lines = terminal.querySelectorAll(".line");
        var cursor = terminal.querySelector(".pg-cursor");
        var els = cursor ? Array.prototype.slice.call(lines).concat([cursor]) : Array.prototype.slice.call(lines);

        els.forEach(function (el) {
          el.style.animation = "none";
        });

        void terminal.offsetWidth;

        els.forEach(function (el) {
          el.style.animation = "";
        });
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

    initTerminalReplay();
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
