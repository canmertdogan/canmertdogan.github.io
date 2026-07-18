(function () {
  "use strict";

  const root = document.documentElement;
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  root.classList.add("animation-ready");

  try {
    const reveals = document.querySelectorAll(".reveal");
    if ("IntersectionObserver" in window) {
      const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          entry.target.classList.add("is-visible");
          observer.unobserve(entry.target);
        });
      }, { threshold: 0.12, rootMargin: "0px 0px -40px" });
      reveals.forEach((element) => observer.observe(element));
    } else {
      reveals.forEach((element) => element.classList.add("is-visible"));
    }

    const menuButton = document.querySelector(".menu-toggle");
    const menu = document.querySelector(".nav");
    if (menuButton && menu) {
      menuButton.addEventListener("click", () => {
        const open = menuButton.getAttribute("aria-expanded") === "true";
        menuButton.setAttribute("aria-expanded", String(!open));
        menuButton.setAttribute("aria-label", open ? "Open menu" : "Close menu");
        menu.classList.toggle("is-open", !open);
      });
      menu.querySelectorAll("a").forEach((link) => link.addEventListener("click", () => {
        menu.classList.remove("is-open");
        menuButton.setAttribute("aria-expanded", "false");
        menuButton.setAttribute("aria-label", "Open menu");
      }));
    }

    const clock = document.getElementById("utc-clock");
    function updateClock() {
      if (!clock) return;
      const now = new Date();
      clock.textContent = `UTC+03 / ${new Intl.DateTimeFormat("en-GB", {
        timeZone: "Europe/Istanbul",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false
      }).format(now)}`;
    }
    updateClock();
    window.setInterval(updateClock, 1000);

    if (!reduceMotion && window.matchMedia("(pointer: fine)").matches) {
      document.querySelectorAll("[data-tilt]").forEach((surface) => {
        surface.addEventListener("pointermove", (event) => {
          const bounds = surface.getBoundingClientRect();
          const x = (event.clientX - bounds.left) / bounds.width - 0.5;
          const y = (event.clientY - bounds.top) / bounds.height - 0.5;
          const base = surface.classList.contains("project-visual") ? "perspective(1200px)" : "perspective(1400px)";
          surface.style.transform = `${base} rotateX(${y * -2.4}deg) rotateY(${x * 3.2}deg) translate3d(0,0,0)`;
        });
        surface.addEventListener("pointerleave", () => { surface.style.transform = ""; });
      });
    }

    const canvas = document.getElementById("signal-canvas");
    const ctx = canvas && canvas.getContext("2d");
    if (!ctx || reduceMotion) return;

    let width = 0;
    let height = 0;
    let ratio = 1;
    let pointerX = 0.68;
    let pointerY = 0.28;
    const points = Array.from({ length: 34 }, () => ({
      x: Math.random(),
      y: Math.random(),
      vx: (Math.random() - 0.5) * 0.00008,
      vy: (Math.random() - 0.5) * 0.00008,
      phase: Math.random() * Math.PI * 2
    }));

    function resizeCanvas() {
      ratio = Math.min(window.devicePixelRatio || 1, 2);
      width = window.innerWidth;
      height = window.innerHeight;
      canvas.width = Math.round(width * ratio);
      canvas.height = Math.round(height * ratio);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    }

    function render(time) {
      ctx.clearRect(0, 0, width, height);
      points.forEach((point) => {
        point.x += point.vx;
        point.y += point.vy;
        if (point.x < -.05) point.x = 1.05;
        if (point.x > 1.05) point.x = -.05;
        if (point.y < -.05) point.y = 1.05;
        if (point.y > 1.05) point.y = -.05;
      });

      for (let i = 0; i < points.length; i += 1) {
        const a = points[i];
        const ax = a.x * width;
        const ay = a.y * height;
        for (let j = i + 1; j < points.length; j += 1) {
          const b = points[j];
          const bx = b.x * width;
          const by = b.y * height;
          const distance = Math.hypot(ax - bx, ay - by);
          if (distance < 145) {
            ctx.beginPath();
            ctx.moveTo(ax, ay);
            ctx.lineTo(bx, by);
            ctx.strokeStyle = `rgba(184,216,208,${(1 - distance / 145) * 0.085})`;
            ctx.stroke();
          }
        }
        const pulse = 0.18 + (Math.sin(time * 0.001 + a.phase) + 1) * 0.08;
        ctx.beginPath();
        ctx.arc(ax, ay, 1.1, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(184,216,208,${pulse})`;
        ctx.fill();
      }

      const glow = ctx.createRadialGradient(pointerX * width, pointerY * height, 0, pointerX * width, pointerY * height, Math.max(width, height) * .28);
      glow.addColorStop(0, "rgba(184,216,208,.035)");
      glow.addColorStop(1, "rgba(184,216,208,0)");
      ctx.fillStyle = glow;
      ctx.fillRect(0, 0, width, height);
      window.requestAnimationFrame(render);
    }

    window.addEventListener("resize", resizeCanvas);
    window.addEventListener("pointermove", (event) => {
      pointerX = event.clientX / window.innerWidth;
      pointerY = event.clientY / window.innerHeight;
    }, { passive: true });
    resizeCanvas();
    window.requestAnimationFrame(render);
  } catch (error) {
    root.classList.remove("animation-ready");
    document.querySelectorAll(".reveal").forEach((element) => element.classList.add("is-visible"));
    console.warn("Motion system fallback enabled.", error);
  }
})();
