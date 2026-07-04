(function () {
  document.documentElement.classList.add("animation-ready");

  try {
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const reveals = document.querySelectorAll(".reveal, [data-reveal]");

  if ("IntersectionObserver" in window) {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-visible");
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.16, rootMargin: "0px 0px -40px 0px" }
    );

    reveals.forEach((item, index) => {
      item.style.transitionDelay = `${Math.min(index * 35, 260)}ms`;
      observer.observe(item);
    });
  } else {
    reveals.forEach((item) => item.classList.add("is-visible"));
  }

  if (!reduceMotion) {
    const parallaxItems = document.querySelectorAll(".parallax-layer");
    let pointerX = 0;
    let pointerY = 0;
    let currentX = 0;
    let currentY = 0;

    window.addEventListener("pointermove", (event) => {
      pointerX = (event.clientX / window.innerWidth - 0.5) * 2;
      pointerY = (event.clientY / window.innerHeight - 0.5) * 2;
    });

    function parallaxTick() {
      currentX += (pointerX - currentX) * 0.06;
      currentY += (pointerY - currentY) * 0.06;

      parallaxItems.forEach((item) => {
        const depth = Number(item.dataset.depth || 0.02);
        item.style.transform = `translate3d(${currentX * depth * 120}px, ${currentY * depth * 90}px, 0)`;
      });

      requestAnimationFrame(parallaxTick);
    }

    requestAnimationFrame(parallaxTick);
  }

  const canvas = document.getElementById("ambientCanvas");
  const context = canvas && canvas.getContext("2d");

  if (!context || reduceMotion) {
    if (canvas) canvas.style.display = "none";
    return;
  }

  const particles = [];
  const particleCount = 72;
  let width = 0;
  let height = 0;
  let mouseX = 0.5;
  let mouseY = 0.5;

  function resize() {
    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = Math.floor(width * ratio);
    canvas.height = Math.floor(height * ratio);
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;
    context.setTransform(ratio, 0, 0, ratio, 0, 0);

    while (particles.length < particleCount) {
      particles.push({
        x: Math.random() * width,
        y: Math.random() * height,
        radius: Math.random() * 1.7 + 0.35,
        speed: Math.random() * 0.18 + 0.05,
        drift: Math.random() * 0.22 - 0.11,
        alpha: Math.random() * 0.38 + 0.12
      });
    }
  }

  function draw() {
    context.clearRect(0, 0, width, height);

    const gradient = context.createRadialGradient(
      width * (0.5 + (mouseX - 0.5) * 0.12),
      height * (0.18 + (mouseY - 0.5) * 0.08),
      0,
      width * 0.5,
      height * 0.15,
      Math.max(width, height) * 0.55
    );
    gradient.addColorStop(0, "rgba(255,255,255,0.09)");
    gradient.addColorStop(0.42, "rgba(255,255,255,0.025)");
    gradient.addColorStop(1, "rgba(255,255,255,0)");
    context.fillStyle = gradient;
    context.fillRect(0, 0, width, height);

    particles.forEach((particle) => {
      particle.y -= particle.speed;
      particle.x += particle.drift + (mouseX - 0.5) * 0.05;

      if (particle.y < -10) {
        particle.y = height + 10;
        particle.x = Math.random() * width;
      }

      if (particle.x < -10) particle.x = width + 10;
      if (particle.x > width + 10) particle.x = -10;

      context.beginPath();
      context.arc(particle.x, particle.y, particle.radius, 0, Math.PI * 2);
      context.fillStyle = `rgba(255,255,255,${particle.alpha})`;
      context.fill();
    });

    requestAnimationFrame(draw);
  }

  window.addEventListener("resize", resize);
  window.addEventListener("pointermove", (event) => {
    mouseX = event.clientX / window.innerWidth;
    mouseY = event.clientY / window.innerHeight;
  });

  resize();
  draw();
  } catch (error) {
    document.documentElement.classList.remove("animation-ready");
    document.querySelectorAll(".reveal").forEach((item) => {
      item.classList.add("is-visible");
    });
    console.warn("Portfolio animation fallback enabled.", error);
  }
})();
