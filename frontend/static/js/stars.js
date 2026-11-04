(function () {
  const c = document.getElementById("stars"); if (!c) return;
  const x = c.getContext("2d"), still = matchMedia("(prefers-reduced-motion: reduce)").matches; let S = [];
  function size() {
    c.width = innerWidth; c.height = innerHeight;
    S = Array.from({ length: Math.min(1400, Math.floor(innerWidth * innerHeight / 1600)) },
      () => ({ x: Math.random() * c.width, y: Math.random() * c.height, r: Math.random() * 1.6 + 0.3, p: Math.random() * 6.28, s: Math.random() * 0.02 + 0.005 }));
  }
  function draw(t) {
    x.clearRect(0, 0, c.width, c.height);
    for (const s of S) {
      x.globalAlpha = still ? 0.8 : 0.45 + 0.55 * Math.sin(s.p + t * s.s * 0.1);
      x.fillStyle = s.r > 1.4 ? "#cfffe0" : "#ffffff"; x.beginPath(); x.arc(s.x, s.y, s.r, 0, 6.283); x.fill();
    }
    if (!still) requestAnimationFrame(draw);
  }
  size(); addEventListener("resize", () => { size(); if (still) draw(0); }); requestAnimationFrame(draw);
})();
