(function () {
  const el = document.getElementById("globe");
  if (!el || typeof Globe === "undefined") return;
  const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const g = Globe()(el)
    .globeImageUrl("/static/images/earth.jpg")
    .backgroundColor("rgba(0,0,0,0)").showAtmosphere(true).atmosphereAltitude(0.15)
    .pointOfView({ lat: 15, lng: 20, altitude: 1.7 });
  const c = g.controls();
  Object.assign(c, { autoRotate: !still, autoRotateSpeed: 1, enableZoom: false, enablePan: false, enableRotate: false });
  const fit = () => g.width(innerWidth).height(innerHeight);
  fit(); addEventListener("resize", fit);
})();
