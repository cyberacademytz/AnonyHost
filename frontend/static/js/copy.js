// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 www.tca.ac.tz (https://www.tca.ac.tz)
// AnonyHost is free software under the GNU General Public License, version 3 or (at your option) any later version.
// It comes WITHOUT ANY WARRANTY. See the LICENSE file.
/* "Copy" button with visible feedback. copyText(button, text) */
(function () {
  function say(b, txt, good) {
    if (!b.dataset.label) b.dataset.label = b.textContent;
    b.textContent = txt; b.classList.toggle('copied', !!good);
    var live = document.getElementById('copymsg'); if (live) live.textContent = txt;
    clearTimeout(b._t); b._t = setTimeout(function () { b.textContent = b.dataset.label; b.classList.remove('copied'); if (live) live.textContent = ''; }, 2000);
  }
  window.copyText = function (b, text) {
    if (!/\.onion$/.test(text)) { say(b, 'No address yet', false); return; }
    var done = function (ok) { say(b, ok ? 'Copied!' : 'Copy failed: select the address and press Ctrl+C', ok); };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(legacy(text)); });
    } else done(legacy(text));
  };
  function legacy(text) {
    var t = document.createElement('textarea'); t.value = text; t.style.cssText = 'position:fixed;opacity:0;top:0;left:0';
    document.body.appendChild(t); t.select(); var ok = false;
    try { ok = document.execCommand('copy'); } catch (e) {}
    t.remove(); return ok;
  }
})();
