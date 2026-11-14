// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 www.tca.ac.tz (https://www.tca.ac.tz)
// AnonyHost is free software under the GNU General Public License, version 3 or (at your option) any later version.
// It comes WITHOUT ANY WARRANTY. See the LICENSE file.
/* AnonyHost code workspace: wires editor-core.js to the page. Vanilla JS, works offline. */
(function () {
  'use strict';
  var root = document.getElementById('ide');
  if (!root || !window.EditorCore) return;            // without JS the plain textarea + Save button still work
  var C = window.EditorCore;
  var $ = function (id) { return document.getElementById(id); };
  var ta = $('code'), hl = $('hl'), gut = $('gut'), gutIn = $('gutin'), cur = $('curline'), form = $('saveform');
  var lang = C.detect(root.dataset.name), BIG = 120000, LH = 22, PAD = 12;
  var unit = C.detectIndent(ta.value, lang), saved = ta.value, lines = 0, raf = 0, busy = false, leaving = false, msgTimer = 0;
  var big = ta.value.length > BIG;

  root.classList.add('js'); if (big) root.classList.add('plain');
  $('lang').textContent = C.names[lang];
  $('indent').textContent = unit === '\t' ? 'Tabs' : 'Spaces: ' + unit.length;
  if (big) say('Large file: syntax highlighting is off.');

  function say(text, bad) {
    var m = $('msg'); m.textContent = text; m.className = bad ? 'bad' : '';
    clearTimeout(msgTimer); if (!bad) msgTimer = setTimeout(function () { m.textContent = ''; }, 6000);
  }
  function dirty() { return ta.value !== saved; }
  function setDirty() { var d = dirty(); root.classList.toggle('dirty', d); $('dirty').textContent = d ? '\u25CF unsaved' : 'saved'; document.title = (d ? '\u25CF ' : '') + root.dataset.name + ' - AnonyHost'; }

  function position() {
    var v = ta.value, s = ta.selectionStart, e = ta.selectionEnd, n = 1, i = -1;
    while ((i = v.indexOf('\n', i + 1)) !== -1 && i < s) n++;
    $('pos').textContent = 'Ln ' + n + ', Col ' + (s - C.lineStart(v, s) + 1) + (e > s ? ' (' + (e - s) + ' selected)' : '');
    cur.style.transform = 'translateY(' + (PAD + (n - 1) * LH - ta.scrollTop) + 'px)';
    cur.hidden = e > s;
  }
  function sync() { hl.scrollTop = ta.scrollTop; hl.scrollLeft = ta.scrollLeft; gut.scrollTop = ta.scrollTop; position(); }

  function render() {
    raf = 0; var v = ta.value;
    if (!big) hl.innerHTML = C.highlight(lang, v) + '\n';
    var n = 1, i = -1; while ((i = v.indexOf('\n', i + 1)) !== -1) n++;
    if (n !== lines) {
      var a = new Array(n); for (var k = 0; k < n; k++) a[k] = k + 1;
      gutIn.textContent = a.join('\n'); lines = n; gut.style.width = (Math.max(3, String(n).length) + 2) + 'ch';
    }
    $('size').textContent = (new Blob([v]).size / 1024).toFixed(1) + ' KB';
    sync(); setDirty();
  }
  function schedule() { if (!raf) raf = requestAnimationFrame(render); }

  // Apply an edit through execCommand so Ctrl+Z / Ctrl+Y keep working.
  function put(text) {
    if (document.execCommand && document.execCommand('insertText', false, text)) return;
    var s = ta.selectionStart; ta.setRangeText(text, s, ta.selectionEnd, 'end');
    ta.dispatchEvent(new Event('input', { bubbles: true }));
  }
  function apply(e) {
    if (!e) return false;
    if (e.move !== undefined) { ta.setSelectionRange(e.move, e.move); position(); return true; }
    ta.setSelectionRange(e.from, e.to); put(e.insert); ta.setSelectionRange(e.sel[0], e.sel[1]); schedule();
    return true;
  }

  function save() {
    if (busy) return; busy = true; say('Saving\u2026');
    var sent = ta.value, fd = new FormData(form); fd.set('content', sent);
    fetch('/files/save', { method: 'POST', body: fd, credentials: 'same-origin', headers: { 'X-Requested-With': 'fetch' } })
      .then(function (r) { return r.json().catch(function () { return {}; }).then(function (d) { return [r, d]; }); })
      .then(function (x) {
        var r = x[0], d = x[1];
        if (r.ok && d.ok) { saved = sent; setDirty(); say('Saved ' + new Date().toLocaleTimeString() + (d.restart ? ' \u2013 restart the site to apply the change.' : '')); }
        else say(d.error || 'Save failed (' + r.status + '). Reload the page and try again.', true);
      })
      .catch(function () { say('Could not reach the dashboard. Your changes are still here.', true); })
      .then(function () { busy = false; });
  }
  function close() {
    if (dirty() && !confirm('Discard your unsaved changes?')) return;
    leaving = true; location.href = root.dataset.close;
  }

  ta.addEventListener('input', schedule);
  ta.addEventListener('scroll', sync);
  ['keyup', 'click', 'select', 'focus'].forEach(function (ev) { ta.addEventListener(ev, position); });
  ta.addEventListener('keydown', function (e) {
    if (e.isComposing || e.keyCode === 229) return;  // IME in progress
    var mod = e.ctrlKey || e.metaKey, v = ta.value, s = ta.selectionStart, t = ta.selectionEnd;
    if (mod && !e.altKey && e.key.toLowerCase() === 's') { e.preventDefault(); save(); return; }
    if (e.key === 'Escape') { e.preventDefault(); close(); return; }
    if (mod || e.altKey) return;
    if (e.key === 'Tab') { e.preventDefault(); apply(e.shiftKey ? C.outdentEdit(v, s, t, unit) : C.indentEdit(v, s, t, unit)); return; }
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); apply(C.enterEdit(v, s, t, unit, lang)); return; }
    if (e.key === 'Backspace') { var b = C.backspaceEdit(v, s, t, lang); if (b) { e.preventDefault(); apply(b); } return; }
    if (e.key.length === 1) { var a = C.autoCloseEdit(v, s, t, e.key, lang); if (a) { e.preventDefault(); apply(a); } }
  });
  $('save').addEventListener('click', save);
  $('close').addEventListener('click', function (e) { e.preventDefault(); close(); });
  form.addEventListener('submit', function (e) { e.preventDefault(); save(); });
  window.addEventListener('beforeunload', function (e) { if (dirty() && !leaving) { e.preventDefault(); e.returnValue = ''; } });

  render(); ta.focus(); ta.setSelectionRange(0, 0);
})();
