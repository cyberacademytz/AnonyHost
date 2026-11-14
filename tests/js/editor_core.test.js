// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 www.tca.ac.tz (https://www.tca.ac.tz)
// AnonyHost is free software under the GNU General Public License, version 3 or (at your option) any later version.
// It comes WITHOUT ANY WARRANTY. See the LICENSE file.
// Run with: node tests/js/editor_core.test.js   (plain asserts, no framework)
const assert = require('assert');
const C = require('../../frontend/static/js/editor-core.js');
const unspan = h => h.replace(/<span class="t-[a-z0-9]+">/g, '').replace(/<\/span>/g, '');
const unesc = h => h.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
const apply = (t, e) => t.slice(0, e.from) + e.insert + t.slice(e.to);
let n = 0; const test = (name, f) => { f(); n++; };

const SAMPLES = {
  html: ['<!doctype html><html><body onload="x()"><script>alert(1)</script><a href=\'q\' data-x=1>don\'t "quote" &amp; &lt;b&gt;</a><!-- c --></body></html>', '<div class="a', '<<<>>>', '<!-- never closed', "it's <b>fine</b> \"here"],
  css: ['a:hover{color:#fff;margin:-1.5px 0 .5em}/* c */ .x>#y::after{content:"a\\"b";--v:1}@media (max-width:600px){h1{font:12px/1 serif!important}}', '/* open', 'a{b:"open'],
  js: ['const a = `t ${x}` + \'s\' + "d"; // c\n/* b */ if (x <= 1 && y > 2) { fn(1.5e3, 0xFF, true); }', '"open string\nnext', '`never closed', '/* open'],
  php: ['<h1><?php echo $a["k"]; // c\nif ($x) { foo(); } ?></h1><?= $v ?>', '<?php "unterminated', '<?php /* x', 'plain html only <b>x</b>'],
  python: ['@dec\ndef f(a, b=1):\n    """doc\n    string"""\n    return f"x{a}" if a is None else \'s\'  # c\n', '"""never', "'open", 'x = 0x1F + 2.5'],
  json: ['{"a": [1, -2.5e3, true, null], "b\\"c": "d"}', '{"open', '[1,'],
  markdown: ['# Title\n> quote\n- item **bold** and `code` [l](http://x)\n```js\ncode <b>\n```\n<!-- c -->', '```never closed', '**x'],
  text: ['<script>alert(1)</script> & "x"']
};
test('highlighting never alters the text and never lets raw markup through', () => {
  for (const [lang, list] of Object.entries(SAMPLES)) for (const s of list) {
    const h = C.highlight(lang, s), plain = unspan(h);
    assert(!/[<>]/.test(plain), `raw angle bracket leaked in ${lang}: ${plain}`);
    assert.strictEqual(unesc(plain), s, `${lang} text changed`);
  }
  // exactly our own span markup is allowed to contain '<'
  assert(!/<(?!\/?span)/.test(C.highlight('html', '<script>alert(1)</script>')));
});
test('tokens get classes', () => {
  assert(C.highlight('html', '<a href="x">').includes('t-tag') && C.highlight('html', '<a href="x">').includes('t-at') && C.highlight('html', '<a href="x">').includes('t-s'));
  assert(C.highlight('js', 'const x = 1; // c').includes('t-k') && C.highlight('js', 'const x = 1; // c').includes('t-c') && C.highlight('js', 'x = 1').includes('t-n'));
  assert(C.highlight('php', '<?php echo $v;').includes('t-v') && C.highlight('php', '<p><?php echo 1; ?></p>').includes('t-tag'));
  assert(C.highlight('css', 'a{color:#fff}').includes('t-p') && !C.highlight('css', 'a:hover{x:1}').startsWith('<span class="t-p">a'));
  assert(C.highlight('json', '{"k": 1}').includes('t-p'));
  assert(C.highlight('python', 'def f(): pass').includes('t-k'));
});
test('highlighting is fast on big files and does not hang on odd input', () => {
  const big = ('function f(a){ return "x" + a; } // line\n').repeat(4000);  // ~160 KB
  let t = Date.now(); C.highlight('js', big); assert(Date.now() - t < 1500, 'js too slow');
  t = Date.now(); C.highlight('html', '<div "' .repeat(20000)); assert(Date.now() - t < 1500, 'html too slow');
  t = Date.now(); C.highlight('css', 'a{b:"'.repeat(20000)); assert(Date.now() - t < 1500, 'css too slow');
});
test('language detection', () => {
  const d = C.detect;
  assert.deepStrictEqual(['a.HTML', 'x.php', 'a/b.css', 'main.py', 'app.js', 'c.json', 'README.md', 'notes.txt', 'Makefile', '.htaccess'].map(d),
    ['html', 'php', 'css', 'python', 'js', 'json', 'markdown', 'text', 'text', 'text']);
});
test('indent detection', () => {
  assert.strictEqual(C.detectIndent('a\n\tb\n\t\tc', 'js'), '\t');
  assert.strictEqual(C.detectIndent('a\n  b\n    c', 'py'), '  ');
  assert.strictEqual(C.detectIndent('a\n    b\n        c', 'js'), '    ');
  assert.strictEqual(C.detectIndent('flat', 'python'), '    ');
  assert.strictEqual(C.detectIndent('flat', 'html'), '  ');
});
test('tab / shift+tab', () => {
  let e = C.indentEdit('ab', 1, 1, '    '); assert.strictEqual(apply('ab', e), 'a   b'); assert.deepStrictEqual(e.sel, [4, 4]);  // to the next tab stop
  e = C.indentEdit('x\ny\nz', 0, 3, '  '); assert.strictEqual(apply('x\ny\nz', e), '  x\n  y\nz');
  e = C.indentEdit('a\n\nb', 0, 4, '  '); assert.strictEqual(apply('a\n\nb', e), '  a\n\n  b');  // blank lines stay blank
  e = C.outdentEdit('    x\n  y\nz', 0, 11, '    '); assert.strictEqual(apply('    x\n  y\nz', e), 'x\ny\nz');
  e = C.outdentEdit('\tx', 2, 2, '\t'); assert.strictEqual(apply('\tx', e), 'x'); assert.deepStrictEqual(e.sel, [1, 1]);
  assert.strictEqual(C.outdentEdit('x', 0, 0, '  '), null);
  e = C.indentEdit('a\nb\n', 0, 4, '  '); assert.strictEqual(apply('a\nb\n', e), '  a\n  b\n');  // selection ending after a newline does not indent the next line
  e = C.indentEdit('\nx', 0, 0, '    '); assert.strictEqual(apply('\nx', e), '    \nx');  // caret at 0 on a blank first line
});
test('enter keeps indent and expands brackets', () => {
  let t = '  if (x) {', e = C.enterEdit(t, t.length, t.length, '  ', 'js'); assert.strictEqual(apply(t, e), t + '\n    ');
  t = '  f({})'; e = C.enterEdit(t, 5, 5, '  ', 'js'); assert.strictEqual(apply(t, e), '  f({\n    \n  })'); assert.deepStrictEqual(e.sel, [10, 10]);
  t = 'def f():'; e = C.enterEdit(t, t.length, t.length, '    ', 'python'); assert.strictEqual(apply(t, e), 'def f():\n    ');
  t = '<div></div>'; e = C.enterEdit(t, 5, 5, '  ', 'html'); assert.strictEqual(apply(t, e), '<div>\n  \n</div>'); assert.deepStrictEqual(e.sel, [8, 8]);
  t = '\tx'; e = C.enterEdit(t, 2, 2, '\t', 'js'); assert.strictEqual(apply(t, e), '\tx\n\t');
  t = 'a'; e = C.enterEdit(t, 0, 0, '  ', 'js'); assert.strictEqual(apply(t, e), '\na');  // no crash at the start of the file
});
test('auto-close, wrap and type-over', () => {
  let e = C.autoCloseEdit('f', 1, 1, '(', 'js'); assert.strictEqual(apply('f', e), 'f()'); assert.deepStrictEqual(e.sel, [2, 2]);
  assert.strictEqual(C.autoCloseEdit('f(a)', 2, 2, '(', 'js'), null);              // not before a word character
  assert.deepStrictEqual(C.autoCloseEdit('f()', 2, 2, ')', 'js'), { move: 3 });     // type over the closer
  e = C.autoCloseEdit('say hi', 4, 6, '"', 'js'); assert.strictEqual(apply('say hi', e), 'say "hi"'); assert.deepStrictEqual(e.sel, [5, 7]);
  assert.strictEqual(C.autoCloseEdit("don", 3, 3, "'", 'js'), null);                // apostrophes
  assert.strictEqual(C.autoCloseEdit('""', 2, 2, '"', 'js'), null);                  // triple quotes
  assert.strictEqual(C.autoCloseEdit('x', 1, 1, '(', 'markdown'), null);             // no pairing in prose
  assert.strictEqual(C.autoCloseEdit('x', 1, 1, '(', 'text'), null);
  e = C.autoCloseEdit('', 0, 0, '{', 'css'); assert.strictEqual(apply('', e), '{}');
});
test('backspace removes an empty pair', () => {
  const e = C.backspaceEdit('f()', 2, 2, 'js'); assert.strictEqual(apply('f()', e), 'f'); assert.deepStrictEqual(e.sel, [1, 1]);
  assert.strictEqual(C.backspaceEdit('f(a)', 3, 3, 'js'), null);
  assert.strictEqual(C.backspaceEdit('()', 1, 1, 'text'), null);
});
console.log(n + ' editor-core tests passed');
