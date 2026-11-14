// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 www.tca.ac.tz (https://www.tca.ac.tz)
// AnonyHost is free software under the GNU General Public License, version 3 or (at your option) any later version.
// It comes WITHOUT ANY WARRANTY. See the LICENSE file.
/* AnonyHost editor core: syntax highlighting and text-editing helpers.
   Pure functions only (no DOM), so they can be unit-tested in node. No external libraries. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.EditorCore = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var esc = function (s) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); };
  var span = function (c, s) { return '<span class="t-' + c + '">' + esc(s) + '</span>'; };
  var words = function (list) { return '\\b(?:' + list.split(' ').join('|') + ')\\b'; };
  var R = String.raw;
  var EOT = R`(?![\s\S])`;            // end of text (works with the m flag, unlike $)
  var BT = R`\x60`;                   // backtick

  // A language is a list of [class, regex source, optional render(fn)]. Sources must not contain capturing groups.
  function build(rules, flags) {
    return { re: new RegExp(rules.map(function (r) { return '(' + r[1] + ')'; }).join('|'), flags || 'g'), rules: rules };
  }

  function run(lang, text) {
    var re = lang.re, rules = lang.rules, out = '', last = 0, m;
    re.lastIndex = 0;
    while ((m = re.exec(text))) {
      if (m[0] === '') { re.lastIndex++; continue; }
      var k = 1; while (m[k] === undefined) k++;
      var rule = rules[k - 1];
      out += esc(text.slice(last, m.index));
      out += rule[2] ? rule[2](m[0]) : (rule[0] ? span(rule[0], m[0]) : esc(m[0]));
      last = m.index + m[0].length;
    }
    return out + esc(text.slice(last));
  }

  var JS_KW = 'async await break case catch class const continue debugger default delete do else export extends finally for function if import in instanceof let new return static super switch throw try typeof var void while with yield interface enum implements public private protected readonly abstract declare namespace';
  var NUM = R`\b(?:0[xX][\da-fA-F]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)\b`;

  function renderTag(t) {
    var head = /^<\/?[\w:-]+/.exec(t)[0], out = span('tag', head), rest = t.slice(head.length);
    var re = /("[^"]*"?|'[^']*'?)|([\w:@.-]+)|(\/?>)|([\s\S])/g, m, prev = '';
    while ((m = re.exec(rest))) {
      if (m[1] !== undefined) { out += span('s', m[1]); prev = 's'; }
      else if (m[2] !== undefined) { out += prev === '=' ? span('s', m[2]) : span('at', m[2]); prev = 'w'; }
      else if (m[3] !== undefined) { out += span('tag', m[3]); prev = '>'; }
      else { out += esc(m[4]); if (m[4].trim()) prev = m[4]; }
    }
    return out;
  }

  var LANGS = {
    js: build([
      ['c', R`\/\/[^\n]*|\/\*[\s\S]*?(?:\*\/|` + EOT + ')'],
      ['s', R`"(?:[^"\\\n]|\\.)*"?|'(?:[^'\\\n]|\\.)*'?|` + BT + R`(?:[^\x60\\]|\\[\s\S])*` + BT + '?'],
      ['n', NUM],
      ['k', words(JS_KW)],
      ['l', words('true false null undefined NaN Infinity this')],
      ['f', R`[A-Za-z_$][\w$]*(?=\s*\()`],
      ['', R`[A-Za-z_$][\w$]*`]
    ]),
    css: build([
      ['c', R`\/\*[\s\S]*?(?:\*\/|` + EOT + ')'],
      ['s', R`"(?:[^"\\\n]|\\.)*"?|'(?:[^'\\\n]|\\.)*'?`],
      ['a', R`@[\w-]+`],
      ['k', R`!important`],
      ['p', R`[\w-]+(?=\s*:(?![^;{}]*\{))`],
      ['v', R`--[\w-]+`],
      ['n', R`#[\da-fA-F]{3,8}\b|-?(?:\d+\.?\d*|\.\d+)(?:%|[a-zA-Z]{1,4})?`],
      ['f', R`[A-Za-z_-][\w-]*(?=\()`],
      ['sel', R`[.#][A-Za-z_][\w-]*`],
      ['', R`[A-Za-z_-][\w-]*`]
    ]),
    html: build([
      ['c', R`<!--[\s\S]*?(?:-->|` + EOT + ')'],
      ['k', R`<![A-Za-z][^>]*>?`],
      ['tag', R`<\/?[A-Za-z][\w:-]*(?:"[^"]*"|'[^']*'|[^>"'])*>?`, renderTag],
      ['e', R`&#?\w+;`]
    ]),
    php: build([
      ['pt', R`<\?(?:php|=)?|\?>`],
      ['c', R`\/\/[^\n]*|#[^\n]*|\/\*[\s\S]*?(?:\*\/|` + EOT + ')'],
      ['s', R`"(?:[^"\\]|\\[\s\S])*"?|'(?:[^'\\]|\\[\s\S])*'?`],
      ['v', R`\$[A-Za-z_]\w*`],
      ['n', NUM],
      ['k', words('abstract and array as break callable case catch class clone const continue declare default do echo else elseif empty extends final finally fn for foreach function global goto if implements include include_once instanceof interface isset list match namespace new or print private protected public readonly require require_once return static switch throw trait try unset use var while xor yield')],
      ['l', words('true false null TRUE FALSE NULL')],
      ['f', R`[A-Za-z_]\w*(?=\s*\()`],
      ['', R`[A-Za-z_]\w*`]
    ]),
    python: build([
      ['c', R`#[^\n]*`],
      ['s', R`[rRbBfFuU]{0,2}(?:"""[\s\S]*?(?:"""|` + EOT + R`)|'''[\s\S]*?(?:'''|` + EOT + R`))`],
      ['s', R`[rRbBfFuU]{0,2}(?:"(?:[^"\\\n]|\\.)*"?|'(?:[^'\\\n]|\\.)*'?)`],
      ['d', R`@[A-Za-z_][\w.]*`],
      ['n', NUM],
      ['k', words('and as assert async await break class continue def del elif else except finally for from global if import in is lambda nonlocal not or pass raise return try while with yield')],
      ['l', words('True False None self cls')],
      ['f', R`[A-Za-z_]\w*(?=\s*\()`],
      ['', R`[A-Za-z_]\w*`]
    ]),
    json: build([
      ['p', R`"(?:[^"\\\n]|\\.)*"(?=\s*:)`],
      ['s', R`"(?:[^"\\\n]|\\.)*"?`],
      ['n', R`-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?`],
      ['l', words('true false null')]
    ]),
    markdown: build([
      ['c', BT + BT + BT + R`[\s\S]*?(?:` + BT + BT + BT + '|' + EOT + ')'],
      ['c', R`<!--[\s\S]*?(?:-->|` + EOT + ')'],
      ['h', R`^#{1,6}[ \t][^\n]*`],
      ['q', R`^>[^\n]*`],
      ['s', BT + R`[^\x60\n]+` + BT],
      ['k', R`\*\*[^*\n]+\*\*|__[^_\n]+__`],
      ['lk', R`!?\[[^\]\n]*\]\([^)\n]*\)`],
      ['n', R`^[ \t]*(?:[-*+]|\d+\.)[ \t]`]
    ], 'gm')
  };

  function phpMode(text) {
    var re = /<\?(?:php|=)?[\s\S]*?(?:\?>|(?![\s\S]))/g, out = '', last = 0, m;
    while ((m = re.exec(text))) {
      out += run(LANGS.html, text.slice(last, m.index)) + run(LANGS.php, m[0]);
      last = m.index + m[0].length;
    }
    return out + run(LANGS.html, text.slice(last));
  }

  function highlight(lang, text) {
    if (lang === 'php') return phpMode(text);
    return LANGS[lang] ? run(LANGS[lang], text) : esc(text);
  }

  var EXT = { html: 'html', htm: 'html', xhtml: 'html', xml: 'html', svg: 'html', css: 'css', js: 'js', mjs: 'js', cjs: 'js', jsx: 'js',
    ts: 'js', tsx: 'js', json: 'json', webmanifest: 'json', php: 'php', phtml: 'php', py: 'python', pyw: 'python', md: 'markdown', markdown: 'markdown' };
  var NAMES = { html: 'HTML', css: 'CSS', js: 'JavaScript', json: 'JSON', php: 'PHP', python: 'Python', markdown: 'Markdown', text: 'Plain text' };

  function detect(name) {
    var m = /\.([A-Za-z0-9]+)$/.exec(name || '');
    return (m && EXT[m[1].toLowerCase()]) || 'text';
  }

  // ---------- editing helpers: each returns an edit {from, to, insert, sel:[a,b]} or {move} or null ----------
  var PAIR_LANGS = { html: 1, css: 1, js: 1, json: 1, php: 1, python: 1 };
  var OPEN = { '(': ')', '[': ']', '{': '}', '"': '"', "'": "'", '`': '`' };
  var CLOSERS = ')]}"\'`';

  function lineStart(text, i) { return i <= 0 ? 0 : text.lastIndexOf('\n', i - 1) + 1; }

  function lineRange(text, s, t) {
    var a = lineStart(text, s), end = (t > s && text[t - 1] === '\n') ? t - 1 : t, b = text.indexOf('\n', end);
    return [a, b < 0 ? text.length : b];
  }

  function defaultUnit(lang) { return /^(html|css|js|json|markdown)$/.test(lang) ? '  ' : '    '; }

  function detectIndent(text, lang) {
    var lines = text.split('\n', 500), tabs = 0, two = 0, four = 0;
    for (var i = 0; i < lines.length; i++) {
      var l = lines[i];
      if (l.charAt(0) === '\t') { tabs++; continue; }
      var m = /^( +)\S/.exec(l);
      if (m) { if (m[1].length % 4 === 2) two++; else if (m[1].length % 4 === 0) four++; }
    }
    if (tabs > two + four) return '\t';
    if (two > 0) return '  ';
    return four > 0 ? '    ' : defaultUnit(lang);
  }

  function indentEdit(text, s, t, unit) {
    if (s === t) {
      var ins = unit;
      if (unit.charAt(0) === ' ') ins = new Array(unit.length - ((s - lineStart(text, s)) % unit.length) + 1).join(' ');
      return { from: s, to: t, insert: ins, sel: [s + ins.length, s + ins.length] };
    }
    var r = lineRange(text, s, t), block = text.slice(r[0], r[1]);
    var out = block.split('\n').map(function (l) { return l.length ? unit + l : l; }).join('\n');
    return { from: r[0], to: r[1], insert: out, sel: [r[0], r[0] + out.length] };
  }

  function outdentEdit(text, s, t, unit) {
    var r = lineRange(text, s, t), block = text.slice(r[0], r[1]), first = 0, n = 0;
    var re = unit === '\t' ? /^(?:\t| {1,4})/ : new RegExp('^(?:\\t| {1,' + unit.length + '})');
    var out = block.split('\n').map(function (l, i) {
      var m = re.exec(l), cut = m ? m[0].length : 0;
      if (i === 0) first = cut;
      n += cut;
      return l.slice(cut);
    }).join('\n');
    if (!n) return null;
    if (s === t) { var c = Math.max(r[0], s - first); return { from: r[0], to: r[1], insert: out, sel: [c, c] }; }
    return { from: r[0], to: r[1], insert: out, sel: [r[0], r[0] + out.length] };
  }

  function enterEdit(text, s, t, unit, lang) {
    var ls = lineStart(text, s), lead = /^[ \t]*/.exec(text.slice(ls, s))[0];
    var prev = s > 0 ? text.charAt(s - 1) : '', next = t < text.length ? text.charAt(t) : '';
    var oi = prev ? '{[('.indexOf(prev) : -1, extra = oi >= 0 ? unit : '';
    if (lang === 'python' && prev === ':') extra = unit;
    var between = (oi >= 0 && next === '}])'.charAt(oi)) || ((lang === 'html' || lang === 'php') && prev === '>' && text.substr(t, 2) === '</');
    if (between) {
      if (oi < 0) extra = unit;
      var ins = '\n' + lead + extra + '\n' + lead, c = s + 1 + lead.length + extra.length;
      return { from: s, to: t, insert: ins, sel: [c, c] };
    }
    var plain = '\n' + lead + extra, p = s + plain.length;
    return { from: s, to: t, insert: plain, sel: [p, p] };
  }

  function autoCloseEdit(text, s, t, key, lang) {
    if (!PAIR_LANGS[lang]) return null;
    var prev = s > 0 ? text.charAt(s - 1) : '', next = t < text.length ? text.charAt(t) : '';
    if (s === t && key.length === 1 && CLOSERS.indexOf(key) >= 0 && next === key) return { move: s + 1 };  // type over the closer
    if (!OPEN[key]) return null;
    var close = OPEN[key], quote = key === close;
    if (s !== t) return { from: s, to: t, insert: key + text.slice(s, t) + close, sel: [s + 1, t + 1] };  // wrap the selection
    if (quote && (/\w/.test(prev) || /\w/.test(next) || prev === key)) return null;  // apostrophes, word-adjacent, triple quotes
    if (next && !/[\s)\]}>,;:.]/.test(next)) return null;
    return { from: s, to: s, insert: key + close, sel: [s + 1, s + 1] };
  }

  function backspaceEdit(text, s, t, lang) {
    if (s !== t || s < 1 || !PAIR_LANGS[lang]) return null;
    var p = text.charAt(s - 1), n = text.charAt(s);
    return (OPEN[p] && OPEN[p] === n) ? { from: s - 1, to: s + 1, insert: '', sel: [s - 1, s - 1] } : null;
  }

  return { esc: esc, highlight: highlight, detect: detect, names: NAMES, lineStart: lineStart, defaultUnit: defaultUnit, detectIndent: detectIndent,
    indentEdit: indentEdit, outdentEdit: outdentEdit, enterEdit: enterEdit, autoCloseEdit: autoCloseEdit, backspaceEdit: backspaceEdit };
});
