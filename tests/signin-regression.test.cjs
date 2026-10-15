const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');

const worker = readFileSync(join(__dirname, '..', 'index.js'), 'utf8');

// The Worker embeds its HTML as an escaped JavaScript string. Permit escaped
// or unescaped quotes so these checks remain readable without rewriting source.
const quote = String.raw`\\*["']`;

test('sign-in gate exists and has a visible-by-default layout', () => {
  assert.match(worker, new RegExp('id=' + quote + 'gate'));
  assert.match(worker, /\.gate\{[^}]*display:grid/);
  assert.match(worker, /\.gate\.out\{[^}]*visibility:hidden/);
  assert.match(worker, /function openGate\(mode='login'\)[\s\S]*?gate\.style\.display='';gate\.classList\.remove\('out'\)/);
  assert.match(worker, /function openGate\(mode='login'\)[\s\S]*?authForm\(mode\)/);
});

test('sign-in form contains username, password, submit and visible feedback hooks', () => {
  assert.match(worker, /id=\\*["']schoolAuth/);
  assert.match(worker, /name=\\*["']username/);
  assert.match(worker, /type=\\*["']password/);
  assert.match(worker, /Launch my universe/);
  assert.match(worker, /id=\\*["']authFeedback/);
  assert.match(worker, /role=\\*["']alert/);
});

test('sign-in submission calls the login API and handles errors without hiding feedback', () => {
  assert.match(worker, /call\('\/api\/'\+\(reg\?'register':recover\?'recover':'login'\),body\)/);
  assert.match(worker, /catch\(e\)\{\$\('authFeedback'\)\.textContent=e\.message;b\.disabled=false\}/);
  assert.match(worker, /if\(path==='\/api\/login'\)/);
  assert.match(worker, /Username or password is incorrect\./);
});

test('the login gate is not permanently hidden by a hidden attribute rule', () => {
  assert.match(worker, /\.gate\{[^}]*display:grid/);
  assert.match(worker, /\.gate\.out\{[^}]*visibility:hidden/);
  assert.doesNotMatch(worker, /\.gate\s*\{[^}]*display\s*:\s*none/);
});
