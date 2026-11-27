import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const readJson = (...p) => JSON.parse(readFileSync(path.join(repoRoot, ...p), 'utf8'));

const ALLOWED_KEYS = new Set([
  '$schema', 'name', 'displayName', 'description', 'version', 'disabled',
  'logo', 'suggestedPrompts', 'skills', 'author', 'homepage', 'repository',
  'license', 'keywords', 'extensions',
]);
const ALLOWED_AUTHOR_KEYS = new Set(['name', 'email', 'url']);

test('Antigravity 插件清单符合官方 v1 Schema 约束且与其余三端版本一致', () => {
  const agy = readJson('.antigravity-plugin', 'plugin.json');
  for (const key of Object.keys(agy)) {
    assert.ok(ALLOWED_KEYS.has(key), `存在 schema 未允许的字段: ${key}`);
  }
  assert.equal(agy.$schema, 'https://antigravity.google/schemas/v1/plugin.json');
  assert.equal(typeof agy.name, 'string');
  assert.match(agy.name, /^[a-z0-9]+(-[a-z0-9]+)*$/);
  assert.equal(typeof agy.displayName, 'string');
  assert.equal(typeof agy.description, 'string');
  assert.equal(typeof agy.version, 'string');
  assert.equal(agy.version, readJson('.devin-plugin', 'plugin.json').version);
  assert.equal(agy.version, readJson('.claude-plugin', 'plugin.json').version);
  assert.equal(agy.version, readJson('.codex-plugin', 'plugin.json').version);
  assert.equal(typeof agy.homepage, 'string');
  assert.match(agy.homepage, /^https:\/\//);
  assert.equal(typeof agy.repository, 'string');
  assert.match(agy.repository, /^https:\/\//);
  assert.equal(typeof agy.author, 'object');
  for (const key of Object.keys(agy.author)) {
    assert.ok(ALLOWED_AUTHOR_KEYS.has(key), `author 存在未允许字段: ${key}`);
    assert.equal(typeof agy.author[key], 'string');
  }
  assert.match(agy.author.url, /^https:\/\//);
  assert.ok(Array.isArray(agy.suggestedPrompts) && agy.suggestedPrompts.length <= 3);
  for (const prompt of agy.suggestedPrompts) {
    assert.equal(typeof prompt, 'string');
    assert.match(prompt, /\S/);
  }
  assert.ok(Array.isArray(agy.keywords));
  for (const kw of agy.keywords) {
    assert.equal(typeof kw, 'string');
  }
});

test('SKILL.md frontmatter name 与目录名精确一致', () => {
  const md = readFileSync(path.join(repoRoot, 'skills', 'security-scan', 'SKILL.md'), 'utf8');
  const fm = md.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  assert.ok(fm, '缺少 YAML frontmatter');
  const nameLine = fm[1].split(/\r?\n/).find((l) => /^name:\s*/.test(l));
  assert.ok(nameLine, 'frontmatter 缺少 name 字段');
  const name = nameLine.replace(/^name:\s*/, '').trim().replace(/^["']|["']$/g, '');
  assert.equal(name, 'security-scan');
});
