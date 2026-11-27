import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const readJson = (...p) => JSON.parse(readFileSync(path.join(repoRoot, ...p), 'utf8'));

test('Antigravity 插件清单符合 schema 且与其余三端版本一致', () => {
  const agy = readJson('.antigravity-plugin', 'plugin.json');
  assert.equal(agy.$schema, 'https://antigravity.google/schemas/v1/plugin.json');
  assert.match(agy.name, /^[a-z0-9]+(-[a-z0-9]+)*$/);
  assert.equal(agy.version, readJson('.devin-plugin', 'plugin.json').version);
  assert.equal(agy.version, readJson('.claude-plugin', 'plugin.json').version);
  assert.equal(agy.version, readJson('.codex-plugin', 'plugin.json').version);
  assert.match(agy.author.url, /^https:\/\//);
  assert.ok(Array.isArray(agy.suggestedPrompts) && agy.suggestedPrompts.length <= 3);
});

test('SKILL.md frontmatter name 与目录名一致', () => {
  const md = readFileSync(path.join(repoRoot, 'skills', 'security-scan', 'SKILL.md'), 'utf8');
  assert.match(md, /^---\r?\n[\s\S]*?\bname:\s*security-scan\b[\s\S]*?\r?\n---/);
});
