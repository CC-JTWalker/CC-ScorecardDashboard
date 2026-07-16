'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const IGNORE_DIRS = new Set(['.git', 'node_modules', 'dist', 'out', 'coverage']);
const errors = [];

for (const required of [
  'SECURITY.md',
  'CONTRIBUTING.md',
  'GOVERNANCE.md',
  '.github/CODEOWNERS',
  '.github/dependabot.yml',
  '.github/workflows/ci.yml',
  '.github/workflows/codeql.yml',
  '.github/workflows/scorecard.yml',
  '.github/workflows/release.yml'
]) {
  if (!fs.existsSync(path.join(ROOT, required))) errors.push(`Missing required security file: ${required}`);
}

const packageJson = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
for (const section of ['dependencies', 'devDependencies', 'optionalDependencies']) {
  for (const [name, version] of Object.entries(packageJson[section] || {})) {
    if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)) {
      errors.push(`${section}.${name} must use an exact version, found ${version}`);
    }
  }
}

const jsFiles = walk(ROOT).filter((file) => file.endsWith('.js'));
for (const file of jsFiles) {
  const result = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  if (result.status !== 0) errors.push(`JavaScript syntax error in ${path.relative(ROOT, file)}:\n${result.stderr.trim()}`);
}

const workflowDir = path.join(ROOT, '.github', 'workflows');
for (const file of fs.readdirSync(workflowDir).filter((name) => /\.ya?ml$/i.test(name))) {
  const filePath = path.join(workflowDir, file);
  const text = fs.readFileSync(filePath, 'utf8');
  if (/\bpull_request_target\s*:/i.test(text)) errors.push(`${file} uses pull_request_target`);
  if (/permissions\s*:\s*write-all/i.test(text)) errors.push(`${file} grants write-all permissions`);
  if (!/^permissions\s*:/m.test(text)) errors.push(`${file} does not declare top-level permissions`);

  for (const match of text.matchAll(/^\s*uses:\s*([^\s#]+)(?:\s+#.*)?$/gm)) {
    const reference = match[1];
    const at = reference.lastIndexOf('@');
    if (at === -1 || !/^[a-f0-9]{40}$/i.test(reference.slice(at + 1))) {
      errors.push(`${file} has an action that is not pinned to a full commit SHA: ${reference}`);
    }
  }
}

if (errors.length) {
  console.error(`Project checks failed (${errors.length}):`);
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}

console.log(`Project checks passed: ${jsFiles.length} JavaScript files and all workflow/action pins verified.`);

function walk(directory) {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && IGNORE_DIRS.has(entry.name)) continue;
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...walk(fullPath));
    else if (entry.isFile()) files.push(fullPath);
  }
  return files;
}
