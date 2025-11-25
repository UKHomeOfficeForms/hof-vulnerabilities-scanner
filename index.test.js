const path = require('path');
const fs = require('fs');
const { spawnSync } = require('child_process');

const scannerPath = path.resolve(__dirname, 'index.js');
const fixtures = [
  {
    name: 'scan-yarn',
    root: path.resolve(__dirname, '../scan-yarn'),
    expect: {
      hasFindings: false, // no compromised packages in fixture
      exitCode: 0, // clean scan
      passedScan: true,
      reason: undefined // no reason key expected
    }
  },
  {
    name: 'scan-no-lock',
    root: path.resolve(__dirname, '../scan-no-lock'),
    expect: {
      hasFindings: false,
      exitCode: 3, // empty scan scenario
      passedScan: false,
      reason: 'No package or lock files found; scan inconclusive.'
    }
  }
];

function runScanner(fixture) {
  const jsonOut = path.resolve(__dirname, `scan-results-${fixture.name}.json`);
  const args = [scannerPath, '--root', fixture.root, '--json-out', jsonOut];
  const result = spawnSync('node', args, { encoding: 'utf8' });
  return { cp: result, jsonPath: jsonOut };
}

function loadJson(p) {
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch (e) {
    return null;
  }
}

const failures = [];
for (const fixture of fixtures) {
  // Pre-check: fixture directory exists
  if (
    !fs.existsSync(fixture.root) ||
    !fs.statSync(fixture.root).isDirectory()
  ) {
    failures.push(`[${fixture.name}] missing directory at ${fixture.root}`);
    continue;
  }
  const { cp, jsonPath } = runScanner(fixture);
  const json = loadJson(jsonPath);
  if (!json) {
    failures.push(
      `[${fixture.name}] failed to load JSON output at ${jsonPath}`
    );
    continue;
  }

  const meta = json.meta || {};
  const vulnerabilities = json.vulnerabilities || [];

  // Validate exit code
  if (meta.exitCode !== fixture.expect.exitCode) {
    failures.push(
      `[${fixture.name}] expected exitCode ${fixture.expect.exitCode}, got ${meta.exitCode}`
    );
  }
  // Validate passedScan
  if (meta.passedScan !== fixture.expect.passedScan) {
    failures.push(
      `[${fixture.name}] expected passedScan=${fixture.expect.passedScan}, got ${meta.passedScan}`
    );
  }
  // Validate vulnerabilities presence
  const hasFindings = vulnerabilities.length > 0;
  if (hasFindings !== fixture.expect.hasFindings) {
    failures.push(
      `[${fixture.name}] vulnerabilities presence mismatch (expected hasFindings=${fixture.expect.hasFindings}, got ${hasFindings})`
    );
  }
  // Validate findingsCount consistency if present
  if (
    typeof meta.findingsCount === 'number' &&
    meta.findingsCount !== vulnerabilities.length
  ) {
    failures.push(
      `[${fixture.name}] meta.findingsCount (${meta.findingsCount}) does not match vulnerabilities length (${vulnerabilities.length})`
    );
  }
  // Validate reason logic
  if (fixture.expect.reason) {
    if (meta.reason !== fixture.expect.reason) {
      failures.push(
        `[${fixture.name}] expected reason '${fixture.expect.reason}', got '${meta.reason}'`
      );
    }
  } else if (meta.reason) {
    failures.push(`[${fixture.name}] unexpected reason '${meta.reason}'`);
  }
  // No specSource validation needed; current fixtures do not enforce source matching.
}

if (failures.length) {
  console.error('Integration tests FAILED');
  for (const f of failures) console.error(' -', f);
  process.exitCode = 1;
} else {
  console.log('Integration tests PASSED');
  process.exitCode = 0;
}
