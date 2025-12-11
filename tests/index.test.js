
import path from 'path';
import fs from 'fs';
import { spawnSync } from 'child_process';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const scannerPath = path.resolve(__dirname, '../index.js');
const fixtures = [
  {
    name: 'scan-yarn',
    root: path.resolve(__dirname, '../scan-yarn'),
    expect: {
      hasFindings: false,
      exitCode: 0,
      passedScan: true,
      reason: undefined
    }
  },
  {
    name: 'scan-no-lock',
    root: path.resolve(__dirname, '../scan-no-lock'),
    expect: {
      hasFindings: false,
      exitCode: 3,
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

describe('Integration tests: index.js', () => {
  for (const fixture of fixtures) {
    describe(fixture.name, () => {
      let json;
      beforeAll(() => {
        if (
          !fs.existsSync(fixture.root) ||
          !fs.statSync(fixture.root).isDirectory()
        ) {
          throw new Error(`[${fixture.name}] missing directory at ${fixture.root}`);
        }
        const { jsonPath } = runScanner(fixture);
        json = loadJson(jsonPath);
        if (!json) {
          throw new Error(`[${fixture.name}] failed to load JSON output at ${jsonPath}`);
        }
      });

      it('should have correct exit code', () => {
        expect(json.meta.exitCode).toBe(fixture.expect.exitCode);
      });

      it('should have correct passedScan', () => {
        expect(json.meta.passedScan).toBe(fixture.expect.passedScan);
      });

      it('should have correct vulnerabilities presence', () => {
        const hasFindings = (json.vulnerabilities || []).length > 0;
        expect(hasFindings).toBe(fixture.expect.hasFindings);
      });

      it('should have consistent vulnerabilitiesCount', () => {
        if (typeof json.meta.vulnerabilitiesCount === 'number') {
          expect(json.meta.vulnerabilitiesCount).toBe((json.vulnerabilities || []).length);
        }
      });

      it('should have correct reason', () => {
        if (fixture.expect.reason) {
          expect(json.meta.reason).toBe(fixture.expect.reason);
        } else {
          expect(json.meta.reason).toBeUndefined();
        }
      });
    });
  }
});

