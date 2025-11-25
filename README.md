# hof-vulnerabilities-scanner

It matches ONLY exact package name + version pairs listed in `compromised-packages.txt` against:

- Declared dependency specs in every `package.json`
- Resolved installed versions in `yarn.lock`

## Quick Start

From this folder:

```bash
node index.js --root /path/to/your/repo --json-out /path/to/save/scan-results.json
```

If you omit `--root`, it scans the parent directory of this project. If you omit `--json-out`, it writes `scan-results.json` into your current working directory.

Common examples:

```bash
# Scan a monorepo
node index.js --root ~/dev/your-monorepo

# Scan current working directory and write default JSON
node index.js

# Custom output file
node index.js --root ~/projects/app --json-out ~/projects/app/tmp/vuln-scan.json
```

## CLI Flags

| Flag | Value | Purpose |
|------|-------|---------|
| `--root <path>` | directory path | Root directory to recursively search for `package.json` and `yarn.lock` files |
| `--json-out <file>` | file path | Where to write detailed structured JSON results |

## What the Console Output Means

Typical run:

```text
Scanned files: 42
vulnerabilities: 3
[Vulnerability Found ❌] chalk@5.6.1 in /repo/app/package.json (package.json)
[Vulnerability Found ❌] debug@4.4.2 in /repo/app/yarn.lock (yarn.lock)
[Vulnerability Found ❌] has-flag@3.0.0 in /repo/lib/package.json (package.json)
JSON results written to: /repo/scan-results.json
```

Explanation:

- `Scanned files` – Count of `package.json` and `yarn.lock` files successfully read.
- `vulnerabilities` – Unique compromised findings (deduplicated by file + package + version).
- Each `[Vulnerability Found ❌]` line – Exact match of a name:version pair appearing in the compromised list.
- Final line – Location where the detailed JSON report was written.
- If none found you will see: `No compromised packages found. ✅`

If no candidate files are found at all you will get an inconclusive scan with a distinct exit code and a reason in JSON.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed, no compromised packages detected |
| `1` | Compromised packages detected (at least one vulnerability) |
| `2` | Scanner runtime failure (unexpected error) |
| `3` | No dependency files found – scan inconclusive |

Use shell conditionals (e.g. CI) to fail builds on exit code `1`.

## JSON Output Structure (summary)

Written to the chosen `--json-out` path (default `scan-results.json`). Key parts:

```jsonc
{
  "meta": {
    "generatedAt": "2025-11-25T10:42:00.000Z",
    "root": "/repo",
    "scannedFilesCount": 42,
    "findingsCount": 3,
    "compromisedPackageCount": 250,      // unique package names in list
    "compromisedVersionCount": 571,      // total name:version pairs tracked
    "exitCode": 1,
    "passedScan": false
  },
  "vulnerabilities": [
    {
      "package": "chalk",
      "version": "5.6.1",
      "file": "/repo/app/package.json",
      "fileRelative": "app/package.json",
      "source": "package.json",
      "spec": "chalk@5.6.1"
    }
  ],
  "scannedFiles": [
    { "path": "/repo/app/package.json", "relative": "app/package.json", "type": "package.json" }
  ]
}
```

`meta` summarizes the scan and decision; `vulnerabilities` lists each matched compromised version; `scannedFiles` lists all dependency files inspected.

## How Matching Works

### package.json

- For each dependency section (`dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`), specs are normalized.
- Aliases like `"npm:pkg@1.2.3"` extract the real version (`1.2.3`).
- Multiple OR ranges (`"1.2.3 || 1.2.4"`) are split; each cleaned candidate is checked for exact match.
- Only exact versions present in the compromised list trigger findings (not broader ranges).

### yarn.lock (Yarn v1)

- The scanner parses entry headers and their subsequent `version "x.y.z"` lines.
- The resolved installed version is matched against the compromised list.
- This ensures you catch transitive dependencies actually installed, even if not pinned directly in `package.json`.

## Updating the Compromised List

File: `compromised-packages.txt`

- Format: `package-name:version` one per line.
- Lines beginning with `#` are comments.
- Append newly discovered compromised versions; avoid removing entries unless verified safe.
- Commit changes so team scans stay consistent.

## Limitations / Notes

- Exact-version matching only; a range like `^5.6.0` will not flag unless a lockfile resolves to a listed compromised version.
- Currently supports Yarn v1 lockfile syntax; pnpm or npm lockfiles are not parsed yet.
- Empty or unreadable directories are skipped silently.

## Automating in CI (example)

```bash
node index.js --root "$PWD" || EXIT=$?
if [ "${EXIT}" = "1" ]; then
  echo "Compromised packages detected" >&2
  exit 1
fi
exit ${EXIT:-0}
```

Run `node index.js` to perform a scan. ✅
