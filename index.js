const fs = require('fs');
const fsp = fs.promises;
const path = require('path');

const WORKSPACE_DEFAULT_ROOT = path.resolve(__dirname, '..');
const COMPROMISED_FILE = path.resolve(__dirname, 'compromised-packages.txt');

async function loadCompromisedList(filePath) {
  const raw = await fsp.readFile(filePath, 'utf8');
  const byName = new Map();
  const exactSet = new Set();
  const lines = raw.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const idx = trimmed.lastIndexOf(':');
    if (idx <= 0) continue;
    const name = trimmed.slice(0, idx).trim();
    const version = trimmed.slice(idx + 1).trim();
    if (!name || !version) continue;
    if (!byName.has(name)) byName.set(name, new Set());
    byName.get(name).add(version);
    exactSet.add(`${name}:${version}`);
  }
  return { byName, exactSet };
}

async function walkDir(root, onFile) {
  const ignoreDirs = new Set([
    'node_modules',
    '.git',
    '.hg',
    '.svn',
    '.idea',
    '.vscode',
    'dist',
    'build',
    'coverage',
    '.cache'
  ]);
  async function walk(current) {
    let entries;
    try {
      entries = await fsp.readdir(current, { withFileTypes: true });
    } catch (e) {
      return; // skip unreadable directories
    }
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (ignoreDirs.has(entry.name)) continue;
        await walk(full);
      } else if (entry.isFile()) {
        await onFile(full);
      }
    }
  }
  await walk(root);
}

// Helper: normalize version specs from package.json (strip ^ ~ >= <= ~ etc., handle ranges)
function normalizeSpecToCandidates(spec) {
  if (!spec || typeof spec !== 'string') return [];
  // Handle npm/yarn aliases like "npm:pkg@1.2.3"
  const npmAliasMatch = spec.match(/npm:([^@]+)@([^\s]+)/);
  if (npmAliasMatch) return [npmAliasMatch[2]];
  // Handle "version1 || version2" cases
  const orParts = spec
    .split('||')
    .map(s => s.trim())
    .filter(Boolean);
  const cleaned = s =>
    s
      .replace(/^[~^><=\s]*/, '')
      .replace(/^v/, '')
      .trim();
  return orParts.map(cleaned).filter(Boolean);
}

// Scanner for package.json
function scanPackageJson(content, filePath, compromised) {
  const vulnerabilities = [];
  let json;
  try {
    json = JSON.parse(content);
  } catch {
    return vulnerabilities;
  }
  const sections = [
    'dependencies',
    'devDependencies',
    'peerDependencies',
    'optionalDependencies'
  ];
  for (const section of sections) {
    const deps = json[section];
    if (!deps || typeof deps !== 'object') continue;
    for (const [name, spec] of Object.entries(deps)) {
      const candidates = normalizeSpecToCandidates(spec);
      for (const ver of candidates) {
        if (
          compromised.exactSet.has(`${name}:${ver}`) ||
          compromised.byName.get(name)?.has(ver)
        ) {
          vulnerabilities.push({
            file: filePath,
            name,
            version: ver,
            source: 'package.json',
            section
          });
        }
      }
    }
  }
  return vulnerabilities;
}

// Scanner for yarn.lock (classic v1 format)

function scanYarnLock(content, filePath, compromised) {
  const vulnerabilities = [];
  const lines = content.split(/\r?\n/);
  // Track current entry specifiers; we now only use the package name for exact resolved version matching.
  let currentEntries = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Key line ends with ':' (can include multiple specifiers separated by ', ')
    if (/^[^#].*:\s*$/.test(line)) {
      const specs = line.replace(/:\s*$/, '').split(/,\s*/);
      currentEntries = specs.map(spec => {
        spec = spec.replace(/^"|"$/g, '').replace(/^'|'$/g, '');
        const atIdx = spec.lastIndexOf('@');
        let name = spec;
        if (atIdx > 0) {
          name = spec.slice(0, atIdx);
        }
        return { name };
      });
      continue;
    }

    // Non-standard lock entry variant: name:range (no trailing colon, no quotes)
    if (
      !line.endsWith(':') &&
      /^[^#"'][@A-Za-z0-9_.\-]+:[^\s]+$/.test(line.trim())
    ) {
      const firstColon = line.indexOf(':');
      if (firstColon > 0) {
        const pkgName = line.slice(0, firstColon).trim();
        currentEntries = [{ name: pkgName }];
        continue;
      }
    }

    // Version line:   version "x.y.z"
    const vm = line.match(/^\s*version\s+"([^"]+)"/);
    if (vm && currentEntries.length) {
      const resolvedVersion = vm[1];
      for (const entry of currentEntries) {
        const name = entry.name;
        // Only match exact installed (resolved) version
        if (
          compromised.exactSet.has(`${name}:${resolvedVersion}`) ||
          compromised.byName.get(name)?.has(resolvedVersion)
        ) {
          vulnerabilities.push({
            file: filePath,
            name,
            version: resolvedVersion,
            source: 'yarn.lock'
          });
        }
      }
      continue;
    }

    if (!line.trim()) currentEntries = [];
  }
  return vulnerabilities;
}

async function main() {
  const argv = process.argv.slice(2);
  const rootFlagIdx = argv.findIndex(a => a === '--root');
  const root =
    rootFlagIdx >= 0 && argv[rootFlagIdx + 1]
      ? path.resolve(argv[rootFlagIdx + 1])
      : WORKSPACE_DEFAULT_ROOT;

  // Load compromised list
  const compromised = await loadCompromisedList(COMPROMISED_FILE);

  const vulnerabilities = [];
  const scannedFiles = [];

  function isCandidateFile(file) {
    const base = path.basename(file);
    if (base === 'package.json' || base === 'yarn.lock') return true;
    return false;
  }

  await walkDir(root, async filePath => {
    if (!isCandidateFile(filePath)) return;
    let content;
    try {
      content = await fsp.readFile(filePath, 'utf8');
    } catch {
      return;
    }
    scannedFiles.push(filePath);
    const base = path.basename(filePath);
    let fileFindings = [];
    if (base === 'package.json') {
      fileFindings = scanPackageJson(content, filePath, compromised);
    } else if (base === 'yarn.lock') {
      fileFindings = scanYarnLock(content, filePath, compromised);
    }
    vulnerabilities.push(...fileFindings);
  });

  // Deduplicate findings
  const unique = new Map();
  for (const f of vulnerabilities) {
    const key = `${f.file}|${f.name}|${f.version}`;
    if (!unique.has(key)) unique.set(key, f);
  }
  const result = Array.from(unique.values());

  // Output
  console.log(`Scanned files: ${scannedFiles.length}`);
  console.log(`vulnerabilities: ${result.length}`);
  if (result.length) {
    for (const f of result) {
      console.log(
        `[Vulnerability Found ❌] ${f.name}@${f.version} in ${f.file} (${f.source})`
      );
    }
    process.exitCode = 1; // signal compromised detection
  } else {
    console.log('No compromised packages found. ✅');
  }

  // Prepare structured JSON output
  const compromisedPackageCount = compromised.byName.size;
  let compromisedVersionCount = 0;
  for (const versions of compromised.byName.values())
    compromisedVersionCount += versions.size;

  // Determine pass/fail logic. If no candidate files were found, mark failed and add reason.
  let passedScan = result.length === 0;
  let reason;
  if (scannedFiles.length === 0) {
    passedScan = false;
    reason = 'No package or lock files found; scan inconclusive.';
    // Distinct exit code if not already set by findings
    if (!process.exitCode) process.exitCode = 3;
  }

  const jsonOutput = {
    meta: {
      generatedAt: new Date().toISOString(),
      root,
      scanner: 'hof-vulnerabilities-scanner',
      version: '1.0.0',
      scannedFilesCount: scannedFiles.length,
      findingsCount: result.length,
      compromisedPackageCount,
      compromisedVersionCount,
      exitCode: process.exitCode || 0,
      passedScan,
      ...(reason ? { reason } : {})
    },
    vulnerabilities: result.map(f => ({
      package: f.name,
      version: f.version,
      file: f.file,
      fileRelative: path.relative(root, f.file),
      source: f.source,
      spec: `${f.name}@${f.version}`
    })),
    scannedFiles: scannedFiles.map(f => ({
      path: f,
      relative: path.relative(root, f),
      type: path.basename(f)
    }))
  };

  const outputFileFlagIdx = argv.findIndex(a => a === '--json-out');
  const outputFile =
    outputFileFlagIdx >= 0 && argv[outputFileFlagIdx + 1]
      ? path.resolve(argv[outputFileFlagIdx + 1])
      : path.resolve(process.cwd(), 'scan-results.json');

  try {
    await fsp.writeFile(
      outputFile,
      JSON.stringify(jsonOutput, null, 2),
      'utf8'
    );
    console.log(`JSON results written to: ${outputFile}`);
  } catch (e) {
    console.error('Failed to write JSON results:', e.message);
  }
}

main().catch(err => {
  console.error('Scanner failed:', err);
  process.exitCode = 2;
});
