#!/usr/bin/env node
// Code Guardian: the one cross-platform runner behind ./run.sh (Linux, macOS) and run.cmd / run.ps1 (Windows).
// The launchers only make sure a suitable Node exists; everything else lives here, so all OSes behave the same.
//
//   start (default)   build and start the API + worker and the web UI (Ctrl-C stops everything)
//   docker            same, with docker compose (200 MB container + Trivy server sidecar)
//   test              lint, typecheck and test backend and frontend
//   oom-check [MB]    a 600 MB report under --max-old-space-size=150
//   doctor            show which tools were found or will be installed
//   clean             remove the local toolchain, data and build output
//
// Nothing is installed globally: Trivy is used from PATH when present, otherwise a pinned, checksum-verified copy is
// downloaded into ./.cg-env/. Environment: API_PORT (3000), WEB_PORT (5173), CG_FORCE_LOCAL_TOOLS=1.
// Plain JavaScript with no dependencies on purpose: it runs before `npm ci`.

import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream, existsSync, mkdirSync, openSync, rmSync, writeFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';

const TRIVY_VERSION = '0.76.1'; // same version as the Docker image
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ENV_DIR = path.join(ROOT, '.cg-env');
const TOOLS = path.join(ENV_DIR, 'tools');
const WIN = process.platform === 'win32';
const EXE = WIN ? '.exe' : '';
const FORCE_LOCAL = process.env.CG_FORCE_LOCAL_TOOLS === '1';

// ------------------------------------------------------------------------------------------------ output
const tty = process.stdout.isTTY === true && process.env.NO_COLOR === undefined;
const c = (code) => (s) => (tty ? `\u001b[${code}m${s}\u001b[0m` : s);
const [bold, dim, green, yellow, red] = [c(1), c(2), c(32), c(33), c(31)];
const step = (s) => console.log(`${bold('==>')} ${s}`);
const info = (s) => console.log(`    ${s}`);
const ok = (s) => console.log(`    ${green('✓')} ${s}`);
const warn = (s) => console.log(`    ${yellow('!')} ${s}`);
class Fatal extends Error {}
const die = (s) => {
  throw new Fatal(s);
};

// ---------------------------------------------------------------------------------------------- platform
function platform() {
  const osName = { linux: 'linux', darwin: 'darwin', win32: 'windows' }[process.platform];
  const arch = { x64: 'x64', arm64: 'arm64' }[process.arch];
  if (osName === undefined) die(`Unsupported OS: ${process.platform}`);
  if (arch === undefined) die(`Unsupported CPU architecture: ${process.arch}`);
  return { os: osName, arch };
}

/** Absolute path of an executable on PATH, or null. */
function which(cmd) {
  const r = WIN ? spawnSync('where.exe', [cmd], { encoding: 'utf8' }) : spawnSync('sh', ['-c', `command -v "${cmd}"`], { encoding: 'utf8' });
  if (r.status !== 0) return null;
  return r.stdout.split(/\r?\n/).find((l) => l.trim() !== '')?.trim() ?? null;
}

function installHint(missing) {
  if (WIN) return missing.includes('git') ? 'winget install --id Git.Git -e   (or https://git-scm.com/download/win)' : '';
  if (process.platform === 'darwin') return 'xcode-select --install';
  for (const [pm, cmd] of [['apt-get', 'sudo apt-get install -y'], ['dnf', 'sudo dnf install -y'], ['apk', 'sudo apk add']]) {
    if (which(pm)) return `${cmd} ${missing.join(' ')}`;
  }
  return `install: ${missing.join(' ')}`;
}

function requireBasics() {
  const missing = ['git', 'tar'].filter((t) => which(t) === null);
  if (missing.length > 0) die(`missing required tools: ${missing.join(', ')}. Install with: ${installHint(missing)}`);
}

// ------------------------------------------------------------------------------------------- processes
/** Run a command to completion with inherited output; throw on failure. */
function run(cmd, args, opts = {}) {
  // npm is a .cmd script on Windows, which Node only spawns through a shell. The arguments here are fixed strings.
  const r = spawnSync(cmd, args, { stdio: 'inherit', shell: WIN && cmd === 'npm', ...opts });
  if (r.error) throw r.error;
  if (r.status !== 0) die(`${cmd} ${args.join(' ')} failed (exit ${String(r.status)})`);
}

const node = (args, opts) => run(process.execPath, args, opts);

// --------------------------------------------------------------------------------------------- downloads
async function download(url, dest) {
  const res = await fetch(url, { redirect: 'follow' });
  if (!res.ok || res.body === null) die(`download failed: ${url} (HTTP ${String(res.status)})`);
  await pipeline(Readable.fromWeb(res.body), createWriteStream(dest));
}

/** Small text files (checksum lists, logs, stamps), read through a stream like everything else in this repo. */
async function readText(file) {
  let text = '';
  for await (const chunk of createReadStream(file, 'utf8')) text += chunk;
  return text;
}

async function sha256(file) {
  const hash = createHash('sha256');
  await pipeline(createReadStream(file), hash);
  return hash.digest('hex');
}

/** Download `name` from `base`, verified against the release's checksum list, into a temp dir. */
async function verifiedDownload(base, checksumsName, name) {
  const tmp = await mkdtemp(path.join(os.tmpdir(), 'cg-'));
  await download(`${base}/${checksumsName}`, path.join(tmp, 'sums.txt'));
  const sums = await readText(path.join(tmp, 'sums.txt'));
  const expected = sums.split(/\r?\n/).map((l) => l.trim().split(/\s+/)).find(([, f]) => f === name)?.[0];
  const file = path.join(tmp, name);
  await download(`${base}/${name}`, file);
  const actual = await sha256(file);
  if (expected === undefined || actual !== expected) die(`checksum mismatch for ${name}: refusing to use it (expected ${String(expected)}, got ${actual})`);
  return { tmp, file };
}

// ------------------------------------------------------------------------------------------------ trivy
function trivyVersion(bin) {
  const r = spawnSync(bin, ['--version'], { encoding: 'utf8' });
  return r.status === 0 ? r.stdout.split(/\r?\n/)[0] : null;
}

async function ensureTrivy() {
  const system = FORCE_LOCAL ? null : which('trivy');
  if (system !== null && trivyVersion(system) !== null) return { bin: system, source: `system ${trivyVersion(system)}` };
  const local = path.join(TOOLS, 'trivy', `trivy${EXE}`);
  if (existsSync(local) && trivyVersion(local) !== null) return { bin: local, source: `local ${trivyVersion(local)}` };

  step(`Installing Trivy v${TRIVY_VERSION} into .cg-env`);
  const { os: o, arch } = platform();
  // Trivy ships Windows for x64 only; Windows on Arm runs it under emulation.
  const label = o === 'windows' ? 'windows-64bit.zip' : `${o === 'darwin' ? 'macOS' : 'Linux'}-${arch === 'arm64' ? 'ARM64' : '64bit'}.tar.gz`;
  const name = `trivy_${TRIVY_VERSION}_${label}`;
  const base = `https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}`;
  const { tmp, file } = await verifiedDownload(base, `trivy_${TRIVY_VERSION}_checksums.txt`, name);
  const dir = path.join(TOOLS, 'trivy');
  mkdirSync(dir, { recursive: true });
  // bsdtar (macOS, and Windows 10+ as tar.exe) reads zip too; GNU tar on Linux gets the .tar.gz.
  run('tar', ['-xf', file, '-C', dir, `trivy${EXE}`]);
  await rm(tmp, { recursive: true, force: true });
  ok(`Trivy ${TRIVY_VERSION} (checksum verified)`);
  return { bin: local, source: `local ${String(trivyVersion(local))}` };
}

// ------------------------------------------------------------------------------------------ dependencies
async function installDeps(dir, label) {
  const stamp = path.join(ENV_DIR, 'stamps', `${label}.lock-sha`);
  const want = await sha256(path.join(dir, 'package-lock.json'));
  const have = existsSync(stamp) ? (await readText(stamp)).trim() : '';
  if (existsSync(path.join(dir, 'node_modules')) && have === want) {
    ok(`${label} dependencies up to date`);
    return;
  }
  step(`Installing ${label} dependencies`);
  run('npm', ['ci', '--no-audit', '--no-fund', '--loglevel=error'], { cwd: dir });
  mkdirSync(path.dirname(stamp), { recursive: true });
  writeFileSync(stamp, want);
  ok(`${label} dependencies installed`);
}

const vite = path.join(ROOT, 'web', 'node_modules', 'vite', 'bin', 'vite.js');

function buildAll() {
  step('Building backend and web UI');
  run('npm', ['run', '--silent', 'build'], { cwd: ROOT });
  node([vite, 'build', '--logLevel', 'error'], { cwd: path.join(ROOT, 'web') });
  ok('build complete');
}

async function bootstrap() {
  platform();
  requireBasics();
  const trivy = await ensureTrivy();
  await installDeps(ROOT, 'backend');
  await installDeps(path.join(ROOT, 'web'), 'web');
  return trivy;
}

// -------------------------------------------------------------------------------------------- networking
const portFree = (port) =>
  new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.listen(port, '127.0.0.1', () => s.close(() => resolve(true)));
  });

async function pickPort(preferred) {
  let p = preferred;
  while (!(await portFree(p))) p += 1;
  return p;
}

async function waitHttp(url, seconds) {
  for (let i = 0; i < seconds; i += 1) {
    try {
      if ((await fetch(url)).ok) return true;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
}

async function tail(file, lines = 20) {
  try {
    return (await readText(file)).split(/\r?\n/).slice(-lines).join('\n');
  } catch {
    return '';
  }
}

// ---------------------------------------------------------------------------------------------- commands
async function cmdStart() {
  const trivy = await bootstrap();
  buildAll();

  const apiWanted = Number(process.env.API_PORT ?? 3000);
  const webWanted = Number(process.env.WEB_PORT ?? 5173);
  const apiPort = await pickPort(apiWanted);
  const webPort = await pickPort(webWanted);
  if (apiPort !== apiWanted) warn(`port ${String(apiWanted)} is busy; API uses ${String(apiPort)}`);
  if (webPort !== webWanted) warn(`port ${String(webWanted)} is busy; UI uses ${String(webPort)}`);
  for (const d of ['data', 'work', 'logs']) mkdirSync(path.join(ENV_DIR, d), { recursive: true });
  const apiLog = path.join(ENV_DIR, 'logs', 'api.log');
  const webLog = path.join(ENV_DIR, 'logs', 'web.log');

  const children = [];
  let stopping = false;
  const stop = (code) => {
    if (stopping) return;
    stopping = true;
    console.log('');
    step('Stopping');
    for (const ch of children) if (ch.exitCode === null) ch.kill('SIGTERM'); // the API re-queues in-flight scans
    const deadline = setTimeout(() => process.exit(code), 15_000);
    deadline.unref();
    Promise.all(children.map((ch) => (ch.exitCode === null ? new Promise((r) => ch.once('exit', r)) : null))).then(() => {
      ok('stopped');
      process.exit(code);
    });
  };
  process.on('SIGINT', () => stop(0));
  process.on('SIGTERM', () => stop(0));
  if (WIN) process.on('SIGBREAK', () => stop(0));

  const spawnLogged = (args, env, cwd, log) => {
    const ch = spawn(process.execPath, args, { cwd, env: { ...process.env, ...env }, stdio: ['ignore', openSync(log, 'w'), openSync(log, 'a')] });
    ch.once('exit', () => {
      if (!stopping) {
        warn(`a process exited; see ${path.relative(ROOT, log)}`);
        stop(1);
      }
    });
    children.push(ch);
    return ch;
  };

  step(`Starting API + worker on :${String(apiPort)}  ${dim("(node --max-old-space-size=150, the brief's self-test)")}`);
  if (!existsSync(path.join(ENV_DIR, 'trivy-cache', 'db'))) {
    info("First scan downloads Trivy's vulnerability database (~1 min, kept in .cg-env for later runs).");
  }
  spawnLogged(
    ['--max-old-space-size=150', 'dist/index.js'],
    {
      PORT: String(apiPort),
      HOST: '127.0.0.1',
      ROLE: 'all',
      LOG_LEVEL: process.env.LOG_LEVEL ?? 'info',
      DATABASE_PATH: path.join(ENV_DIR, 'data', 'code-guardian.db'),
      WORK_DIR: path.join(ENV_DIR, 'work'),
      TRIVY_BIN: trivy.bin,
      TRIVY_CACHE_DIR: path.join(ENV_DIR, 'trivy-cache'),
      MIN_FREE_DISK_MB: process.env.MIN_FREE_DISK_MB ?? '1024',
      NODE_OPTIONS: process.env.NODE_OPTIONS ?? '--max-semi-space-size=2',
    },
    ROOT,
    apiLog,
  );
  if (!(await waitHttp(`http://127.0.0.1:${String(apiPort)}/healthz`, 60))) {
    console.error(await tail(apiLog));
    stop(1);
    die('API did not start (log: .cg-env/logs/api.log)');
  }
  ok('API ready');

  step(`Starting web UI on :${String(webPort)}`);
  spawnLogged(
    [vite, 'preview', '--host', '127.0.0.1', '--port', String(webPort), '--strictPort'],
    { BACKEND_URL: `http://127.0.0.1:${String(apiPort)}` },
    path.join(ROOT, 'web'),
    webLog,
  );
  if (!(await waitHttp(`http://127.0.0.1:${String(webPort)}/`, 60))) {
    console.error(await tail(webLog));
    stop(1);
    die('web UI did not start (log: .cg-env/logs/web.log)');
  }
  ok('web UI ready');

  const api = `http://localhost:${String(apiPort)}`;
  console.log(`
  ${bold('Code Guardian is running')}
    Web UI     ${green(`http://localhost:${String(webPort)}`)}
    REST API   ${api}/api/scan
    GraphQL    ${api}/graphql   ${dim(`(GraphiQL: ${api}/graphiql)`)}
    Metrics    ${api}/metrics
    Logs       .cg-env/logs/api.log, .cg-env/logs/web.log

  Try:  curl -s -X POST ${api}/api/scan -H "content-type: application/json" -d "{\\"repoUrl\\":\\"https://github.com/armansw/NodeGoat\\"}"

  Press Ctrl-C to stop.`);
  await new Promise(() => undefined); // until a signal or a child exit stops us
}

function cmdDocker() {
  if (which('docker') === null) die('Docker is not installed. Run without arguments (no Docker needed), or install Docker Desktop / Docker Engine.');
  if (spawnSync('docker', ['compose', 'version'], { stdio: 'ignore' }).status !== 0) die('Docker Compose v2 is required (docker compose ...).');
  step(`Starting with docker compose (app mem_limit ${process.env.APP_MEM_LIMIT ?? '200m'}, Trivy server, web UI)`);
  info("UI http://localhost:8080 · API http://localhost:3000 · first start downloads Trivy's DB (~1 min)");
  run('docker', ['compose', 'up', '--build'], { cwd: ROOT });
}

async function cmdTest() {
  await bootstrap();
  for (const [label, dir] of [['Backend', ROOT], ['Web', path.join(ROOT, 'web')]]) {
    step(`${label}: lint, typecheck, tests with coverage`);
    for (const script of ['lint', 'typecheck', 'test:coverage']) run('npm', ['run', '--silent', script], { cwd: dir });
  }
  ok('all checks passed');
}

async function cmdOomCheck(sizeMb) {
  platform();
  await installDeps(ROOT, 'backend');
  step(`OOM check: ${sizeMb} MB report under --max-old-space-size=150`);
  run('npm', ['run', '--silent', 'build'], { cwd: ROOT });
  node(['--max-old-space-size=150', 'dist/scripts/oom-check.js', '--size-mb', sizeMb, '--dir', path.join(ENV_DIR, 'oom')], { cwd: ROOT });
}

function cmdDoctor() {
  const { os: o, arch } = platform();
  step(`Platform: ${o}/${arch}`);
  for (const t of ['git', 'tar', 'docker']) {
    const p = which(t);
    if (p) ok(`${t}: ${p}`);
    else warn(`${t}: not found${t === 'docker' ? ' (only needed for the docker command)' : ` (required; ${installHint([t])})`}`);
  }
  ok(`node: ${process.version} (${process.execPath.startsWith(TOOLS) ? '.cg-env' : 'system'})`);
  const system = which('trivy');
  const local = path.join(TOOLS, 'trivy', `trivy${EXE}`);
  if (system && trivyVersion(system)) ok(`trivy: ${String(trivyVersion(system))} (system)`);
  else if (existsSync(local)) ok(`trivy: ${String(trivyVersion(local))} (.cg-env)`);
  else warn(`trivy: not found; it will be installed locally (v${TRIVY_VERSION})`);
}

function cmdClean() {
  step('Removing .cg-env, dist/, web/dist/ and node_modules/');
  const runningFromLocalNode = process.execPath.startsWith(TOOLS);
  for (const p of [path.join(ENV_DIR, 'data'), path.join(ENV_DIR, 'work'), path.join(ENV_DIR, 'logs'), path.join(ENV_DIR, 'stamps'), path.join(ENV_DIR, 'trivy-cache'), path.join(ENV_DIR, 'oom'), path.join(TOOLS, 'trivy'), path.join(ROOT, 'dist'), path.join(ROOT, 'web', 'dist'), path.join(ROOT, 'node_modules'), path.join(ROOT, 'web', 'node_modules')]) {
    rmSync(p, { recursive: true, force: true, maxRetries: 3 });
  }
  // The Node that is running this script cannot delete itself on Windows; the launcher removes it afterwards.
  if (!runningFromLocalNode) rmSync(ENV_DIR, { recursive: true, force: true, maxRetries: 3 });
  ok('clean');
}

const USAGE = `Usage: ${WIN ? 'run.cmd' : './run.sh'} [command]

  start (default)   build and start the API + worker and the web UI (Ctrl-C stops everything)
  docker            same, with docker compose (200 MB container + Trivy server sidecar)
  test              lint, typecheck and test backend and frontend
  oom-check [MB]    a 600 MB report under --max-old-space-size=150
  doctor            show which tools were found or will be installed
  clean             remove the local toolchain, data and build output

Same commands on every OS: ./run.sh on Linux and macOS, run.cmd on Windows.`;

async function main() {
  const [cmd = 'start', arg] = process.argv.slice(2);
  switch (cmd) {
    case 'start':
      return cmdStart();
    case 'docker':
      return cmdDocker();
    case 'test':
      return cmdTest();
    case 'oom-check':
      return cmdOomCheck(arg ?? '600');
    case 'doctor':
      return cmdDoctor();
    case 'clean':
      return cmdClean();
    case 'help':
    case '-h':
    case '--help':
      console.log(USAGE);
      return undefined;
    default:
      console.log(USAGE);
      process.exitCode = 1;
      return undefined;
  }
}

main().catch((err) => {
  console.error(`${red('error:')} ${err instanceof Fatal ? err.message : String(err?.stack ?? err)}`);
  process.exit(1);
});
