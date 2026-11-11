#!/usr/bin/env node
// Smoke test of the one-command launcher on a clean machine, the same on every OS (CI: Linux, macOS, Windows).
// Starts ./run.sh (run.cmd on Windows), runs a real scan through the UI's proxy, stops it, checks everything stopped.
//   CG_FORCE_LOCAL_TOOLS=1 node scripts/smoke-run.mjs      # also forces the Node/Trivy download path
import { spawn, spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const WIN = process.platform === 'win32';
const REPO = process.env.REPO ?? 'https://github.com/armansw/NodeGoat';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const child = WIN
  ? spawn('cmd.exe', ['/d', '/c', 'run.cmd'], { cwd: ROOT, env: process.env })
  : spawn('./run.sh', [], { cwd: ROOT, env: process.env, detached: true });
let log = '';
for (const s of [child.stdout, child.stderr]) {
  s.setEncoding('utf8');
  s.on('data', (d) => {
    log += d;
    process.stdout.write(d);
  });
}
let exited = false;
child.once('exit', () => {
  exited = true;
});

function stop() {
  if (exited) return;
  // Windows: end the whole tree (cmd → powershell → node → API, vite). Elsewhere SIGTERM, which run.sh/cg.mjs
  // handle exactly like Ctrl-C (background jobs of a non-interactive shell ignore SIGINT).
  if (WIN) spawnSync('taskkill', ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore' });
  else process.kill(-child.pid, 'SIGTERM');
}

function fail(msg) {
  console.error(`FAIL: ${msg}`);
  stop();
  process.exit(1);
}

async function http(url, init) {
  const res = await fetch(url, init);
  return { status: res.status, text: await res.text() };
}

const ANSI = new RegExp(String.fromCharCode(27) + '\\[[0-9;]*m', 'g');
const plain = () => log.replace(ANSI, '');
const deadline = Date.now() + 20 * 60_000;
while (!plain().includes('is running')) {
  if (exited) fail('the launcher exited during start-up');
  if (Date.now() > deadline) fail('the launcher did not become ready');
  await sleep(2000);
}
console.log('\nlauncher is up');

// The launcher moves to the next free port when one is busy; use the ports it printed.
const webPort = /Web UI +http:\/\/localhost:(\d+)/.exec(plain())?.[1];
const apiPort = /REST API +http:\/\/localhost:(\d+)/.exec(plain())?.[1];
if (!webPort || !apiPort) fail('could not read the ports');
const ui = `http://127.0.0.1:${webPort}`;

if (!(await http(`${ui}/`)).text.includes('<div id="root">')) fail('UI not served');
const started = await http(`${ui}/api/scan`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ repoUrl: REPO }) });
const scanId = /"scanId":"([^"]+)"/.exec(started.text)?.[1];
if (!scanId) fail(`scan not accepted: ${started.text}`);

let body = '';
let status = '';
for (let i = 0; i < 450 && status !== 'Finished' && status !== 'Failed'; i += 1) {
  body = (await http(`${ui}/api/scan/${scanId}?limit=1`)).text;
  status = /"status":"([A-Za-z]+)"/.exec(body)?.[1] ?? '';
  if (status !== 'Finished' && status !== 'Failed') await sleep(2000);
}
const critical = Number(/"criticalCount":(\d+)/.exec(body)?.[1] ?? 0);
console.log(`scan: status=${status} criticalCount=${String(critical)}`);
if (status !== 'Finished' || critical < 1) fail(`scan did not finish with criticals: ${body}`);

stop();
for (let i = 0; i < 30 && !exited; i += 1) await sleep(500);
await sleep(2000);
for (const url of [`http://127.0.0.1:${apiPort}/healthz`, `${ui}/`]) {
  try {
    await fetch(url);
    fail(`${url} still answers after stop`);
  } catch {
    // connection refused: stopped, as expected
  }
}
console.log('PASS: the launcher started, scanned, and stopped cleanly');
process.exit(0);
