export type RepoUrlResult = { readonly ok: true; readonly url: string } | { readonly ok: false; readonly reason: string };

const MAX_LENGTH = 2048;
const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPO_RE = /^[A-Za-z0-9._-]{1,100}$/;

/**
 * Validate and normalise a repository URL.
 *
 * The value reaches a process argument (`git clone … <url>`) and a network call, so it is the service's main
 * attack surface. Only `https://<allowed-host>/<owner>/<repo>[.git][/]` is accepted. This blocks:
 *  - other transports (`file://`, `ssh://`, `git://`, `ext::`) and option injection (`--upload-pack=…`);
 *  - SSRF to internal hosts (host allow-list, no ports, no IP literals unless explicitly allowed);
 *  - credentials, query strings, fragments, path traversal.
 *
 * Output form: `https://github.com/<owner>/<repo>.git` — what we store, clone and deduplicate on.
 */
export function normalizeRepoUrl(input: string, allowedHosts: readonly string[]): RepoUrlResult {
  const raw = input.trim();
  if (raw.length === 0) return fail('Repository URL is required');
  if (raw.length > MAX_LENGTH) return fail(`Repository URL must be at most ${MAX_LENGTH} characters`);
  if (/[\s\\]/.test(raw)) return fail('Repository URL must not contain whitespace or backslashes');

  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return fail('Repository URL is not a valid URL');
  }

  if (url.protocol !== 'https:') return fail('Only https:// repository URLs are supported');
  if (url.username !== '' || url.password !== '') return fail('Repository URL must not contain credentials');
  if (url.port !== '') return fail('Repository URL must not specify a port');
  if (url.search !== '' || url.hash !== '') return fail('Repository URL must not contain a query string or fragment');

  const host = url.hostname.toLowerCase();
  if (!allowedHosts.includes(host)) return fail(`Repository host must be one of: ${allowedHosts.join(', ')}`);

  // Reject traversal in the raw input: WHATWG URL parsing silently resolves `..` segments.
  if (/\/\.{1,2}(\/|$)/.test(raw.slice(raw.indexOf(host) + host.length))) return fail('Repository path must not contain . or .. segments');

  const segments = url.pathname.replace(/\/+$/, '').split('/').slice(1);
  if (segments.length !== 2) return fail('Repository URL must look like https://github.com/<owner>/<repo>');
  const [owner = '', repoSegment = ''] = segments;
  const repo = repoSegment.endsWith('.git') ? repoSegment.slice(0, -4) : repoSegment;

  if (!OWNER_RE.test(owner)) return fail('Repository owner is not valid');
  if (!REPO_RE.test(repo) || repo === '.' || repo === '..') return fail('Repository name is not valid');

  return { ok: true, url: `https://${host}/${owner}/${repo}.git` };
}

function fail(reason: string): RepoUrlResult {
  return { ok: false, reason };
}
