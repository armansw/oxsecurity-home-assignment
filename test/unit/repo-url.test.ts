import { describe, expect, it } from 'vitest';
import { normalizeRepoUrl } from '../../src/infrastructure/git/repo-url.js';

const hosts = ['github.com'];
const ok = (input: string) => normalizeRepoUrl(input, hosts);

describe('normalizeRepoUrl', () => {
  it.each([
    ['https://github.com/OWASP/NodeGoat', 'https://github.com/OWASP/NodeGoat.git'],
    ['https://github.com/OWASP/NodeGoat.git', 'https://github.com/OWASP/NodeGoat.git'],
    ['https://github.com/OWASP/NodeGoat/', 'https://github.com/OWASP/NodeGoat.git'],
    ['  https://GitHub.com/OWASP/NodeGoat  ', 'https://github.com/OWASP/NodeGoat.git'],
    ['https://github.com/a-b/c.d_e-f', 'https://github.com/a-b/c.d_e-f.git'],
  ])('accepts and normalises %s', (input, expected) => {
    expect(ok(input)).toEqual({ ok: true, url: expected });
  });

  it.each([
    ['', 'required'],
    ['not a url', 'whitespace'],
    ['github.com/OWASP/NodeGoat', 'not a valid URL'],
    ['http://github.com/OWASP/NodeGoat', 'https://'],
    ['ssh://git@github.com/OWASP/NodeGoat', 'https://'],
    ['git://github.com/OWASP/NodeGoat', 'https://'],
    ['file:///etc/passwd', 'https://'],
    ['git@github.com:OWASP/NodeGoat.git', 'not a valid URL'],
    ['https://user:pass@github.com/OWASP/NodeGoat', 'credentials'],
    ['https://token@github.com/OWASP/NodeGoat', 'credentials'],
    ['https://github.com:8443/OWASP/NodeGoat', 'port'],
    ['https://github.com/OWASP/NodeGoat?x=1', 'query'],
    ['https://github.com/OWASP/NodeGoat#main', 'query'],
    ['https://gitlab.com/OWASP/NodeGoat', 'host'],
    ['https://169.254.169.254/latest/meta-data', 'host'],
    ['https://localhost/OWASP/NodeGoat', 'host'],
    ['https://github.com.evil.com/OWASP/NodeGoat', 'host'],
    ['https://github.com/OWASP/../etc/passwd', 'segments'],
    ['https://github.com/OWASP/./NodeGoat', 'segments'],
    ['https://github.com/OWASP', 'look like'],
    ['https://github.com/OWASP/NodeGoat/tree/main', 'look like'],
    ['https://github.com/-bad/NodeGoat', 'owner'],
    ['https://github.com/OWASP/--upload-pack=touch%20x', 'name'],
    ['https://github.com/OWASP/NodeGoat;rm', 'name'],
    ['https://github.com/OWASP/$(id)', 'name'],
    ['https://github.com/OWASP/Node Goat', 'whitespace'],
    ['https://github.com\\OWASP\\NodeGoat', 'backslashes'],
    [`https://github.com/OWASP/${'a'.repeat(2100)}`, 'at most'],
  ])('rejects %s', (input, reasonFragment) => {
    const result = ok(input);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason.toLowerCase()).toContain(reasonFragment.toLowerCase());
  });

  it('honours a custom host allow-list', () => {
    expect(normalizeRepoUrl('https://gitlab.com/group/project', ['gitlab.com'])).toEqual({
      ok: true,
      url: 'https://gitlab.com/group/project.git',
    });
  });
});
