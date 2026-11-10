import { ScanError } from '../../domain/errors.js';
import type { RepositoryFetcher } from '../../domain/ports.js';
import { CommandError, baseChildEnv, isNoSpaceMessage, runCommand } from '../process/run-command.js';

export interface GitFetcherOptions {
  readonly gitBin: string;
  readonly timeoutMs: number;
}

const NOT_FOUND_RE = /repository not found|not found|could not read username|authentication failed|terminal prompts disabled/i;

/** Shallow, hardened `git clone`. All git failures are classified here, where their meaning is known. */
export class GitRepositoryFetcher implements RepositoryFetcher {
  constructor(private readonly opts: GitFetcherOptions) {}

  async clone(repoUrl: string, destDir: string, signal: AbortSignal): Promise<void> {
    const args = [
      // Refuse local-file transport even via redirects/submodules; no credential helper prompts.
      '-c', 'protocol.file.allow=never',
      '-c', 'credential.helper=',
      'clone',
      '--depth', '1',
      '--single-branch',
      '--no-tags',
      '--no-recurse-submodules',
      // `--` ends option parsing: the URL can never be read as a flag, even though it is already validated.
      '--',
      repoUrl,
      destDir,
    ];

    try {
      await runCommand(this.opts.gitBin, {
        args,
        timeoutMs: this.opts.timeoutMs,
        signal,
        env: baseChildEnv({
          GIT_TERMINAL_PROMPT: '0', // private/missing repo fails fast instead of waiting for a password
          GIT_CONFIG_NOSYSTEM: '1',
          GIT_CONFIG_GLOBAL: '/dev/null',
          GIT_LFS_SKIP_SMUDGE: '1',
        }),
      });
    } catch (err) {
      throw classifyGitError(err);
    }
  }
}

export function classifyGitError(err: unknown): unknown {
  if (!(err instanceof CommandError)) return err;
  switch (err.kind) {
    case 'aborted':
      return err;
    case 'timeout':
      return new ScanError('CLONE_TIMEOUT', 'Cloning the repository timed out', true, { cause: err });
    case 'spawn':
      return new ScanError('INTERNAL', 'git is not available on this host', false, { cause: err });
    case 'exit':
      if (isNoSpaceMessage(err.stderrTail)) {
        return new ScanError('DISK_FULL', 'Ran out of disk space while cloning the repository', true, { cause: err });
      }
      if (NOT_FOUND_RE.test(err.stderrTail)) {
        return new ScanError('REPO_NOT_FOUND', 'Repository not found or not public', false, { cause: err });
      }
      return new ScanError('CLONE_FAILED', 'Cloning the repository failed', true, { cause: err });
  }
}
