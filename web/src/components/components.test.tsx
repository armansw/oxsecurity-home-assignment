import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { fakeApi, failed, finished, queued, scanning, vuln } from '../test/fixtures';
import { ScanForm, validateRepoUrl } from './ScanForm';
import { ScanResults } from './ScanResults';
import { statusLabel } from './StatusBadge';
import { TransportToggle } from './TransportToggle';

describe('statusLabel', () => {
  it.each([
    [queued(), 'Queued'],
    [scanning(), 'Scanning · scanning 40%'],
    [scanning({ phase: 'cloning', progressPct: null }), 'Scanning · cloning'],
    [scanning({ phase: null, progressPct: null }), 'Scanning'],
    [failed(), 'Failed · CLONE_FAILED: repository not found'],
    [finished(), 'Finished'],
  ])('renders %#', (scan, label) => {
    expect(statusLabel(scan)).toBe(label);
  });
});

describe('ScanForm', () => {
  it('validates the URL scheme on the client', () => {
    expect(validateRepoUrl('  ')).toMatch(/enter a repository url/i);
    expect(validateRepoUrl('http://github.com/a/b')).toMatch(/https:\/\//);
    expect(validateRepoUrl(' https://github.com/a/b ')).toBeNull();
  });

  it('submits a trimmed valid URL', async () => {
    const onSubmit = vi.fn();
    render(<ScanForm disabled={false} serverError={null} onSubmit={onSubmit} />);
    await userEvent.type(screen.getByLabelText('Repository URL'), '  https://github.com/a/b ');
    await userEvent.click(screen.getByRole('button', { name: 'Start' }));
    expect(onSubmit).toHaveBeenCalledWith('https://github.com/a/b');
  });

  it('shows the client error accessibly and clears it on edit', async () => {
    const onSubmit = vi.fn();
    render(<ScanForm disabled={false} serverError={null} onSubmit={onSubmit} />);
    const input = screen.getByLabelText('Repository URL');
    await userEvent.type(input, 'github.com/a/b{Enter}');
    expect(onSubmit).not.toHaveBeenCalled();
    expect(screen.getByRole('alert')).toHaveTextContent('must start with https://');
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(input).toHaveAccessibleDescription(/must start with https/);

    await userEvent.type(input, 'x');
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('shows a server error and honours disabled', () => {
    render(<ScanForm disabled serverError="repoUrl must be a GitHub URL" onSubmit={vi.fn()} />);
    expect(screen.getByRole('alert')).toHaveTextContent('repoUrl must be a GitHub URL');
    expect(screen.getByRole('button', { name: 'Start' })).toBeDisabled();
  });
});

describe('TransportToggle', () => {
  it('reports the chosen transport', async () => {
    const onChange = vi.fn();
    render(<TransportToggle value="rest" onChange={onChange} />);
    expect(screen.getByRole('radio', { name: 'REST' })).toBeChecked();
    await userEvent.click(screen.getByRole('radio', { name: 'GraphQL' }));
    expect(onChange).toHaveBeenCalledWith('graphql');
  });
});

describe('ScanResults', () => {
  it('renders the summary and the vulnerability table', () => {
    const page = {
      items: [vuln(), vuln({ id: 'CVE-2', primaryUrl: null, fixedVersion: null, installedVersion: null, cvssScore: null, title: null })],
      nextCursor: null,
    };
    render(<ScanResults api={fakeApi()} scan={finished(page)} />);

    expect(screen.getByText('Critical').nextElementSibling).toHaveTextContent('2');
    expect(screen.getByText('Report size').nextElementSibling).toHaveTextContent('1.5 MB');
    expect(screen.getByText('Vulnerabilities scanned').nextElementSibling).toHaveTextContent('1,234');
    expect(screen.getByText('Duration').nextElementSibling).toHaveTextContent('12.3 s');
    expect(screen.getByText('Worker peak RSS').nextElementSibling).toHaveTextContent('87 MB');

    const rows = within(screen.getByRole('table')).getAllByRole('row');
    expect(rows).toHaveLength(3);
    const link = within(rows[1]!).getByRole('link', { name: 'CVE-2024-0001' });
    expect(link).toHaveAttribute('href', 'https://avd.aquasec.com/nvd/cve-2024-0001');
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('rel', 'noopener noreferrer');
    expect(rows[1]).toHaveTextContent('4.17.20 → 4.17.21');
    expect(rows[1]).toHaveTextContent('9.8');
    expect(within(rows[2]!).queryByRole('link')).not.toBeInTheDocument();
    expect(rows[2]).toHaveTextContent('? → no fix');
    expect(screen.queryByRole('button', { name: 'Load more' })).not.toBeInTheDocument();
  });

  it('shows a friendly empty state for zero criticals', () => {
    render(<ScanResults api={fakeApi()} scan={finished({ items: [], nextCursor: null })} />);
    expect(screen.getByText(/no critical vulnerabilities found/i)).toBeInTheDocument();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });

  it('loads more pages on demand', async () => {
    const api = fakeApi();
    api.getScan.mockResolvedValue(finished({ items: [vuln({ id: 'CVE-NEXT' })], nextCursor: null }, 2));
    render(<ScanResults api={api} scan={finished({ items: [vuln()], nextCursor: 'cur' }, 2)} />);

    expect(screen.getByText('Showing 1 of 2')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Load more' }));
    expect(await screen.findByRole('link', { name: 'CVE-NEXT' })).toBeInTheDocument();
    expect(screen.getByText('Showing 2 of 2')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Load more' })).not.toBeInTheDocument();
  });

  it('reports a failed page load', async () => {
    const api = fakeApi();
    api.getScan.mockRejectedValue(new TypeError('Failed to fetch'));
    render(<ScanResults api={api} scan={finished({ items: [vuln()], nextCursor: 'cur' }, 2)} />);
    await userEvent.click(screen.getByRole('button', { name: 'Load more' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load more: Could not reach the server.');
  });
});
