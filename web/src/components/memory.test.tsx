import { act, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { systemMemory, type SystemMemory } from '../api/system';
import { MEMORY_POLL_INTERVAL_MS, useSystemMemory } from '../hooks/useSystemMemory';
import { MemoryMeter } from './MemoryMeter';
import { MemoryPanel } from './MemoryPanel';

const withCgroup: SystemMemory = { privateMb: 58, heapUsedMb: 24, heapLimitMb: 198, cgroup: { limitMb: 150, currentMb: 67, peakMb: 96 } };

describe('MemoryMeter', () => {
  it('draws used and background fills to scale against the limit, with a peak mark', () => {
    const { container } = render(<MemoryMeter label="m" usedMb={30} backgroundMb={60} markMb={75} limitMb={150} note="n" />);
    const fills = container.querySelectorAll<HTMLElement>('.meter__fill');
    expect(fills[0]?.style.width).toBe('40%');
    expect(fills[1]?.style.width).toBe('20%');
    expect(container.querySelector<HTMLElement>('.meter__mark')?.style.left).toBe('50%');
    expect(screen.getByRole('meter')).toHaveAttribute('aria-valuetext', '30 MB of 150 MB');
    expect(container.querySelector('.meter__track--tight')).toBeNull();
    expect(screen.getByText('n')).toBeInTheDocument();
  });

  it('turns red above 90 % and clamps overflow', () => {
    const { container } = render(<MemoryMeter label="m" usedMb={200} limitMb={150} />);
    expect(container.querySelector('.meter__track--tight')).not.toBeNull();
    expect(container.querySelector<HTMLElement>('.meter__fill')?.style.width).toBe('100%');
  });
});

describe('MemoryPanel', () => {
  it('shows the container total and peak against the hard limit', () => {
    render(<MemoryPanel memory={withCgroup} />);
    expect(screen.getByRole('meter', { name: 'Service memory (live)' })).toHaveAttribute('aria-valuemax', '150');
    expect(screen.getByText('Private 58 MB · container total incl. page cache 67 MB · peak 96 MB · hard limit 150 MB')).toBeInTheDocument();
  });

  it('omits the peak when the kernel does not report one', () => {
    render(<MemoryPanel memory={{ ...withCgroup, cgroup: { limitMb: 150, currentMb: 67, peakMb: null } }} />);
    expect(screen.getByText('Private 58 MB · container total incl. page cache 67 MB · hard limit 150 MB')).toBeInTheDocument();
  });

  it('falls back to the V8 heap when there is no cgroup limit', () => {
    render(<MemoryPanel memory={{ ...withCgroup, cgroup: { limitMb: null, currentMb: 10, peakMb: null } }} />);
    expect(screen.getByRole('meter', { name: 'Service heap (live)' })).toHaveAttribute('aria-valuetext', '24 MB of 198 MB');
  });
});

describe('systemMemory guard', () => {
  it('parses with and without a cgroup, and rejects malformed bodies', () => {
    expect(systemMemory(withCgroup)).toEqual(withCgroup);
    expect(systemMemory({ ...withCgroup, cgroup: null }).cgroup).toBeNull();
    expect(() => systemMemory({ privateMb: 'x' })).toThrow();
    expect(() => systemMemory({ ...withCgroup, cgroup: { currentMb: 'x' } })).toThrow();
  });
});

describe('useSystemMemory', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  function Probe({ load }: { load: (s: AbortSignal) => Promise<SystemMemory> }) {
    const m = useSystemMemory(load);
    return <span>{m === null ? 'none' : String(m.privateMb)}</span>;
  }

  it('polls, clears on failure, and stops on unmount', async () => {
    vi.useFakeTimers();
    const load = vi
      .fn<(s: AbortSignal) => Promise<SystemMemory>>()
      .mockResolvedValueOnce(withCgroup)
      .mockRejectedValueOnce(new Error('down'))
      .mockResolvedValue({ ...withCgroup, privateMb: 61 });
    const { unmount } = render(<Probe load={load} />);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(screen.getByText('58')).toBeInTheDocument();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(MEMORY_POLL_INTERVAL_MS);
    });
    expect(screen.getByText('none')).toBeInTheDocument();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(MEMORY_POLL_INTERVAL_MS);
    });
    expect(screen.getByText('61')).toBeInTheDocument();
    unmount();
    const calls = load.mock.calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(MEMORY_POLL_INTERVAL_MS * 3);
    });
    expect(load.mock.calls.length).toBe(calls);
  });
});
