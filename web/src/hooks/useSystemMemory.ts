import { useEffect, useState } from 'react';
import type { SystemMemory } from '../api/system';

export const MEMORY_POLL_INTERVAL_MS = 5000;

/** Polls the service's live memory. Failures simply hide the panel: it is a proof, not a feature. */
export function useSystemMemory(load: (signal: AbortSignal) => Promise<SystemMemory>): SystemMemory | null {
  const [memory, setMemory] = useState<SystemMemory | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = (): void => {
      load(controller.signal)
        .then((m) => {
          setMemory(m);
        })
        .catch(() => {
          if (!controller.signal.aborted) setMemory(null);
        })
        .finally(() => {
          if (!controller.signal.aborted) timer = setTimeout(tick, MEMORY_POLL_INTERVAL_MS);
        });
    };
    tick();
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [load]);
  return memory;
}
