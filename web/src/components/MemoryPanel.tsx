import type { ReactElement } from 'react';
import type { SystemMemory } from '../api/system';
import { MemoryMeter } from './MemoryMeter';

/**
 * Live proof that the service fits its memory budget: everything charged to its container (page cache
 * included) against the container's real limit, with the peak since start. Falls back to the V8 heap
 * against --max-old-space-size where the server cannot read its cgroup (e.g. local dev without limits).
 */
export function MemoryPanel({ memory }: { readonly memory: SystemMemory }): ReactElement {
  const cg = memory.cgroup;
  return (
    <section className="memory" aria-label="Service memory">
      {cg !== null && cg.limitMb !== null ? (
        <MemoryMeter
          label="Service memory (live)"
          usedMb={memory.privateMb}
          backgroundMb={cg.currentMb}
          limitMb={cg.limitMb}
          {...(cg.peakMb === null ? {} : { markMb: cg.peakMb, markLabel: `Peak since start: ${String(cg.peakMb)} MB` })}
          note={`Private ${String(memory.privateMb)} MB · container total incl. page cache ${String(cg.currentMb)} MB${
            cg.peakMb === null ? '' : ` · peak ${String(cg.peakMb)} MB`
          } · hard limit ${String(cg.limitMb)} MB`}
        />
      ) : (
        <MemoryMeter
          label="Service heap (live)"
          usedMb={memory.heapUsedMb}
          limitMb={memory.heapLimitMb}
          note={`V8 heap against its --max-old-space-size ceiling · private memory ${String(memory.privateMb)} MB`}
        />
      )}
    </section>
  );
}
