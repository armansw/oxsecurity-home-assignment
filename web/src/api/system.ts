import { API_BASE, fetchJson } from './http';
import { asObject, num, optNum, type JsonObject } from './guards';
import { errorFromEnvelope } from './http';

/** Live memory of the service, measured by the server (see GET /api/system/memory). */
export interface SystemMemory {
  readonly privateMb: number;
  readonly heapUsedMb: number;
  readonly heapLimitMb: number;
  /** The service's own cgroup (container / systemd unit); null where the server cannot read one. */
  readonly cgroup: { readonly limitMb: number | null; readonly currentMb: number; readonly peakMb: number | null } | null;
}

export function systemMemory(value: unknown): SystemMemory {
  const obj = asObject(value, 'memory');
  const cg: unknown = obj.cgroup;
  let cgroup: SystemMemory['cgroup'] = null;
  if (cg !== null && cg !== undefined) {
    const c: JsonObject = asObject(cg, 'cgroup');
    cgroup = { limitMb: optNum(c, 'limitMb'), currentMb: num(c, 'currentMb'), peakMb: optNum(c, 'peakMb') };
  }
  return { privateMb: num(obj, 'privateMb'), heapUsedMb: num(obj, 'heapUsedMb'), heapLimitMb: num(obj, 'heapLimitMb'), cgroup };
}

export async function fetchSystemMemory(signal?: AbortSignal): Promise<SystemMemory> {
  const res = await fetchJson(`${API_BASE}/api/system/memory`, signal ? { signal } : {});
  if (!res.ok) throw errorFromEnvelope(res.status, res.body);
  return systemMemory(res.body);
}
