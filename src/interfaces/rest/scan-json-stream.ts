import { Readable } from 'node:stream';
import type { ScanStore } from '../../domain/ports.js';
import type { Scan } from '../../domain/scan.js';
import { toScanHeaderView, toVulnerabilityDto } from './scan.dto.js';

/**
 * Serialises a Finished scan — including ALL of its critical vulnerabilities — as a JSON byte stream.
 *
 * The egress side of the memory problem: building `{ …, criticalVulnerabilities: [...] }` and calling
 * JSON.stringify once would re-materialise the whole result set. Instead the generator emits the header, then
 * one keyset page at a time. `Readable.from` only pulls the next page when the socket has drained, so a slow
 * client holds at most one page in memory. Keyset paging (row_id > ?) keeps no SQLite cursor open between
 * pages, so the worker is never blocked by a slow reader.
 */
export function finishedScanJsonStream(scan: Scan, store: ScanStore, pageSize: number): Readable {
  function* chunks(): Generator<string> {
    const header = JSON.stringify(toScanHeaderView(scan));
    yield `${header.slice(0, -1)},"criticalVulnerabilities":[`;
    let afterRowId = 0;
    let first = true;
    for (;;) {
      const page = store.listVulnerabilities(scan.id, { afterRowId, limit: pageSize });
      const last = page.at(-1);
      if (last === undefined) break;
      yield (first ? '' : ',') + page.map((v) => JSON.stringify(toVulnerabilityDto(v))).join(',');
      first = false;
      afterRowId = last.rowId;
      if (page.length < pageSize) break;
    }
    yield ']}';
  }
  return Readable.from(chunks(), { objectMode: false });
}
