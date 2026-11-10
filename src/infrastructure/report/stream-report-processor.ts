import fs from 'node:fs';
import { stat } from 'node:fs/promises';
import { pipeline } from 'node:stream/promises';
import { chain, flushable, none } from 'stream-chain';
import { jsonParser, type Token } from 'stream-json/parser.js';
import { ScanError } from '../../domain/errors.js';
import type { ReportProcessor, ReportStats, ScanStore } from '../../domain/ports.js';
import type { CriticalVulnerability } from '../../domain/vulnerability.js';
import { CriticalVulnerabilityExtractor } from './critical-vulnerability-extractor.js';
import { VulnerabilityBatchWriter } from './vulnerability-batch-writer.js';

export interface StreamReportProcessorOptions {
  readonly batchSize: number;
  /** Largest single JSON string/number the parser may buffer (bounds memory on hostile input). */
  readonly maxValueBytes: number;
  /** Read chunk size. 256 KiB keeps syscalls low while holding a trivial amount of memory. */
  readonly highWaterMark?: number;
  readonly progressIntervalMs?: number;
}

/**
 * The memory-critical path:
 *
 *   createReadStream (256 KiB chunks, utf8)
 *     → chain[ stream-json parser  →  CriticalVulnerabilityExtractor ]   (fused: plain function calls)
 *     → VulnerabilityBatchWriter (500-row transactions)
 *
 * `pipeline()` provides end-to-end backpressure, destroys every stage on error or abort, and rejects with the
 * first error. The parser and extractor are fused inside one stream-chain Duplex, so the ~tens of millions of
 * JSON tokens in a 500 MB report are passed by function call; only CRITICAL findings cross a stream boundary.
 *
 * At no point is the report — or the full result set — held in memory. There is no fs.readFile and no
 * JSON.parse anywhere in this path.
 */
export class StreamReportProcessor implements ReportProcessor {
  constructor(
    private readonly store: ScanStore,
    private readonly opts: StreamReportProcessorOptions,
  ) {}

  async process(input: Parameters<ReportProcessor['process']>[0]): Promise<ReportStats> {
    const { scanId, workerId, reportPath, signal, onProgress } = input;
    const reportBytes = await reportSize(reportPath);

    const source = fs.createReadStream(reportPath, {
      encoding: 'utf8',
      highWaterMark: this.opts.highWaterMark ?? 256 * 1024,
    });
    const extractor = new CriticalVulnerabilityExtractor();
    const writer = new VulnerabilityBatchWriter(this.store, scanId, workerId, this.opts.batchSize);

    const progress = setInterval(() => {
      onProgress(Math.min(99, Math.floor((100 * source.bytesRead) / reportBytes)));
    }, this.opts.progressIntervalMs ?? 1000);

    try {
      await pipeline(source, buildParseStage(extractor, this.opts.maxValueBytes), writer, { signal });
    } catch (err) {
      if (signal.aborted) throw signal.reason;
      throw err;
    } finally {
      clearInterval(progress);
    }

    return {
      reportBytes,
      vulnerabilitiesScanned: extractor.stats.scanned,
      criticalCount: writer.written,
      malformedSkipped: extractor.stats.malformed,
    };
  }
}

async function reportSize(reportPath: string): Promise<number> {
  try {
    const s = await stat(reportPath);
    if (!s.isFile() || s.size === 0) throw new ScanError('REPORT_INVALID', 'Trivy report is missing or empty');
    return s.size;
  } catch (err) {
    if (err instanceof ScanError) throw err;
    throw new ScanError('REPORT_INVALID', 'Trivy report is missing or unreadable', false, { cause: err });
  }
}

/**
 * Builds the fused text → CriticalVulnerability Duplex. Any parser failure (malformed or truncated JSON,
 * value over `maxValueBytes`, absurd nesting) is classified as REPORT_INVALID here, where its origin is known.
 */
export function buildParseStage(extractor: CriticalVulnerabilityExtractor, maxValueBytes: number): chain.ChainOutput<string, CriticalVulnerability> {
  // The synchronous core tokenizer (not the async-generator `parser()` wrapper): it returns each chunk's
  // tokens as one batch and throws synchronously, so the whole stage runs as plain function calls and parse
  // errors surface here, where they can be classified. UTF-8 boundaries are handled by the read stream's
  // `encoding: 'utf8'` decoder.
  const tokenize = jsonParser({
    packValues: true,
    streamValues: false,
    maxPackedLength: maxValueBytes,
    maxDepth: 64,
  });

  type TokenOutput = ReturnType<typeof tokenize>;
  // stream-chain flushes a Flushable by calling it with `none`; the typings only declare the data signature.
  const flushTokenizer = tokenize as (value: string | typeof none) => TokenOutput;

  const guardedTokenize = flushable(
    (text: string): TokenOutput => asReportInvalid(() => tokenize(text)),
    (): TokenOutput => asReportInvalid(() => flushTokenizer(none)),
  );

  const extract = flushable(
    (token: Token): CriticalVulnerability | typeof none => extractor.push(token) ?? none,
    (): typeof none => {
      extractor.end();
      return none;
    },
  );

  return chain([guardedTokenize, extract], { writableObjectMode: true, readableObjectMode: true });
}

function asReportInvalid<T>(fn: () => T): T {
  try {
    return fn();
  } catch (err) {
    if (err instanceof ScanError) throw err;
    const detail = err instanceof Error ? err.message : String(err);
    throw new ScanError('REPORT_INVALID', `Trivy report is not valid JSON: ${detail}`, false, { cause: err });
  }
}
