import type { ReactElement } from 'react';

interface MemoryMeterProps {
  readonly label: string;
  /** Solid fill: the value being proven against the limit. */
  readonly usedMb: number;
  /** The limit the bar is drawn against (100 % width). */
  readonly limitMb: number;
  /** Optional lighter fill behind the solid one (e.g. total including page cache). */
  readonly backgroundMb?: number;
  /** Optional tick mark (e.g. the peak since start). */
  readonly markMb?: number;
  readonly markLabel?: string;
  readonly note?: string;
}

const pct = (value: number, limit: number): number => Math.max(0, Math.min(100, (value / limit) * 100));

/** A to-scale bar: what was used, against the real limit. Turns red above 90 %. */
export function MemoryMeter({ label, usedMb, limitMb, backgroundMb, markMb, markLabel, note }: MemoryMeterProps): ReactElement {
  const used = pct(usedMb, limitMb);
  const tight = Math.max(usedMb, backgroundMb ?? 0) / limitMb > 0.9;
  return (
    <div className="meter">
      <div className="meter__head">
        <span>{label}</span>
        <span className="meter__value">
          <strong>{usedMb} MB</strong> of {limitMb} MB
        </span>
      </div>
      <div
        className={`meter__track${tight ? ' meter__track--tight' : ''}`}
        role="meter"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={limitMb}
        aria-valuenow={usedMb}
        aria-valuetext={`${String(usedMb)} MB of ${String(limitMb)} MB`}
      >
        {backgroundMb !== undefined && <span className="meter__fill meter__fill--bg" style={{ width: `${String(pct(backgroundMb, limitMb))}%` }} />}
        <span className="meter__fill" style={{ width: `${String(used)}%` }} />
        {markMb !== undefined && (
          <span className="meter__mark" style={{ left: `${String(pct(markMb, limitMb))}%` }} title={markLabel ?? `${String(markMb)} MB`} />
        )}
      </div>
      {note !== undefined && <p className="meter__note">{note}</p>}
    </div>
  );
}
