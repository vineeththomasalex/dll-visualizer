import { useMemo, useRef, useState } from 'react';
import type { PEImage } from '../pe/types';
import { formatSize, hexBig } from '../pe/reader';
import { colorForSection } from '../pe/colors';

const ROW = 16;
const WINDOW = 512; // rows rendered around the scroll position

export function HexView({ pe }: { pe: PEImage }) {
  const [jump, setJump] = useState('');
  const [scrollTop, setScrollTop] = useState(0);
  const boxRef = useRef<HTMLDivElement>(null);
  const rowHeight = 18;
  const totalRows = Math.ceil(pe.fileSize / ROW);

  const regions = useMemo(
    () =>
      pe.fileRegions.map((r) => ({
        ...r,
        color:
          r.sectionIndex !== undefined ? colorForSection(pe.sections[r.sectionIndex]) : r.color,
      })),
    [pe],
  );

  const regionAt = (off: number) => regions.find((r) => off >= r.start && off < r.start + r.size);

  const first = Math.max(0, Math.floor(scrollTop / rowHeight) - 8);
  const last = Math.min(totalRows, first + WINDOW);

  const rows = [];
  for (let i = first; i < last; i++) {
    const off = i * ROW;
    const slice = pe.bytes.subarray(off, Math.min(off + ROW, pe.fileSize));
    const reg = regionAt(off);
    rows.push(
      <div className="hex-row" key={i} style={{ height: rowHeight }}>
        <span className="off" style={{ color: reg ? reg.color : undefined, opacity: 0.85 }}>
          {off.toString(16).toUpperCase().padStart(8, '0')}
        </span>
        <span className="bytes">
          {Array.from(slice).map((b, j) => (
            <span key={j} className={b ? 'nz' : 'z'}>
              {b.toString(16).toUpperCase().padStart(2, '0')}
              {j === 7 ? '  ' : ' '}
            </span>
          ))}
          {slice.length < ROW && '   '.repeat(ROW - slice.length)}
        </span>
        <span className="ascii">
          {Array.from(slice)
            .map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '·'))
            .join('')}
        </span>
      </div>,
    );
  }

  const go = (v: string) => {
    setJump(v);
    const n = parseInt(v.replace(/^0x/i, ''), 16);
    if (!Number.isNaN(n) && boxRef.current) {
      boxRef.current.scrollTop = Math.floor(n / ROW) * rowHeight;
    }
  };

  return (
    <>
      <h2 className="section-title">Raw bytes</h2>
      <p className="section-sub">
        The file exactly as stored, {formatSize(pe.fileSize)} of it. Offset colours match the file-layout map, so you can
        see at a glance which structure you have landed in.
      </p>
      <div className="toolbar">
        <label className="search" style={{ flex: '0 0 220px' }}>
          <span className="faint" style={{ fontSize: 12 }}>
            Go to
          </span>
          <input className="mono" value={jump} placeholder="0x1000" onChange={(e) => go(e.target.value)} />
        </label>
        {pe.sections.map((s) => (
          <button
            key={s.index}
            className="chip"
            onClick={() => go('0x' + s.rawPointer.toString(16))}
            style={{ borderColor: colorForSection(s) + '66' }}
          >
            <i className="swatch" style={{ background: colorForSection(s) }} />
            {s.name}
          </button>
        ))}
      </div>
      <div
        ref={boxRef}
        onScroll={(e) => setScrollTop((e.target as HTMLDivElement).scrollTop)}
        style={{
          height: 'calc(100vh - 250px)',
          overflow: 'auto',
          background: 'var(--bg-1)',
          border: '1px solid var(--line-soft)',
          borderRadius: 'var(--radius)',
          padding: '10px 14px',
        }}
      >
        <div style={{ height: totalRows * rowHeight, position: 'relative' }}>
          <div className="hex" style={{ position: 'absolute', top: first * rowHeight, left: 0, right: 0 }}>
            {rows}
          </div>
        </div>
      </div>
      <div className="faint" style={{ fontSize: 11.5, marginTop: 8 }}>
        Currently inside: <b className="mono">{regionAt(first * ROW)?.label ?? '—'}</b> · file offset{' '}
        {hexBig(first * ROW)}
      </div>
    </>
  );
}
