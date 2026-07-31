import { useMemo, useState } from 'react';
import type { MemoryRegion, PEImage, PESection } from '../pe/types';
import { formatSize, hexBig } from '../pe/reader';
import { entropyColor } from '../pe/entropy';
import { PERM_COLOR } from '../pe/colors';
import { HoverCard } from './ui';
import { SECTION_TOPIC_HINTS } from '../knowledge/glossary';
import type { Symbol } from '../symbols/pdb';

export type Highlight = 'sections' | 'perms' | 'entropy' | 'dirs';
export type LayoutMode = 'virtual' | 'file';

const FILTERS: { id: string; label: string; test: (s: PESection) => boolean }[] = [
  { id: 'exec', label: 'Executable', test: (s) => (s.characteristics & 0x20000000) !== 0 },
  { id: 'write', label: 'Writable', test: (s) => (s.characteristics & 0x80000000) !== 0 },
  { id: 'ro', label: 'Read-only', test: (s) => (s.characteristics & 0x40000000) !== 0 && !(s.characteristics & 0x80000000) },
  { id: 'discard', label: 'Discardable', test: (s) => (s.characteristics & 0x02000000) !== 0 },
  { id: 'shared', label: 'Shared', test: (s) => (s.characteristics & 0x10000000) !== 0 },
  { id: 'bss', label: 'Zero-filled', test: (s) => (s.characteristics & 0x00000080) !== 0 || s.rawSize === 0 },
];

interface Props {
  pe: PEImage;
  symbols: Symbol[];
  layout: LayoutMode;
  setLayout: (l: LayoutMode) => void;
  highlight: Highlight;
  setHighlight: (h: Highlight) => void;
  selected: string | null;
  onSelect: (id: string | null, region: MemoryRegion | null) => void;
}

export function MemoryMap({ pe, symbols, layout, setLayout, highlight, setHighlight, selected, onSelect }: Props) {
  const [zoom, setZoom] = useState(1);
  const [filters, setFilters] = useState<string[]>([]);
  const [hover, setHover] = useState<MemoryRegion | null>(null);

  const all = layout === 'virtual' ? pe.memoryRegions : pe.fileRegions;
  const bands = useMemo(() => all.filter((r) => !r.parentId).sort((a, b) => a.start - b.start), [all]);
  const overlays = useMemo(() => all.filter((r) => r.parentId), [all]);

  const sectionOf = (r: MemoryRegion) => (r.sectionIndex !== undefined ? pe.sections[r.sectionIndex] : undefined);

  const colorFor = (r: MemoryRegion) => {
    if (r.kind === 'gap') return '#171a27';
    const s = sectionOf(r);
    if (highlight === 'perms') return s ? (PERM_COLOR[s.perms] ?? '#5a5f70') : '#7d8496';
    if (highlight === 'entropy') return s ? entropyColor(s.entropy) : '#3a4059';
    if (highlight === 'dirs') return r.kind === 'section' ? '#232838' : r.color;
    return r.color;
  };

  const dimmed = (r: MemoryRegion) => {
    if (!filters.length) return false;
    const s = sectionOf(r);
    if (!s) return true;
    return !filters.some((f) => FILTERS.find((x) => x.id === f)?.test(s));
  };

  const total = bands.reduce((a, b) => a + Math.max(b.size, 1), 0) || 1;
  // A gentle power curve keeps tiny sections visible without lying about big ones.
  const weight = (n: number) => Math.pow(Math.max(n, 1) / total, 0.62);
  const height = 560 * zoom;

  const selectedRegion = all.find((r) => r.id === selected) ?? null;

  return (
    <div className="mapview">
      <div className="map-pane">
        <div className="map-toolbar">
          <div className="segmented" role="tablist">
            <button className={layout === 'virtual' ? 'on' : ''} onClick={() => setLayout('virtual')} title="How the loader maps the image">
              Virtual layout
            </button>
            <button className={layout === 'file' ? 'on' : ''} onClick={() => setLayout('file')} title="How the bytes sit on disk">
              File layout
            </button>
          </div>
          <div className="segmented">
            {(
              [
                ['sections', 'Content'],
                ['perms', 'Perms'],
                ['entropy', 'Entropy'],
                ['dirs', 'Tables'],
              ] as [Highlight, string][]
            ).map(([id, label]) => (
              <button key={id} className={highlight === id ? 'on' : ''} onClick={() => setHighlight(id)}>
                {label}
              </button>
            ))}
          </div>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            <span className="faint" style={{ fontSize: 11 }}>
              Zoom
            </span>
            <input
              type="range"
              min={1}
              max={8}
              step={0.5}
              value={zoom}
              onChange={(e) => setZoom(Number(e.target.value))}
              style={{ flex: 1, accentColor: 'var(--accent)' }}
            />
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
            {FILTERS.map((f) => (
              <button
                key={f.id}
                className={'chip' + (filters.includes(f.id) ? ' on' : '')}
                style={{ height: 24, fontSize: 11, padding: '0 8px' }}
                onClick={() =>
                  setFilters((cur) => (cur.includes(f.id) ? cur.filter((x) => x !== f.id) : [...cur, f.id]))
                }
              >
                {f.label}
              </button>
            ))}
          </div>
        </div>

        <div className="map-scroll">
          <div className="map-row" style={{ height }}>
            <div className="addr-col" style={{ display: 'flex', flexDirection: 'column' }}>
              {bands.map((b) => (
                <div key={b.id} style={{ flex: `${weight(b.size)} 1 0`, minHeight: 14, position: 'relative' }}>
                  <span style={{ position: 'absolute', top: 0, right: 8 }}>
                    {layout === 'virtual' ? hexBig(pe.imageBase + b.start, pe.is64 ? 12 : 8) : hexBig(b.start)}
                  </span>
                </div>
              ))}
            </div>
            <div className="map-block">
              {bands.map((b) => {
                const kids = overlays.filter((o) => o.parentId === b.id);
                const isDim = dimmed(b);
                return (
                  <div
                    key={b.id}
                    className={
                      'band' +
                      (b.kind === 'gap' ? ' gap' : '') +
                      (isDim ? ' dimmed' : '') +
                      (selected === b.id ? ' selected' : '')
                    }
                    style={{ flex: `${weight(b.size)} 1 0`, minHeight: b.kind === 'gap' ? 8 : 16 }}
                    onMouseEnter={() => setHover(b)}
                    onMouseLeave={() => setHover((h) => (h === b ? null : h))}
                    onClick={() => onSelect(selected === b.id ? null : b.id, b)}
                  >
                    <div className="fill" style={{ background: colorFor(b) }} />
                    {kids.map((k) => {
                      const top = ((k.start - b.start) / Math.max(b.size, 1)) * 100;
                      const h = (k.size / Math.max(b.size, 1)) * 100;
                      if (top < -1 || top > 101) return null;
                      return (
                        <div
                          key={k.id}
                          className="dirmark"
                          style={{
                            top: `${Math.max(0, top)}%`,
                            height: `max(2px, ${Math.min(h, 100 - Math.max(0, top))}%)`,
                            background: `color-mix(in srgb, ${k.color} 70%, transparent)`,
                          }}
                          onMouseEnter={(e) => {
                            e.stopPropagation();
                            setHover(k);
                          }}
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelect(k.id, k);
                          }}
                        />
                      );
                    })}
                    <div className="label">
                      <span>{b.label}</span>
                      <span className="sz">{formatSize(b.size)}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        <div className="map-legend">
          {highlight === 'perms' &&
            Object.entries(PERM_COLOR).map(([k, v]) => (
              <span className="legend-item" key={k}>
                <i className="swatch" style={{ background: v }} /> {k}
              </span>
            ))}
          {highlight === 'entropy' && (
            <>
              <span className="legend-item">low</span>
              <i className="entropy-bar" />
              <span className="legend-item">high (packed / encrypted)</span>
            </>
          )}
          {(highlight === 'sections' || highlight === 'dirs') && (
            <>
              <span className="legend-item">
                <i className="swatch" style={{ background: '#5b8dd9' }} /> code
              </span>
              <span className="legend-item">
                <i className="swatch" style={{ background: '#4fb3a5' }} /> read-only data
              </span>
              <span className="legend-item">
                <i className="swatch" style={{ background: '#c9885f' }} /> writable data
              </span>
              <span className="legend-item">
                <i className="swatch" style={{ background: '#c96f9e' }} /> resources
              </span>
              <span className="legend-item">
                <i className="swatch" style={{ background: '#a8a35e' }} /> relocations
              </span>
              <span className="legend-item">striped = data directory</span>
            </>
          )}
        </div>
      </div>

      <div className="detail-pane">
        <RegionDetail pe={pe} region={selectedRegion} symbols={symbols} layout={layout} overlays={overlays} />
      </div>

      {hover && (
        <HoverCard>
          <div className="tt-title">
            <i className="swatch" style={{ background: colorFor(hover), width: 10, height: 10 }} />
            {hover.label}
          </div>
          <div className="tt-row">
            <span>{layout === 'virtual' ? 'RVA' : 'Offset'}</span>
            <span>{hexBig(hover.start)}</span>
          </div>
          {layout === 'virtual' && (
            <div className="tt-row">
              <span>VA</span>
              <span>{hexBig(pe.imageBase + hover.start, pe.is64 ? 12 : 8)}</span>
            </div>
          )}
          <div className="tt-row">
            <span>Size</span>
            <span>
              {formatSize(hover.size)} ({hexBig(hover.size)})
            </span>
          </div>
          {sectionOf(hover) && (
            <>
              <div className="tt-row">
                <span>Permissions</span>
                <span>{sectionOf(hover)!.perms}</span>
              </div>
              <div className="tt-row">
                <span>Entropy</span>
                <span>{sectionOf(hover)!.entropy.toFixed(2)} / 8</span>
              </div>
            </>
          )}
          {hover.detail && <div className="tt-desc">{hover.detail}</div>}
        </HoverCard>
      )}
    </div>
  );
}

function RegionDetail({
  pe,
  region,
  symbols,
  layout,
  overlays,
}: {
  pe: PEImage;
  region: MemoryRegion | null;
  symbols: Symbol[];
  layout: LayoutMode;
  overlays: MemoryRegion[];
}) {
  if (!region) {
    return (
      <>
        <h2 className="section-title">Image layout</h2>
        <p className="section-sub">
          This is {pe.fileName} as the Windows loader will see it — {formatSize(pe.sizeOfImage)} of address space split
          into {pe.sections.length} sections. Hover a band for a live readout, click one to pin it here.
        </p>
        <div className="stat-grid">
          <Kv k="Image base" v={hexBig(pe.imageBase, pe.is64 ? 12 : 8)} />
          <Kv k="Size of image" v={formatSize(pe.sizeOfImage)} />
          <Kv k="On disk" v={formatSize(pe.fileSize)} />
          <Kv k="Entry point" v={pe.entryPoint ? hexBig(pe.imageBase + pe.entryPoint, pe.is64 ? 12 : 8) : 'none'} />
          <Kv k="Section alignment" v={formatSize(pe.sectionAlignment)} />
          <Kv k="File alignment" v={formatSize(pe.fileAlignment)} />
        </div>
        <div className="panel">
          <header>Why the two layouts differ</header>
          <div className="body" style={{ fontSize: 13, lineHeight: 1.7, color: 'var(--text-dim)' }}>
            On disk, sections are packed to a 512-byte boundary to keep the file small. In memory they are spread to{' '}
            {formatSize(pe.sectionAlignment)} boundaries so that each one can carry its own page protection. That is why{' '}
            {formatSize(pe.fileSize)} of file expands into {formatSize(pe.sizeOfImage)} of address space — and why a file
            offset is almost never equal to an RVA.
          </div>
        </div>
      </>
    );
  }

  const s = region.sectionIndex !== undefined ? pe.sections[region.sectionIndex] : undefined;
  const inside = overlays.filter((o) => o.parentId === region.id);
  const symsHere = s
    ? symbols.filter((sym) => sym.rva >= s.virtualAddress && sym.rva < s.virtualAddress + Math.max(s.virtualSize, s.rawSize))
    : [];
  const topic = s ? SECTION_TOPIC_HINTS.find((t) => t.match.test(s.name))?.topic : undefined;
  void topic;

  return (
    <>
      <h2 className="section-title" style={{ fontFamily: 'var(--mono)' }}>
        {region.label}
      </h2>
      <p className="section-sub">{region.detail}</p>

      <div className="stat-grid">
        <Kv k={layout === 'virtual' ? 'RVA range' : 'File range'} v={`${hexBig(region.start)} – ${hexBig(region.start + region.size)}`} />
        {layout === 'virtual' && (
          <Kv
            k="Virtual address range"
            v={`${hexBig(pe.imageBase + region.start, pe.is64 ? 12 : 8)} – ${hexBig(pe.imageBase + region.start + region.size, pe.is64 ? 12 : 8)}`}
          />
        )}
        <Kv k="Size" v={`${formatSize(region.size)} (${hexBig(region.size)})`} />
        {s && <Kv k="Permissions" v={s.perms.replace(/-/g, '·')} />}
        {s && <Kv k="Entropy" v={`${s.entropy.toFixed(3)} / 8.0`} />}
        {s && <Kv k="Pages" v={String(Math.ceil(Math.max(s.virtualSize, 1) / 4096))} />}
      </div>

      {s && (
        <div className="panel">
          <header>
            Byte entropy across the section
            <span className="sub">each cell is {formatSize(Math.max(1, Math.floor(s.rawSize / 96)))}</span>
          </header>
          <div className="body">
            <div className="entropy-strip">
              {(s.entropyMap.length ? s.entropyMap : [0]).map((e, i) => (
                <i key={i} style={{ background: entropyColor(e) }} title={`${e.toFixed(2)} bits`} />
              ))}
            </div>
            <div className="entropy-legend">
              <span>0</span>
              <i className="entropy-bar" />
              <span>8 bits/byte</span>
              <span style={{ marginLeft: 'auto' }}>
                {s.entropy > 7.2
                  ? 'High — compressed or encrypted content'
                  : s.entropy > 5.8
                    ? 'Typical for compiled machine code'
                    : s.entropy > 3
                      ? 'Structured data, tables and strings'
                      : 'Very low — mostly padding or zeros'}
              </span>
            </div>
          </div>
        </div>
      )}

      {s && (
        <div className="panel">
          <header>Section header</header>
          <div className="body tight">
            <div className="fields">
              <Field n="Name" o={s.name} />
              <Field n="VirtualAddress" o={hexBig(s.virtualAddress)} d="Where the section starts once mapped, relative to the image base." />
              <Field n="VirtualSize" o={`${formatSize(s.virtualSize)} (${hexBig(s.virtualSize)})`} d="How many bytes it occupies in memory. Larger than the raw size when the tail is zero-filled." />
              <Field n="PointerToRawData" o={hexBig(s.rawPointer)} d="Where the bytes live in the file." />
              <Field n="SizeOfRawData" o={`${formatSize(s.rawSize)} (${hexBig(s.rawSize)})`} d="How many bytes are stored on disk, rounded up to FileAlignment." />
              <Field n="Characteristics" o={hexBig(s.characteristics)} d="The flag bits that become page protections." />
            </div>
            <div className="body">
              {s.flagNames.map((f) => (
                <span className="tag on" key={f}>
                  {f}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      {inside.length > 0 && (
        <div className="panel">
          <header>
            Data directories inside this region <span className="sub">{inside.length}</span>
          </header>
          <div className="body tight">
            <table className="grid">
              <thead>
                <tr>
                  <th>Table</th>
                  <th className="num">RVA</th>
                  <th className="num">Size</th>
                  <th>What it does</th>
                </tr>
              </thead>
              <tbody>
                {inside.map((d) => (
                  <tr key={d.id}>
                    <td>
                      <i className="swatch" style={{ background: d.color, display: 'inline-block', marginRight: 6 }} />
                      {d.label}
                    </td>
                    <td className="num">{hexBig(d.start)}</td>
                    <td className="num">{formatSize(d.size)}</td>
                    <td className="faint">{d.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {symsHere.length > 0 && (
        <div className="panel">
          <header>
            Symbols in this region <span className="sub">{symsHere.length.toLocaleString()}</span>
          </header>
          <div className="body tight">
            <table className="grid">
              <thead>
                <tr>
                  <th className="num">RVA</th>
                  <th>Symbol</th>
                  <th>Kind</th>
                </tr>
              </thead>
              <tbody>
                {symsHere.slice(0, 60).map((sym, i) => (
                  <tr key={i}>
                    <td className="num">{hexBig(sym.rva)}</td>
                    <td className="mono">{sym.pretty}</td>
                    <td className="faint">{sym.kind}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {symsHere.length > 60 && <div className="empty">…and {symsHere.length - 60} more. See the Symbols tab.</div>}
          </div>
        </div>
      )}
    </>
  );
}

function Kv({ k, v }: { k: string; v: string }) {
  return (
    <div className="stat">
      <div className="k">{k}</div>
      <div className="v sm">{v}</div>
    </div>
  );
}

function Field({ n, o, d }: { n: string; o: string; d?: string }) {
  return (
    <div className="field">
      <span className="fname">{n}</span>
      <span className="foff" />
      <span className="fval">{o}</span>
      {d && <span className="fdesc">{d}</span>}
    </div>
  );
}
