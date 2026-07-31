import { useMemo, useRef, useState } from 'react';
import type { PEImage } from '../pe/types';
import { diffPE, signedSize, type ChangeKind, type FieldDiff, type PEDiff } from '../pe/diff';
import { formatSize, hexBig } from '../pe/reader';
import { colorForSection } from '../pe/colors';
import { entropyColor } from '../pe/entropy';
import { Empty, Panel, Search } from './ui';

const KIND_COLOR: Record<ChangeKind, string> = {
  same: '#4a5169',
  changed: '#e0a34a',
  added: '#5fc98a',
  removed: '#ef6f6c',
};

const KIND_LABEL: Record<ChangeKind, string> = {
  same: 'unchanged',
  changed: 'changed',
  added: 'added',
  removed: 'removed',
};

export function CompareView({
  pe,
  other,
  onPick,
  onClear,
  onSwap,
  busy,
}: {
  pe: PEImage;
  other: PEImage | null;
  onPick: (files: File[]) => void;
  onClear: () => void;
  onSwap: () => void;
  busy: boolean;
}) {
  const input = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);
  const diff = useMemo(() => (other ? diffPE(pe, other) : null), [pe, other]);

  if (!diff) {
    return (
      <>
        <h2 className="section-title">Compare with another build</h2>
        <p className="section-sub">
          Add a second copy of this DLL — an older release, a patched build, a different flavour — and see exactly what
          moved: layout, sections, dependencies, exported API, resources, and the security flags. Both files stay in your
          browser.
        </p>
        <div
          className={'dropzone' + (over ? ' over' : '')}
          style={{ width: '100%', maxWidth: 720, padding: '40px 28px' }}
          onDragOver={(e) => {
            e.preventDefault();
            setOver(true);
          }}
          onDragLeave={() => setOver(false)}
          onDrop={(e) => {
            e.preventDefault();
            setOver(false);
            onPick(Array.from(e.dataTransfer.files));
          }}
          onClick={() => input.current?.click()}
        >
          <div className="big">{busy ? 'Parsing…' : `Drop the other version of ${pe.fileName}`}</div>
          <div className="sub">or click to browse · it does not have to have the same name</div>
          <input
            ref={input}
            type="file"
            hidden
            accept=".dll,.exe,.sys,.ocx,.cpl,.drv,.efi,.node"
            onChange={(e) => onPick(Array.from(e.target.files ?? []))}
          />
        </div>
        <div className="features" style={{ marginTop: 22, width: '100%', maxWidth: 980 }}>
          <div className="feature">
            <b>Layout drift</b>
            <span>Both images drawn to the same byte scale, with matched sections joined so you can see what grew.</span>
          </div>
          <div className="feature">
            <b>Byte-level similarity</b>
            <span>Every matched section compared block by block to show how much really changed.</span>
          </div>
          <div className="feature">
            <b>API &amp; dependency churn</b>
            <span>Exports added, removed or relocated; imported modules and functions gained and dropped.</span>
          </div>
          <div className="feature">
            <b>Regression flags</b>
            <span>Mitigations that were switched off between builds are called out explicitly.</span>
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      <div className="cmp-head">
        <span className="file-chip">
          <i className="dot" />
          <b>{diff.a.fileName}</b>
          <span>A · {formatSize(diff.a.fileSize)}</span>
        </span>
        <span className="cmp-arrow">→</span>
        <span className="file-chip pdb">
          <i className="dot" />
          <b>{diff.b.fileName}</b>
          <span>B · {formatSize(diff.b.fileSize)}</span>
        </span>
        <span style={{ flex: 1 }} />
        <button className="btn" onClick={onSwap} title="Swap which image is the baseline">
          ⇄ Swap
        </button>
        <button className="btn" onClick={() => input.current?.click()}>
          Replace B
        </button>
        <button className="btn" onClick={onClear}>
          Clear
        </button>
        <input
          ref={input}
          type="file"
          hidden
          accept=".dll,.exe,.sys,.ocx,.cpl,.drv,.efi,.node"
          onChange={(e) => onPick(Array.from(e.target.files ?? []))}
        />
      </div>

      <div className={'banner ' + (diff.counts.mitigationsChanged || diff.counts.exportsRemoved ? 'warn' : 'info')}>
        <span>{diff.counts.mitigationsChanged || diff.counts.exportsRemoved ? '⚠' : '≡'}</span>
        <div>
          {diff.headline.map((h, i) => (
            <div key={i} style={{ marginBottom: i === diff.headline.length - 1 ? 0 : 5 }}>
              {h}
            </div>
          ))}
        </div>
      </div>

      <Scoreboard diff={diff} />
      <LayoutRibbon diff={diff} />
      <SectionDeltas diff={diff} />
      <EntropyComparison diff={diff} />
      <MetaTables diff={diff} />
      <MitigationDiff diff={diff} />
      <DirectoryDiffTable diff={diff} />
      <ImportDiffPanel diff={diff} />
      <ExportDiffPanel diff={diff} />
      <ResourceDiffPanel diff={diff} />
    </>
  );
}

/* ------------------------------------------------------------------ scoreboard */
function Scoreboard({ diff }: { diff: PEDiff }) {
  const entropyDelta = diff.b.entropy - diff.a.entropy;
  const cards: { k: string; v: string; delta?: number; deltaText?: string }[] = [
    { k: 'File size', v: formatSize(diff.b.fileSize), delta: diff.b.fileSize - diff.a.fileSize, deltaText: signedSize(diff.b.fileSize - diff.a.fileSize) },
    { k: 'Mapped image', v: formatSize(diff.b.sizeOfImage), delta: diff.b.sizeOfImage - diff.a.sizeOfImage, deltaText: signedSize(diff.b.sizeOfImage - diff.a.sizeOfImage) },
    { k: 'Sections', v: String(diff.b.sections.length), delta: diff.b.sections.length - diff.a.sections.length },
    {
      k: 'Imported functions',
      v: String(diff.b.imports.reduce((n, m) => n + m.symbols.length, 0)),
      delta:
        diff.b.imports.reduce((n, m) => n + m.symbols.length, 0) -
        diff.a.imports.reduce((n, m) => n + m.symbols.length, 0),
    },
    {
      k: 'Exports',
      v: String(diff.b.exports?.symbols.length ?? 0),
      delta: (diff.b.exports?.symbols.length ?? 0) - (diff.a.exports?.symbols.length ?? 0),
    },
    { k: 'Resources', v: String(diff.b.resourceCount), delta: diff.b.resourceCount - diff.a.resourceCount },
    { k: 'Relocations', v: diff.b.relocCount.toLocaleString(), delta: diff.b.relocCount - diff.a.relocCount },
    {
      k: 'Entropy',
      v: diff.b.entropy.toFixed(3),
      delta: Math.abs(entropyDelta) < 0.0005 ? 0 : entropyDelta,
      deltaText: (entropyDelta > 0 ? '+' : '') + entropyDelta.toFixed(3),
    },
  ];

  return (
    <>
      <div className="stat-grid">
        {cards.map((c) => (
          <div className="stat" key={c.k}>
            <div className="k">{c.k}</div>
            <div className="v sm">
              {c.v}
              {!!c.delta && (
                <span className="delta" style={{ color: c.delta > 0 ? 'var(--ok)' : 'var(--danger)' }}>
                  {c.deltaText ?? (c.delta > 0 ? '+' : '') + c.delta}
                </span>
              )}
            </div>
          </div>
        ))}
      </div>

      <Panel
        title="Byte-level similarity"
        sub="matched sections compared in 512-byte blocks"
        right={<b className="mono">{(diff.similarity * 100).toFixed(1)}%</b>}
      >
        <div className="bar" style={{ height: 12 }}>
          <i
            style={{
              width: `${Math.max(1, diff.similarity * 100)}%`,
              background: 'linear-gradient(90deg, var(--accent), var(--accent-2))',
            }}
          />
        </div>
        <div className="faint" style={{ fontSize: 12, marginTop: 8, lineHeight: 1.6 }}>
          {diff.similarity > 0.98
            ? 'Nearly everything is identical — this looks like a targeted patch or a rebuild with only metadata churn.'
            : diff.similarity > 0.7
              ? 'A substantial common core with localised changes: typical of a service update.'
              : diff.similarity > 0.2
                ? 'Large parts of the image were rewritten — a feature release or a compiler change.'
                : 'Almost nothing lines up. Either the code was rebuilt with different settings, or these are not really the same component.'}
        </div>
      </Panel>
    </>
  );
}

/* ------------------------------------------------------------------ layout ribbon */
function LayoutRibbon({ diff }: { diff: PEDiff }) {
  const H = 520;
  const CONNECT = 96;
  const maxImage = Math.max(diff.a.sizeOfImage, diff.b.sizeOfImage) || 1;
  const scale = H / maxImage;
  const y = (n: number) => n * scale;
  const h = (n: number) => Math.max(2.5, n * scale);

  const column = (pe: PEImage, side: 'a' | 'b') => (
    <div className="ribbon" style={{ height: H }}>
      <div
        className="rband"
        style={{ top: 0, height: h(pe.sizeOfHeaders), background: '#8b8fa3' }}
        title={`Headers · ${formatSize(pe.sizeOfHeaders)}`}
      />
      {pe.sections.map((s) => {
        const d = diff.sections.find((x) => x.name === s.name);
        const kind = d?.kind ?? 'same';
        const height = h(s.virtualSize || s.rawSize);
        return (
          <div
            key={s.index}
            className={'rband k-' + kind}
            style={{
              top: y(s.virtualAddress),
              height,
              background: colorForSection(s),
              outline: kind === 'same' ? 'none' : `1.5px solid ${KIND_COLOR[kind]}`,
            }}
            title={`${s.name} · ${formatSize(s.virtualSize)} · ${s.perms} · ${KIND_LABEL[kind]}`}
          >
            {height >= 13 && <span className="rlabel">{s.name}</span>}
          </div>
        );
      })}
      <span className="rcap">{side === 'a' ? 'A' : 'B'} · {formatSize(pe.sizeOfImage)}</span>
    </div>
  );

  return (
    <Panel
      title="Layout drift"
      sub={`both images at the same scale — 1 px ≈ ${formatSize(Math.round(1 / scale))}`}
      right={
        <span style={{ display: 'flex', gap: 10, fontSize: 11 }}>
          {(['same', 'changed', 'added', 'removed'] as ChangeKind[]).map((k) => (
            <span className="legend-item" key={k}>
              <i className="swatch" style={{ background: KIND_COLOR[k] }} /> {KIND_LABEL[k]}
            </span>
          ))}
        </span>
      }
    >
      <div className="ribbon-row">
        {column(diff.a, 'a')}
        <svg width={CONNECT} height={H} className="connectors" preserveAspectRatio="none">
          {diff.sections.map((s) => {
            if (!s.a || !s.b) return null;
            const y1 = y(s.a.virtualAddress);
            const y2 = y1 + h(s.a.virtualSize || s.a.rawSize);
            const y3 = y(s.b.virtualAddress);
            const y4 = y3 + h(s.b.virtualSize || s.b.rawSize);
            return (
              <path
                key={s.name}
                d={`M0,${y1} C${CONNECT * 0.5},${y1} ${CONNECT * 0.5},${y3} ${CONNECT},${y3} L${CONNECT},${y4} C${CONNECT * 0.5},${y4} ${CONNECT * 0.5},${y2} 0,${y2} Z`}
                fill={colorForSection(s.a)}
                fillOpacity={s.kind === 'same' ? 0.22 : 0.4}
                stroke={s.kind === 'same' ? 'none' : KIND_COLOR[s.kind]}
                strokeOpacity={0.75}
                strokeWidth={s.kind === 'same' ? 0 : 1}
              >
                <title>{`${s.name}: ${s.virtualDelta === 0 ? 'unchanged size' : `${signedSize(s.virtualDelta)} virtual`}`}</title>
              </path>
            );
          })}
        </svg>
        {column(diff.b, 'b')}
        <div className="ribbon-notes">
          <h4>Reading this</h4>
          <p>
            Both columns use one shared byte scale, so a taller column really is a bigger image. Ribbons join sections
            that exist in both builds — a ribbon that fans out or pinches in is a section that grew or shrank, and a slope
            means everything after it shifted to a new address.
          </p>
          <ul>
            {diff.sections
              .filter((s) => s.kind !== 'same')
              .slice(0, 8)
              .map((s) => (
                <li key={s.name}>
                  <b className="mono" style={{ color: KIND_COLOR[s.kind] }}>
                    {s.name}
                  </b>{' '}
                  {s.kind === 'added'
                    ? `is new (${formatSize(s.b!.virtualSize)})`
                    : s.kind === 'removed'
                      ? `is gone (was ${formatSize(s.a!.virtualSize)})`
                      : `${s.virtualDelta === 0 ? 'kept its size' : `${signedSize(s.virtualDelta)} virtual`}${s.movedVa ? ', and moved' : ''}`}
                </li>
              ))}
            {diff.sections.every((s) => s.kind === 'same') && <li>Every section kept its exact size and address.</li>}
          </ul>
        </div>
      </div>
    </Panel>
  );
}

/* ------------------------------------------------------------------ section deltas */
function SectionDeltas({ diff }: { diff: PEDiff }) {
  const max = Math.max(1, ...diff.sections.map((s) => Math.abs(s.virtualDelta)));
  return (
    <Panel title="Section-by-section" sub="virtual size change, entropy shift and how much of the content is identical" tight>
      <table className="grid">
        <thead>
          <tr>
            <th>Section</th>
            <th>Status</th>
            <th className="num">A</th>
            <th className="num">B</th>
            <th style={{ width: 220 }}>Change</th>
            <th className="num">Delta</th>
            <th style={{ width: 150 }}>Identical bytes</th>
            <th className="num">Entropy</th>
            <th>Flags</th>
          </tr>
        </thead>
        <tbody>
          {diff.sections.map((s) => (
            <tr key={s.name}>
              <td className="mono">{s.name}</td>
              <td>
                <span className="tag" style={{ color: KIND_COLOR[s.kind], borderColor: KIND_COLOR[s.kind] + '66' }}>
                  {KIND_LABEL[s.kind]}
                </span>
              </td>
              <td className="num">{s.a ? formatSize(s.a.virtualSize) : '—'}</td>
              <td className="num">{s.b ? formatSize(s.b.virtualSize) : '—'}</td>
              <td>
                <div className="diverge">
                  <span className="mid" />
                  {s.virtualDelta !== 0 && (
                    <i
                      style={{
                        left: s.virtualDelta < 0 ? `${50 - (Math.abs(s.virtualDelta) / max) * 50}%` : '50%',
                        width: `${(Math.abs(s.virtualDelta) / max) * 50}%`,
                        background: s.virtualDelta > 0 ? 'var(--ok)' : 'var(--danger)',
                      }}
                    />
                  )}
                </div>
              </td>
              <td className="num" style={{ color: s.virtualDelta > 0 ? 'var(--ok)' : s.virtualDelta < 0 ? 'var(--danger)' : undefined }}>
                {s.virtualDelta === 0 ? '±0' : signedSize(s.virtualDelta)}
              </td>
              <td>
                {s.similarity === null ? (
                  <span className="faint">—</span>
                ) : (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <div className="bar" style={{ flex: 1 }}>
                      <i
                        style={{
                          width: `${s.similarity * 100}%`,
                          background: s.similarity > 0.9 ? 'var(--ok)' : s.similarity > 0.5 ? 'var(--warn)' : 'var(--danger)',
                        }}
                      />
                    </div>
                    <span className="mono faint" style={{ fontSize: 11 }}>
                      {Math.round(s.similarity * 100)}%
                    </span>
                  </div>
                )}
              </td>
              <td className="num faint">
                {s.a && s.b ? (Math.abs(s.entropyDelta) < 0.001 ? '±0' : (s.entropyDelta > 0 ? '+' : '') + s.entropyDelta.toFixed(3)) : '—'}
              </td>
              <td>
                {s.permsChanged && <span className="tag bad">{s.a?.perms} → {s.b?.perms}</span>}
                {s.flagsChanged && !s.permsChanged && <span className="tag warn">characteristics</span>}
                {s.movedVa && <span className="tag">moved</span>}
                {!s.permsChanged && !s.flagsChanged && !s.movedVa && <span className="faint">—</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Panel>
  );
}

/* ------------------------------------------------------------------ entropy */
function EntropyComparison({ diff }: { diff: PEDiff }) {
  const rows = diff.sections.filter((s) => s.a && s.b && s.kind === 'changed');
  if (!rows.length) return null;
  return (
    <Panel title="Where inside each section the bytes changed" sub="entropy profile, A above B">
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        {rows.map((s) => (
          <div key={s.name}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6, fontSize: 12 }}>
              <b className="mono">{s.name}</b>
              <span className="faint">
                {formatSize(s.a!.rawSize)} → {formatSize(s.b!.rawSize)} on disk
              </span>
            </div>
            <div className="entropy-strip" style={{ height: 16, borderRadius: '4px 4px 0 0' }}>
              {(s.a!.entropyMap.length ? s.a!.entropyMap : [0]).map((e, i) => (
                <i key={i} style={{ background: entropyColor(e) }} />
              ))}
            </div>
            <div className="entropy-strip" style={{ height: 16, borderRadius: '0 0 4px 4px', borderTop: 'none' }}>
              {(s.b!.entropyMap.length ? s.b!.entropyMap : [0]).map((e, i) => (
                <i key={i} style={{ background: entropyColor(e) }} />
              ))}
            </div>
          </div>
        ))}
      </div>
    </Panel>
  );
}

/* ------------------------------------------------------------------ metadata tables */
function DiffRows({ fields }: { fields: FieldDiff[] }) {
  if (!fields.length) return <Empty>Nothing to compare here.</Empty>;
  return (
    <table className="grid" style={{ tableLayout: 'fixed' }}>
      <colgroup>
        <col style={{ width: '26%' }} />
        <col style={{ width: '31%' }} />
        <col style={{ width: '31%' }} />
        <col style={{ width: '12%' }} />
      </colgroup>
      <thead>
        <tr>
          <th>Field</th>
          <th>A</th>
          <th>B</th>
          <th style={{ width: 120 }} className="num">
            Change
          </th>
        </tr>
      </thead>
      <tbody>
        {fields.map((f) => (
          <tr key={f.name} className={f.changed ? 'row-changed' : undefined}>
            <td>
              {f.name}
              {f.note && f.changed && <div className="faint" style={{ fontSize: 11.5, marginTop: 3 }}>{f.note}</div>}
            </td>
            <td className="mono" style={{ color: f.changed ? 'var(--danger)' : undefined, wordBreak: 'break-all' }}>
              {f.a}
            </td>
            <td className="mono" style={{ color: f.changed ? 'var(--ok)' : undefined, wordBreak: 'break-all' }}>
              {f.b}
            </td>
            <td className="num faint">
              {f.delta !== undefined && f.delta !== 0 ? signedSize(f.delta) : f.changed ? 'changed' : '—'}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function MetaTables({ diff }: { diff: PEDiff }) {
  const [showAll, setShowAll] = useState(false);
  const pick = (rows: FieldDiff[]) => (showAll ? rows : rows.filter((r) => r.changed));
  const groups: [string, string, FieldDiff[]][] = [
    ['Identity', 'what kind of binary this is', diff.identity],
    ['Layout', 'sizes and addresses', diff.layout],
    ['Build provenance', 'toolchain and debug identity', diff.build],
    ['Version resource', 'the strings Explorer shows', diff.versionInfo],
  ];
  return (
    <Panel
      title="Metadata"
      sub={showAll ? 'every field' : 'only fields that differ'}
      right={
        <button className="btn" onClick={() => setShowAll((v) => !v)}>
          {showAll ? 'Only changes' : 'Show all fields'}
        </button>
      }
      tight
    >
      {groups.map(([title, sub, rows]) => {
        const shown = pick(rows);
        if (!shown.length) return null;
        return (
          <div key={title}>
            <div className="group-head" style={{ cursor: 'default' }}>
              <b>{title}</b>
              <span className="faint">{sub}</span>
              <span className="spacer" />
              <span className="faint">{rows.filter((r) => r.changed).length} of {rows.length} changed</span>
            </div>
            <DiffRows fields={shown} />
          </div>
        );
      })}
      {!groups.some(([, , rows]) => pick(rows).length) && <Empty>Every metadata field is identical.</Empty>}
    </Panel>
  );
}

/* ------------------------------------------------------------------ mitigations */
function MitigationDiff({ diff }: { diff: PEDiff }) {
  const changed = diff.mitigations.filter((m) => m.a !== m.b);
  return (
    <Panel
      title="Security mitigations"
      sub={changed.length ? `${changed.length} changed` : 'no change'}
      right={changed.some((m) => m.a && !m.b) ? <span className="tag bad">regression</span> : undefined}
    >
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
        {diff.mitigations.map((m) => {
          const state = m.a === m.b ? (m.a ? 'on' : 'off') : m.b ? 'gained' : 'lost';
          if (state === 'off') return null;
          return (
            <span
              key={m.name}
              className={'tag ' + (state === 'gained' ? 'good' : state === 'lost' ? 'bad' : '')}
              title={m.desc}
            >
              {state === 'gained' ? '+ ' : state === 'lost' ? '− ' : ''}
              {m.name}
            </span>
          );
        })}
      </div>
      {changed.length > 0 && (
        <div style={{ marginTop: 12, fontSize: 12.5, lineHeight: 1.6, color: 'var(--text-dim)' }}>
          {changed.map((m) => (
            <div key={m.name} style={{ marginBottom: 5 }}>
              <b className="mono" style={{ color: m.b ? 'var(--ok)' : 'var(--danger)' }}>
                {m.b ? 'Enabled' : 'Disabled'} {m.name}
              </b>{' '}
              — {m.desc}
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

/* ------------------------------------------------------------------ directories */
function DirectoryDiffTable({ diff }: { diff: PEDiff }) {
  const rows = diff.directories.filter((d) => d.kind !== 'same');
  if (!rows.length) return null;
  return (
    <Panel title="Data directories that moved or resized" tight>
      <table className="grid">
        <thead>
          <tr>
            <th>Directory</th>
            <th>Status</th>
            <th className="num">A RVA</th>
            <th className="num">A size</th>
            <th className="num">B RVA</th>
            <th className="num">B size</th>
            <th className="num">Delta</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((d) => (
            <tr key={d.index}>
              <td>{d.name}</td>
              <td>
                <span className="tag" style={{ color: KIND_COLOR[d.kind], borderColor: KIND_COLOR[d.kind] + '66' }}>
                  {KIND_LABEL[d.kind]}
                </span>
              </td>
              <td className="num faint">{d.aRva ? hexBig(d.aRva) : '—'}</td>
              <td className="num">{d.aSize ? formatSize(d.aSize) : '—'}</td>
              <td className="num faint">{d.bRva ? hexBig(d.bRva) : '—'}</td>
              <td className="num">{d.bSize ? formatSize(d.bSize) : '—'}</td>
              <td className="num" style={{ color: d.bSize > d.aSize ? 'var(--ok)' : d.bSize < d.aSize ? 'var(--danger)' : undefined }}>
                {d.bSize === d.aSize ? '±0' : signedSize(d.bSize - d.aSize)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Panel>
  );
}

/* ------------------------------------------------------------------ imports */
function ImportDiffPanel({ diff }: { diff: PEDiff }) {
  const [q, setQ] = useState('');
  const [open, setOpen] = useState<string[]>([]);
  const [onlyChanged, setOnlyChanged] = useState(true);
  const needle = q.trim().toLowerCase();

  const rows = diff.imports.filter((m) => {
    if (onlyChanged && m.kind === 'same') return false;
    if (!needle) return true;
    return (
      m.dll.toLowerCase().includes(needle) ||
      m.added.some((n) => n.toLowerCase().includes(needle)) ||
      m.removed.some((n) => n.toLowerCase().includes(needle))
    );
  });

  const maxChurn = Math.max(1, ...diff.imports.map((m) => m.added.length + m.removed.length));

  return (
    <Panel
      title="Dependencies"
      sub={`${diff.counts.modulesAdded} modules added · ${diff.counts.modulesRemoved} removed · ${diff.counts.functionsAdded} functions gained · ${diff.counts.functionsRemoved} dropped`}
      tight
    >
      <div className="body" style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <Search value={q} onChange={setQ} placeholder="Filter modules or functions…" />
        <button className={'chip' + (onlyChanged ? ' on' : '')} onClick={() => setOnlyChanged((v) => !v)}>
          Only changed
        </button>
        <span className="faint" style={{ fontSize: 12 }}>
          {rows.length} of {diff.imports.length} modules
        </span>
      </div>
      {!rows.length && <Empty>No dependency changed between these builds.</Empty>}
      {rows.map((m) => {
        const isOpen = open.includes(m.dll) || !!needle;
        const churn = m.added.length + m.removed.length;
        return (
          <div key={m.dll + m.kind}>
            <div
              className="group-head"
              onClick={() => setOpen((o) => (o.includes(m.dll) ? o.filter((x) => x !== m.dll) : [...o, m.dll]))}
            >
              <span className="caret">{isOpen ? '▼' : '▶'}</span>
              <b style={{ color: m.kind === 'added' ? KIND_COLOR.added : m.kind === 'removed' ? KIND_COLOR.removed : undefined }}>
                {m.dll}
              </b>
              <span className="tag" style={{ color: KIND_COLOR[m.kind], borderColor: KIND_COLOR[m.kind] + '66' }}>
                {KIND_LABEL[m.kind]}
              </span>
              {m.delayLoaded && <span className="tag warn">delay</span>}
              <span className="spacer" />
              <div className="churn" title={`${m.added.length} added, ${m.removed.length} removed`}>
                <i style={{ width: `${(m.removed.length / maxChurn) * 100}%`, background: 'var(--danger)' }} />
                <i style={{ width: `${(m.added.length / maxChurn) * 100}%`, background: 'var(--ok)' }} />
              </div>
              <span className="faint mono" style={{ fontSize: 11, minWidth: 74, textAlign: 'right' }}>
                {m.added.length ? `+${m.added.length}` : ''} {m.removed.length ? `−${m.removed.length}` : ''}
                {!churn ? `${m.commonCount} same` : ''}
              </span>
            </div>
            {isOpen && churn > 0 && (
              <div className="body split" style={{ gap: 14 }}>
                <div>
                  <div className="faint" style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>
                    Added in B ({m.added.length})
                  </div>
                  {m.added.length ? (
                    m.added.map((n) => (
                      <div key={n} className="mono difflineadd">
                        + {n}
                      </div>
                    ))
                  ) : (
                    <span className="faint" style={{ fontSize: 12 }}>none</span>
                  )}
                </div>
                <div>
                  <div className="faint" style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>
                    Removed from A ({m.removed.length})
                  </div>
                  {m.removed.length ? (
                    m.removed.map((n) => (
                      <div key={n} className="mono difflinedel">
                        − {n}
                      </div>
                    ))
                  ) : (
                    <span className="faint" style={{ fontSize: 12 }}>none</span>
                  )}
                </div>
              </div>
            )}
          </div>
        );
      })}
    </Panel>
  );
}

/* ------------------------------------------------------------------ exports */
function ExportDiffPanel({ diff }: { diff: PEDiff }) {
  const e = diff.exports;
  const total = e.added.length + e.removed.length + e.moved.length + e.ordinalChanged.length + e.forwarderChanged.length;
  if (!diff.a.exports && !diff.b.exports) return null;

  const stacked = [
    { label: 'unchanged', n: e.unchanged, color: '#4a5169' },
    { label: 'relocated', n: e.moved.length, color: '#e0a34a' },
    { label: 'added', n: e.added.length, color: KIND_COLOR.added },
    { label: 'removed', n: e.removed.length, color: KIND_COLOR.removed },
  ];
  const sum = stacked.reduce((a, s) => a + s.n, 0) || 1;

  return (
    <Panel title="Exported API" sub={total ? `${total} entries changed` : 'identical'}>
      <div className="stackbar">
        {stacked.map((s) => (
          <i key={s.label} style={{ width: `${(s.n / sum) * 100}%`, background: s.color }} title={`${s.label}: ${s.n}`} />
        ))}
      </div>
      <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', marginTop: 8, fontSize: 11.5 }}>
        {stacked.map((s) => (
          <span className="legend-item" key={s.label}>
            <i className="swatch" style={{ background: s.color }} /> {s.label} · {s.n.toLocaleString()}
          </span>
        ))}
      </div>

      {e.removed.length > 0 && (
        <div className="banner err" style={{ marginTop: 14 }}>
          <span>✕</span>
          <div>
            {e.removed.length} exported {e.removed.length === 1 ? 'symbol was' : 'symbols were'} removed. Anything linked
            against {diff.a.fileName} that imports them will fail to load against B.
          </div>
        </div>
      )}

      <div className="split" style={{ marginTop: 14 }}>
        <ExportList title={`Added in B (${e.added.length})`} names={e.added.map((s) => s.name ?? `#${s.ordinal}`)} tone="add" />
        <ExportList title={`Removed from A (${e.removed.length})`} names={e.removed.map((s) => s.name ?? `#${s.ordinal}`)} tone="del" />
      </div>

      {e.forwarderChanged.length > 0 && (
        <div style={{ marginTop: 14 }}>
          <div className="faint" style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>
            Forwarder changes ({e.forwarderChanged.length})
          </div>
          {e.forwarderChanged.slice(0, 40).map((c) => (
            <div key={c.name} className="mono" style={{ fontSize: 12, padding: '2px 0' }}>
              {c.name}: <span style={{ color: 'var(--danger)' }}>{c.a ?? '(direct)'}</span> →{' '}
              <span style={{ color: 'var(--ok)' }}>{c.b ?? '(direct)'}</span>
            </div>
          ))}
        </div>
      )}

      {e.ordinalChanged.length > 0 && (
        <div className="banner warn" style={{ marginTop: 14 }}>
          <span>⚠</span>
          <div>
            {e.ordinalChanged.length} export{e.ordinalChanged.length === 1 ? '' : 's'} changed ordinal. Callers that bind
            by ordinal instead of by name will silently reach the wrong function.
          </div>
        </div>
      )}

      {e.moved.length > 0 && (
        <div className="faint" style={{ fontSize: 12.5, marginTop: 12, lineHeight: 1.6 }}>
          {e.moved.length.toLocaleString()} exports kept their name and ordinal but moved to a new RVA — normal whenever
          code above them changes size.
        </div>
      )}
    </Panel>
  );
}

function ExportList({ title, names, tone }: { title: string; names: string[]; tone: 'add' | 'del' }) {
  const [expanded, setExpanded] = useState(false);
  const shown = expanded ? names : names.slice(0, 25);
  return (
    <div>
      <div className="faint" style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>
        {title}
      </div>
      {!names.length && <span className="faint" style={{ fontSize: 12 }}>none</span>}
      {shown.map((n) => (
        <div key={n} className={'mono ' + (tone === 'add' ? 'difflineadd' : 'difflinedel')}>
          {tone === 'add' ? '+' : '−'} {n}
        </div>
      ))}
      {names.length > shown.length && (
        <button className="btn" style={{ marginTop: 8 }} onClick={() => setExpanded(true)}>
          Show all {names.length}
        </button>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ resources */
function ResourceDiffPanel({ diff }: { diff: PEDiff }) {
  const rows = diff.resources.filter((r) => r.kind !== 'same');
  if (!diff.a.resources && !diff.b.resources) return null;
  return (
    <Panel
      title="Resources"
      sub={
        rows.length
          ? `${diff.counts.resourcesAdded} added · ${diff.counts.resourcesRemoved} removed · ${diff.counts.resourcesChanged} resized`
          : 'identical'
      }
      tight
    >
      {!rows.length && <Empty>Every resource leaf is the same size in both builds.</Empty>}
      {rows.length > 0 && (
        <table className="grid">
          <thead>
            <tr>
              <th>Resource</th>
              <th>Status</th>
              <th className="num">A</th>
              <th className="num">B</th>
              <th className="num">Delta</th>
            </tr>
          </thead>
          <tbody>
            {rows.slice(0, 200).map((r) => (
              <tr key={r.path}>
                <td className="mono">{r.path}</td>
                <td>
                  <span className="tag" style={{ color: KIND_COLOR[r.kind], borderColor: KIND_COLOR[r.kind] + '66' }}>
                    {KIND_LABEL[r.kind]}
                  </span>
                </td>
                <td className="num">{r.aSize !== undefined ? formatSize(r.aSize) : '—'}</td>
                <td className="num">{r.bSize !== undefined ? formatSize(r.bSize) : '—'}</td>
                <td className="num faint">
                  {r.aSize !== undefined && r.bSize !== undefined ? signedSize(r.bSize - r.aSize) : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}
