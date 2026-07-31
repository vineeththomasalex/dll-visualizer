import { useCallback, useEffect, useMemo, useState } from 'react';
import type { PEImage } from '../pe/types';
import { formatSize, hexBig } from '../pe/reader';
import { disassemble, isArchSupported, type Instruction } from '../disasm/disasm';
import type { Symbol } from '../symbols/pdb';
import { Empty, Search } from './ui';

interface Entry {
  rva: number;
  label: string;
  source: string;
}

export function DisasmView({ pe, symbols }: { pe: PEImage; symbols: Symbol[] }) {
  const [target, setTarget] = useState<number | null>(null);
  const [insns, setInsns] = useState<Instruction[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState('');
  const [size, setSize] = useState(2048);

  const nameMap = useMemo(() => {
    const m = new Map<number, string>();
    pe.exports?.symbols.forEach((s) => {
      if (s.name) m.set(s.rva, s.name);
    });
    symbols.forEach((s) => m.set(s.rva, s.pretty));
    pe.imports.forEach((mod) =>
      mod.symbols.forEach((s) => m.set(s.iatRva, `${mod.dll.replace(/\.dll$/i, '')}!${s.name}`)),
    );
    return m;
  }, [pe, symbols]);

  const entries: Entry[] = useMemo(() => {
    const out: Entry[] = [];
    if (pe.entryPoint) out.push({ rva: pe.entryPoint, label: pe.isDll ? 'DllMain (entry point)' : 'Entry point', source: 'header' });
    pe.tls?.callbacks.forEach((c, i) =>
      out.push({ rva: Math.max(0, c - pe.imageBase), label: `TLS callback #${i}`, source: 'tls' }),
    );
    pe.exports?.symbols.forEach((s) => {
      if (!s.forwarder && s.rva) out.push({ rva: s.rva, label: s.name ?? `Ordinal #${s.ordinal}`, source: 'export' });
    });
    symbols
      .filter((s) => s.kind === 'function')
      .forEach((s) => out.push({ rva: s.rva, label: s.pretty, source: 'pdb' }));
    const seen = new Set<number>();
    return out.filter((e) => {
      if (seen.has(e.rva) || !e.rva) return false;
      seen.add(e.rva);
      return true;
    });
  }, [pe, symbols]);

  const run = useCallback(
    async (rva: number, bytes: number) => {
      setBusy(true);
      setError(null);
      try {
        const res = await disassemble(pe, rva, bytes, (t) => nameMap.get(t));
        setInsns(res);
        if (!res.length) setError('Nothing decodable at that address — it may be data rather than code.');
      } catch (e) {
        setError((e as Error).message);
      } finally {
        setBusy(false);
      }
    },
    [pe, nameMap],
  );

  useEffect(() => {
    const start = entries[0]?.rva;
    if (start !== undefined && target === null && isArchSupported(pe.machine)) {
      setTarget(start);
      void run(start, size);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [entries, pe.machine]);

  if (!isArchSupported(pe.machine)) {
    return <Empty>Disassembly is not available for {pe.machineName} images.</Empty>;
  }
  if (pe.isDotNet && !pe.sections.some((s) => s.characteristics & 0x20000000)) {
    return <Empty>This is a pure IL assembly — there is no native code to disassemble.</Empty>;
  }

  const needle = q.trim().toLowerCase();
  const shown = entries.filter((e) => !needle || e.label.toLowerCase().includes(needle)).slice(0, 400);
  const current = entries.find((e) => e.rva === target);

  return (
    <div style={{ display: 'flex', gap: 16, height: '100%', minHeight: 0 }}>
      <div style={{ flex: '0 0 300px', display: 'flex', flexDirection: 'column', minHeight: 0 }}>
        <div style={{ flex: '0 0 auto' }}>
          <Search value={q} onChange={setQ} placeholder="Find a function…" />
        </div>
        <div
          style={{
            marginTop: 10,
            flex: 1,
            overflow: 'auto',
            border: '1px solid var(--line-soft)',
            borderRadius: 'var(--radius)',
            background: 'var(--bg-1)',
          }}
        >
          {shown.map((e) => (
            <button
              key={e.rva}
              onClick={() => {
                setTarget(e.rva);
                void run(e.rva, size);
              }}
              style={{
                display: 'block',
                width: '100%',
                textAlign: 'left',
                padding: '6px 10px',
                fontSize: 12,
                fontFamily: 'var(--mono)',
                borderBottom: '1px solid var(--line-soft)',
                background: target === e.rva ? 'color-mix(in srgb, var(--accent) 15%, transparent)' : 'none',
                color: target === e.rva ? 'var(--accent)' : 'var(--text-dim)',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}
              title={e.label}
            >
              <span className="faint" style={{ fontSize: 10.5, marginRight: 7 }}>
                {hexBig(e.rva)}
              </span>
              {e.label}
            </button>
          ))}
          {!shown.length && <div className="empty">No entry points matched.</div>}
        </div>
      </div>

      <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
        <div className="toolbar" style={{ marginBottom: 10 }}>
          <h2 className="section-title" style={{ margin: 0, fontFamily: 'var(--mono)', fontSize: 15 }}>
            {current?.label ?? (target !== null ? hexBig(target) : 'Disassembly')}
          </h2>
          <span className="spacer" style={{ flex: 1 }} />
          <select
            className="mini"
            value={size}
            onChange={(e) => {
              const n = Number(e.target.value);
              setSize(n);
              if (target !== null) void run(target, n);
            }}
          >
            {[512, 2048, 8192, 32768].map((n) => (
              <option key={n} value={n}>
                {formatSize(n)} window
              </option>
            ))}
          </select>
          {busy && (
            <span className="loading">
              <i className="spinner" /> decoding…
            </span>
          )}
        </div>

        {error && <div className="banner warn">{error}</div>}

        <div
          style={{
            flex: 1,
            overflow: 'auto',
            background: 'var(--bg-1)',
            border: '1px solid var(--line-soft)',
            borderRadius: 'var(--radius)',
            padding: '10px 6px',
            minHeight: 0,
          }}
        >
          <div className="disasm">
            {insns.map((i, idx) => {
              const label = nameMap.get(i.rva);
              return (
                <div key={idx}>
                  {label && idx > 0 && <div className="sym-head">{label}</div>}
                  <div className={'ins ' + i.group}>
                    <span className="a">{hexBig(pe.imageBase + i.rva, pe.is64 ? 12 : 8)}</span>
                    <span className="b">
                      {Array.from(i.bytes)
                        .map((b) => b.toString(16).padStart(2, '0'))
                        .join(' ')}
                    </span>
                    <span className="m">{i.mnemonic}</span>
                    <span className="o">
                      {i.followable && i.target !== undefined ? (
                        <button
                          style={{ color: 'var(--accent)', padding: 0, font: 'inherit' }}
                          title="Follow this branch"
                          onClick={() => {
                            setTarget(i.target!);
                            void run(i.target!, size);
                          }}
                        >
                          {i.opStr}
                        </button>
                      ) : (
                        i.opStr
                      )}
                      {i.targetName && <em> ; {i.targetName}</em>}
                    </span>
                  </div>
                </div>
              );
            })}
            {!insns.length && !busy && !error && <div className="empty">Pick an entry point on the left.</div>}
          </div>
        </div>
      </div>
    </div>
  );
}
