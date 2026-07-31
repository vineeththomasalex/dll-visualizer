import { useMemo, useState } from 'react';
import type { ImportModule, PEImage, ResourceNode } from '../pe/types';
import { formatSize, hexBig } from '../pe/reader';
import { Empty, Panel, Search } from './ui';
import type { PdbInfo, Symbol } from '../symbols/pdb';
import { RESOURCE_TYPE } from '../pe/constants';

/* ------------------------------------------------------------------ imports */
export function Imports({ pe }: { pe: PEImage }) {
  const [q, setQ] = useState('');
  const [openDlls, setOpenDlls] = useState<string[]>(() => pe.imports.slice(0, 3).map((m) => m.dll));
  const [groupBy, setGroupBy] = useState<'dll' | 'category'>('dll');

  const needle = q.trim().toLowerCase();
  const filtered = useMemo(() => {
    if (!needle) return pe.imports;
    return pe.imports
      .map((m) => ({
        ...m,
        symbols: m.dll.toLowerCase().includes(needle)
          ? m.symbols
          : m.symbols.filter((s) => s.name.toLowerCase().includes(needle)),
      }))
      .filter((m) => m.symbols.length || m.dll.toLowerCase().includes(needle));
  }, [pe.imports, needle]);

  const total = pe.imports.reduce((a, m) => a + m.symbols.length, 0);
  if (!pe.imports.length) return <Empty>This image imports nothing — unusual, but valid for pure resource DLLs.</Empty>;

  const byCategory = new Map<string, ImportModule[]>();
  filtered.forEach((m) => {
    const k = m.category;
    byCategory.set(k, [...(byCategory.get(k) ?? []), m]);
  });

  return (
    <>
      <h2 className="section-title">Imports</h2>
      <p className="section-sub">
        {total.toLocaleString()} functions from {pe.imports.length} modules. Each entry has a slot in the Import Address
        Table which the loader overwrites with the real function pointer — that is what an indirect call goes through.
      </p>

      <div className="toolbar">
        <Search value={q} onChange={setQ} placeholder="Filter by DLL or function name…  (press /)" />
        <div className="segmented" style={{ height: 32 }}>
          <button className={groupBy === 'dll' ? 'on' : ''} onClick={() => setGroupBy('dll')}>
            By module
          </button>
          <button className={groupBy === 'category' ? 'on' : ''} onClick={() => setGroupBy('category')}>
            By purpose
          </button>
        </div>
        <span className="faint" style={{ fontSize: 12 }}>
          {filtered.reduce((a, m) => a + m.symbols.length, 0).toLocaleString()} shown
        </span>
      </div>

      {groupBy === 'category' && (
        <div className="stat-grid">
          {[...byCategory.entries()]
            .sort((a, b) => b[1].length - a[1].length)
            .map(([cat, mods]) => (
              <div className="stat" key={cat}>
                <div className="k">{cat}</div>
                <div className="v sm">{mods.reduce((a, m) => a + m.symbols.length, 0)} functions</div>
                <div className="faint" style={{ fontSize: 11, marginTop: 5, lineHeight: 1.5 }}>
                  {mods.map((m) => m.dll).join(', ')}
                </div>
              </div>
            ))}
        </div>
      )}

      {filtered.map((m) => {
        const isOpen = openDlls.includes(m.dll) || !!needle;
        const apiGroups = new Map<string, number>();
        m.symbols.forEach((s) => apiGroups.set(s.category, (apiGroups.get(s.category) ?? 0) + 1));
        return (
          <section className="panel" key={m.dll + m.descriptorRva + String(m.delayLoaded)}>
            <div
              className="group-head"
              onClick={() => setOpenDlls((o) => (o.includes(m.dll) ? o.filter((x) => x !== m.dll) : [...o, m.dll]))}
            >
              <span className="caret">{isOpen ? '▼' : '▶'}</span>
              <b>{m.dll}</b>
              <span className="tag">{m.category}</span>
              {m.delayLoaded && <span className="tag warn">delay-loaded</span>}
              {m.symbols.some((s) => s.byOrdinal) && <span className="tag">has ordinal imports</span>}
              <span className="spacer" />
              <span className="faint">{m.symbols.length} functions</span>
            </div>
            {isOpen && (
              <>
                <div className="body" style={{ paddingBottom: 8 }}>
                  {[...apiGroups.entries()]
                    .sort((a, b) => b[1] - a[1])
                    .map(([g, n]) => (
                      <span className="tag" key={g}>
                        {g} · {n}
                      </span>
                    ))}
                  <div className="faint" style={{ fontSize: 11.5, marginTop: 8, fontFamily: 'var(--mono)' }}>
                    INT {hexBig(m.originalFirstThunk)} → IAT {hexBig(m.firstThunk)}
                    {m.timeDateStamp ? ` · bound ${new Date(m.timeDateStamp * 1000).toISOString().slice(0, 10)}` : ''}
                  </div>
                </div>
                <table className="grid">
                  <thead>
                    <tr>
                      <th className="num">IAT slot</th>
                      <th className="num">Hint</th>
                      <th>Function</th>
                      <th>Purpose</th>
                    </tr>
                  </thead>
                  <tbody>
                    {m.symbols.map((s, i) => (
                      <tr key={i}>
                        <td className="num faint">{hexBig(s.iatRva)}</td>
                        <td className="num faint">{s.hint ?? (s.byOrdinal ? `#${s.ordinal}` : '—')}</td>
                        <td className="mono">{s.name}</td>
                        <td className="faint">{s.category}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
          </section>
        );
      })}
    </>
  );
}

/* ------------------------------------------------------------------ exports */
export function Exports({ pe, symbols }: { pe: PEImage; symbols: Symbol[] }) {
  const [q, setQ] = useState('');
  const [onlyForwarders, setOnlyForwarders] = useState(false);
  const e = pe.exports;
  if (!e) return <Empty>This image exports nothing. Without an export table nothing can bind to it by name.</Empty>;

  const needle = q.trim().toLowerCase();
  const rows = e.symbols.filter((s) => {
    if (onlyForwarders && !s.forwarder) return false;
    if (!needle) return true;
    return (s.name ?? '').toLowerCase().includes(needle) || String(s.ordinal).includes(needle);
  });
  const forwarders = e.symbols.filter((s) => s.forwarder).length;

  return (
    <>
      <h2 className="section-title">Exports</h2>
      <p className="section-sub">
        {e.dllName} publishes {e.numberOfFunctions.toLocaleString()} functions, {e.numberOfNames.toLocaleString()} of them
        by name. GetProcAddress binary-searches the sorted name array, so ordinal-only exports are effectively private.
        {forwarders > 0 && ` ${forwarders} of these are forwarders that redirect the caller to another module.`}
      </p>

      <div className="stat-grid">
        <div className="stat">
          <div className="k">Ordinal base</div>
          <div className="v sm">{e.ordinalBase}</div>
        </div>
        <div className="stat">
          <div className="k">Address table</div>
          <div className="v sm">{hexBig(e.addressTableRva)}</div>
        </div>
        <div className="stat">
          <div className="k">Name pointers</div>
          <div className="v sm">{hexBig(e.namePointerRva)}</div>
        </div>
        <div className="stat">
          <div className="k">Ordinal table</div>
          <div className="v sm">{hexBig(e.ordinalTableRva)}</div>
        </div>
      </div>

      <div className="toolbar">
        <Search value={q} onChange={setQ} placeholder="Filter exports…  (press /)" />
        <button className={'chip' + (onlyForwarders ? ' on' : '')} onClick={() => setOnlyForwarders((v) => !v)}>
          Forwarders only
        </button>
        <span className="faint" style={{ fontSize: 12 }}>
          {rows.length.toLocaleString()} shown
        </span>
      </div>

      <Panel title="Exported symbols" tight>
        <table className="grid">
          <thead>
            <tr>
              <th className="num">Ordinal</th>
              <th className="num">RVA</th>
              <th>Name</th>
              <th>Section</th>
              <th>Notes</th>
            </tr>
          </thead>
          <tbody>
            {rows.slice(0, 4000).map((s) => {
              const sym = symbols.find((x) => x.rva === s.rva);
              return (
                <tr key={s.ordinal}>
                  <td className="num">{s.ordinal}</td>
                  <td className="num">{hexBig(s.rva)}</td>
                  <td className="mono">{s.name ?? <span className="faint">(by ordinal only)</span>}</td>
                  <td className="mono faint">{s.section ?? '—'}</td>
                  <td className="faint">
                    {s.forwarder ? (
                      <span className="tag warn">→ {s.forwarder}</span>
                    ) : sym ? (
                      <span className="mono" style={{ fontSize: 11 }}>
                        {sym.pretty}
                      </span>
                    ) : (
                      ''
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {rows.length > 4000 && <div className="empty">Showing the first 4,000 of {rows.length.toLocaleString()}.</div>}
      </Panel>
    </>
  );
}

/* ------------------------------------------------------------------ resources */
export function Resources({ pe }: { pe: PEImage }) {
  if (!pe.resources) return <Empty>No resource directory — this image carries no icons, dialogs or version info.</Empty>;
  return (
    <>
      <h2 className="section-title">Resources</h2>
      <p className="section-sub">
        A three-level tree: resource type → name or ID → language, ending in {pe.resourceCount} data leaves. This is where
        icons, dialog templates, string tables, the version block and the side-by-side manifest live.
      </p>
      {pe.versionInfo && (
        <Panel title="Version information">
          <div className="fields" style={{ margin: -14 }}>
            {Object.entries(pe.versionInfo).map(([k, v]) => (
              <div className="field" key={k} style={{ gridTemplateColumns: '220px 1fr' }}>
                <span className="fname">{k}</span>
                <span className="fval">{v}</span>
              </div>
            ))}
          </div>
        </Panel>
      )}
      <Panel title="Resource tree">
        <div className="tree">
          {pe.resources.children?.map((c, i) => (
                <TreeNode key={i} node={c} depth={0} />
          ))}
        </div>
      </Panel>
    </>
  );
}

function TreeNode({ node, depth }: { node: ResourceNode; depth: number }) {
  const [open, setOpen] = useState(depth < 1);
  const hasKids = !!node.children?.length;
  const label =
    depth === 0
      ? typeof node.id === 'string'
        ? node.id
        : (node.typeName ?? RESOURCE_TYPE[Number(node.id)] ?? `Type ${node.id}`)
      : depth === 1
        ? `#${node.name}`
        : `lang ${node.name}`;

  return (
    <div className="tnode">
      <div className="row" onClick={() => hasKids && setOpen((o) => !o)}>
        <span className="caret">{hasKids ? (open ? '▼' : '▶') : '·'}</span>
        <span className="name">{label}</span>
        {node.dataSize !== undefined && (
          <span className="meta">
            {hexBig(node.dataRva ?? 0)} · {formatSize(node.dataSize)}
            {node.codePage ? ` · cp${node.codePage}` : ''}
          </span>
        )}
        {hasKids && <span className="meta">{node.children!.length} entries</span>}
      </div>
      {open && hasKids && (
        <div className="kids">
          {node.children!.map((c, i) => (
            <TreeNode key={i} node={c} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ symbols */
export function Symbols({
  pe,
  symbols,
  pdb,
  onDropHint,
}: {
  pe: PEImage;
  symbols: Symbol[];
  pdb: PdbInfo | null;
  onDropHint: () => void;
}) {
  const [q, setQ] = useState('');
  const [kind, setKind] = useState('all');
  const cv = pe.debug.find((d) => d.type === 2);

  if (!symbols.length) {
    return (
      <>
        <h2 className="section-title">Symbols</h2>
        <p className="section-sub">
          {pdb
            ? 'The PDB loaded, but it carries no public or procedure symbol records. Managed (.NET) assemblies keep their names in CLI metadata rather than in the PDB symbol streams, so this is expected for IL-only images.'
            : 'No symbol file loaded yet. Drop the matching .pdb or linker .map next to the DLL and every address in this app gets a real name.'}
        </p>
        {pdb && (
          <div className="stat-grid">
            <div className="stat">
              <div className="k">PDB GUID</div>
              <div className="v sm">{pdb.guid}</div>
            </div>
            <div className="stat">
              <div className="k">Age</div>
              <div className="v sm">{pdb.age}</div>
            </div>
            <div className="stat">
              <div className="k">MSF block size</div>
              <div className="v sm">{pdb.blockSize} B</div>
            </div>
            <div className="stat">
              <div className="k">Streams</div>
              <div className="v sm">{pdb.streamCount}</div>
            </div>
            <div className="stat">
              <div className="k">Compilands</div>
              <div className="v sm">{pdb.modules.length}</div>
            </div>
            <div className="stat">
              <div className="k">Matches image</div>
              <div className="v sm">{cv?.guid === pdb.guid && cv?.age === pdb.age ? 'yes' : 'no'}</div>
            </div>
          </div>
        )}
        {cv?.pdbPath && !pdb && (
          <div className="banner info">
            <span>ℹ</span>
            <div>
              This image was built with <b className="mono">{cv.pdbPath.split(/[\\/]/).pop()}</b> — GUID{' '}
              <span className="mono">{cv.guid}</span>, age {cv.age}. Only a PDB with exactly that GUID and age matches
              this build.
            </div>
          </div>
        )}
        {pdb && pdb.modules.length > 0 && (
          <Panel title="Compilands in the PDB" sub={`${pdb.modules.length} object files`} tight>
            <table className="grid">
              <thead>
                <tr>
                  <th>Module</th>
                  <th>Object file</th>
                  <th className="num">Symbol bytes</th>
                </tr>
              </thead>
              <tbody>
                {pdb.modules.slice(0, 500).map((m, i) => (
                  <tr key={i}>
                    <td className="mono">{m.name}</td>
                    <td className="mono faint">{m.objectFile}</td>
                    <td className="num faint">{m.symbolBytes.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Panel>
        )}
        <button className="btn primary" onClick={onDropHint} style={{ marginTop: 12 }}>
          Add a symbol file
        </button>
      </>
    );
  }

  const needle = q.trim().toLowerCase();
  const rows = symbols.filter(
    (s) =>
      (kind === 'all' || s.kind === kind) &&
      (!needle || s.pretty.toLowerCase().includes(needle) || s.name.toLowerCase().includes(needle)),
  );

  return (
    <>
      <h2 className="section-title">Symbols</h2>
      <p className="section-sub">
        {symbols.length.toLocaleString()} symbols resolved from your {symbols[0].source === 'pdb' ? 'PDB' : 'MAP'} file,
        mapped back onto section-relative addresses.
      </p>
      <div className="toolbar">
        <Search value={q} onChange={setQ} placeholder="Filter symbols…  (press /)" />
        <select className="mini" value={kind} onChange={(e) => setKind(e.target.value)}>
          <option value="all">All kinds</option>
          <option value="function">Functions</option>
          <option value="public">Public</option>
          <option value="data">Data</option>
          <option value="thunk">Thunks</option>
        </select>
        <span className="faint" style={{ fontSize: 12 }}>
          {rows.length.toLocaleString()} shown
        </span>
      </div>
      <Panel title="Resolved symbols" tight>
        <table className="grid">
          <thead>
            <tr>
              <th className="num">RVA</th>
              <th className="num">VA</th>
              <th>Symbol</th>
              <th>Section</th>
              <th>Kind</th>
            </tr>
          </thead>
          <tbody>
            {rows.slice(0, 3000).map((s, i) => (
              <tr key={i}>
                <td className="num">{hexBig(s.rva)}</td>
                <td className="num faint">{hexBig(pe.imageBase + s.rva, pe.is64 ? 12 : 8)}</td>
                <td className="mono" title={s.name}>
                  {s.pretty}
                </td>
                <td className="mono faint">{pe.sections[s.section]?.name ?? '—'}</td>
                <td className="faint">{s.kind}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length > 3000 && <div className="empty">Showing the first 3,000 of {rows.length.toLocaleString()}.</div>}
      </Panel>
    </>
  );
}

