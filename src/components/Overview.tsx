import type { PEImage } from '../pe/types';
import { formatSize, hexBig } from '../pe/reader';
import { entropyColor } from '../pe/entropy';
import type { PdbInfo, Symbol } from '../symbols/pdb';
import { Panel, Stat } from './ui';

export function Overview({
  pe,
  symbols,
  pdb,
  onGoto,
}: {
  pe: PEImage;
  symbols: Symbol[];
  pdb: PdbInfo | null;
  onGoto: (tab: string) => void;
}) {
  const codeBytes = pe.sections.filter((s) => s.characteristics & 0x20000000).reduce((a, s) => a + s.virtualSize, 0);
  const importCount = pe.imports.reduce((a, m) => a + m.symbols.length, 0);
  const cv = pe.debug.find((d) => d.type === 2);
  const pdbMatches = pdb && cv?.guid ? pdb.guid === cv.guid && pdb.age === cv.age : null;

  return (
    <>
      <h2 className="section-title">{pe.fileName}</h2>
      <p className="section-sub">
        {pe.is64 ? '64-bit (PE32+)' : '32-bit (PE32)'} {pe.isDll ? 'dynamic-link library' : 'executable'} for{' '}
        {pe.machineName}, {pe.subsystemName.toLowerCase()} subsystem. {formatSize(pe.fileSize)} on disk expands to{' '}
        {formatSize(pe.sizeOfImage)} of virtual address space.
        {pe.isDotNet && ' This is a managed .NET assembly — most of its content is CLI metadata and IL rather than native code.'}
      </p>

      {pe.warnings.length > 0 && (
        <div className="banner warn">
          <span>⚠</span>
          <div>
            {pe.warnings.map((w, i) => (
              <div key={i} style={{ marginBottom: i === pe.warnings.length - 1 ? 0 : 5 }}>
                {w}
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="stat-grid">
        <Stat k="Architecture" v={pe.machineName} small />
        <Stat k="Image base" v={hexBig(pe.imageBase, pe.is64 ? 12 : 8)} small />
        <Stat k="Entry point" v={pe.entryPoint ? hexBig(pe.entryPoint) : '—'} small />
        <Stat k="Sections" v={String(pe.sections.length)} small />
        <Stat k="Imports" v={`${importCount} from ${pe.imports.length}`} small />
        <Stat k="Exports" v={String(pe.exports?.symbols.length ?? 0)} small />
        <Stat k="Relocations" v={pe.relocCount.toLocaleString()} small />
        <Stat k="Resources" v={String(pe.resourceCount)} small />
        <Stat k="Executable code" v={formatSize(codeBytes)} small />
        <Stat k="Overall entropy" v={`${pe.entropy.toFixed(2)} / 8`} small />
        <Stat k="Linked" v={pe.timeDateStamp ? new Date(pe.timeDateStamp * 1000).toISOString().slice(0, 10) : '—'} small />
        <Stat k="Symbols loaded" v={symbols.length ? symbols.length.toLocaleString() : '—'} small />
      </div>

      <div className="split">
        <Panel title="Security posture" sub="what this image opted into">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 9 }}>
            <Mitigation on={pe.hasASLR} name="ASLR (DYNAMIC_BASE)" good="Image can be loaded at a random base." bad="Image demands its preferred base — predictable addresses for an attacker." />
            <Mitigation on={pe.hasDEP} name="DEP (NX_COMPAT)" good="Data pages are non-executable." bad="Data pages may be executable — classic shellcode territory." />
            <Mitigation on={pe.hasCFG} name="Control Flow Guard" good="Indirect calls are validated against a table of legal targets." bad="Indirect calls are unchecked." />
            <Mitigation on={pe.hasSEH} name="Structured exception handling" good="SEH allowed (SafeSEH may still restrict handlers)." bad="NO_SEH set — no exception handlers may run." neutral />
            <Mitigation on={pe.hasAuthenticode} name="Authenticode signature" good={`Signed — ${formatSize(pe.certificates[0]?.size ?? 0)} PKCS#7 blob appended.`} bad="Unsigned." />
            <Mitigation
              on={!pe.sections.some((s) => s.perms === 'RWX')}
              name="No W+X sections"
              good="No section is writable and executable at the same time."
              bad="A section is writable AND executable — almost certainly a packer."
            />
            <Mitigation on={(pe.dllCharacteristics & 0x0020) !== 0} name="High-entropy ASLR" good="Full 64-bit address randomisation." bad="Randomisation limited to the low 32 bits." neutral={!pe.is64} />
          </div>
        </Panel>

        <Panel title="Build provenance">
          <div className="fields" style={{ margin: -14 }}>
            <Row k="Linker version" v={pe.groups.find((g) => g.id === 'optional')?.fields.find((f) => f.name === 'LinkerVersion')?.value ?? '—'} />
            <Row k="Timestamp" v={pe.timeDateStamp ? `${new Date(pe.timeDateStamp * 1000).toUTCString()}` : 'not set'} />
            <Row k="CheckSum" v={`${hexBig(pe.checksum)} ${pe.checksum === pe.computedChecksum ? '(valid)' : pe.checksum === 0 ? '(not set)' : '(mismatch)'}`} />
            {cv && <Row k="PDB" v={cv.pdbPath ?? '—'} />}
            {cv?.guid && <Row k="PDB GUID" v={`${cv.guid} (age ${cv.age})`} />}
            {pdb && (
              <Row
                k="Loaded PDB"
                v={pdbMatches ? '✓ matches this image exactly' : '✗ GUID/age mismatch — symbols may be wrong'}
              />
            )}
            {pe.rich && <Row k="Rich header" v={`${pe.rich.entries.length} tool records, key ${hexBig(pe.rich.key)}`} />}
            {pe.versionInfo &&
              Object.entries(pe.versionInfo).map(([k, v]) => <Row key={k} k={k} v={v} />)}
          </div>
        </Panel>
      </div>

      <Panel title="Sections at a glance" tight right={<button className="btn" onClick={() => onGoto('sections')}>Details →</button>}>
        <table className="grid">
          <thead>
            <tr>
              <th>Name</th>
              <th>Perms</th>
              <th className="num">RVA</th>
              <th className="num">Virtual size</th>
              <th className="num">Raw size</th>
              <th style={{ width: 160 }}>Entropy</th>
              <th>Purpose</th>
            </tr>
          </thead>
          <tbody>
            {pe.sections.map((s) => (
              <tr key={s.index}>
                <td className="mono">{s.name}</td>
                <td className="mono">{s.perms}</td>
                <td className="num">{hexBig(s.virtualAddress)}</td>
                <td className="num">{formatSize(s.virtualSize)}</td>
                <td className="num">{formatSize(s.rawSize)}</td>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <div className="bar" style={{ flex: 1 }}>
                      <i style={{ width: `${(s.entropy / 8) * 100}%`, background: entropyColor(s.entropy) }} />
                    </div>
                    <span className="mono faint" style={{ fontSize: 11 }}>
                      {s.entropy.toFixed(2)}
                    </span>
                  </div>
                </td>
                <td className="faint" style={{ maxWidth: 380 }}>
                  {s.desc}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>

      {pe.clr && (
        <Panel title=".NET metadata">
          <div className="fields" style={{ margin: -14 }}>
            <Row k="Runtime version" v={pe.clr.runtimeVersion} />
            <Row k="Metadata version" v={pe.clr.metadataVersion ?? '—'} />
            <Row k="Flags" v={pe.clr.flagNames.join(', ') || hexBig(pe.clr.flags)} />
            <Row k="Entry point token" v={hexBig(pe.clr.entryPointToken)} />
            <Row k="Metadata" v={`${hexBig(pe.clr.metadataRva)} · ${formatSize(pe.clr.metadataSize)}`} />
            {pe.clr.streams?.map((s) => (
              <Row key={s.name} k={`Stream ${s.name}`} v={`${hexBig(s.offset)} · ${formatSize(s.size)}`} />
            ))}
          </div>
        </Panel>
      )}
    </>
  );
}

function Mitigation({
  on,
  name,
  good,
  bad,
  neutral,
}: {
  on: boolean;
  name: string;
  good: string;
  bad: string;
  neutral?: boolean;
}) {
  return (
    <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
      <span className={'tag ' + (on ? 'good' : neutral ? '' : 'bad')} style={{ marginTop: 1, minWidth: 46, textAlign: 'center' }}>
        {on ? 'ON' : 'OFF'}
      </span>
      <div style={{ fontSize: 12.5 }}>
        <b style={{ fontWeight: 550 }}>{name}</b>
        <div className="faint" style={{ lineHeight: 1.5, marginTop: 2 }}>
          {on ? good : bad}
        </div>
      </div>
    </div>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="field" style={{ gridTemplateColumns: '190px 1fr' }}>
      <span className="fname">{k}</span>
      <span className="fval" style={{ gridColumn: 'auto' }}>
        {v}
      </span>
    </div>
  );
}
