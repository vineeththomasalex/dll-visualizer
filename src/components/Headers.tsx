import { useState } from 'react';
import type { PEImage } from '../pe/types';
import { formatSize, hexBig } from '../pe/reader';
import { Panel } from './ui';

export function Headers({ pe }: { pe: PEImage }) {
  const [open, setOpen] = useState<string[]>(['coff', 'optional']);
  const toggle = (id: string) => setOpen((o) => (o.includes(id) ? o.filter((x) => x !== id) : [...o, id]));

  return (
    <>
      <h2 className="section-title">Headers</h2>
      <p className="section-sub">
        Every field the Windows loader reads before it maps a single byte of content, in file order. Offsets are absolute
        file offsets — these headers are also mapped at the image base, so the same bytes are readable at runtime.
      </p>

      {pe.groups.map((g) => {
        const isOpen = open.includes(g.id);
        return (
          <section className="panel" key={g.id}>
            <div className="group-head" onClick={() => toggle(g.id)}>
              <span className="caret">{isOpen ? '▼' : '▶'}</span>
              <b>{g.title}</b>
              <span className="faint mono" style={{ fontSize: 11 }}>
                {hexBig(g.offset)} · {formatSize(g.size)}
              </span>
              <span className="spacer" />
              <span className="faint">{g.fields.length} fields</span>
            </div>
            {isOpen && (
              <>
                <div className="body" style={{ paddingBottom: 0, color: 'var(--text-dim)', fontSize: 12.5, lineHeight: 1.6 }}>
                  {g.desc}
                </div>
                <div className="fields" style={{ marginTop: 10 }}>
                  {g.fields.map((f) => (
                    <div className="field" key={f.name + f.offset}>
                      <span className="fname">{f.name}</span>
                      <span className="foff">{hexBig(f.offset)}</span>
                      <span className="fval">{f.value}</span>
                      {f.desc && <span className="fdesc">{f.desc}</span>}
                      {f.flags && (
                        <span className="flags">
                          {f.flags
                            .filter((x) => x.set)
                            .map((x) => (
                              <span className="tag on" key={x.name} title={x.desc}>
                                {x.name}
                              </span>
                            ))}
                          {f.flags
                            .filter((x) => !x.set)
                            .map((x) => (
                              <span className="tag" key={x.name} title={x.desc} style={{ opacity: 0.4 }}>
                                {x.name}
                              </span>
                            ))}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </>
            )}
          </section>
        );
      })}

      <Panel title="Data directories" sub="16 fixed slots the loader indexes by number" tight>
        <table className="grid">
          <thead>
            <tr>
              <th className="num">#</th>
              <th>Directory</th>
              <th className="num">RVA</th>
              <th className="num">Size</th>
              <th>In section</th>
              <th>Role</th>
            </tr>
          </thead>
          <tbody>
            {pe.dataDirectories.map((d) => {
              const sec = pe.sections.find(
                (s) => d.rva >= s.virtualAddress && d.rva < s.virtualAddress + Math.max(s.virtualSize, s.rawSize),
              );
              return (
                <tr key={d.index} style={{ opacity: d.rva ? 1 : 0.4 }}>
                  <td className="num">{d.index}</td>
                  <td>{d.name}</td>
                  <td className="num">{d.rva ? hexBig(d.rva) : '—'}</td>
                  <td className="num">{d.size ? formatSize(d.size) : '—'}</td>
                  <td className="mono faint">{d.index === 4 ? '(file offset)' : (sec?.name ?? '—')}</td>
                  <td className="faint" style={{ maxWidth: 460 }}>
                    {d.desc}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </Panel>

      {pe.rich && (
        <Panel
          title="Rich header"
          sub={`undocumented build provenance · XOR key ${hexBig(pe.rich.key)}`}
          tight
        >
          <table className="grid">
            <thead>
              <tr>
                <th className="num">Product ID</th>
                <th>Tool</th>
                <th className="num">Build</th>
                <th className="num">Objects</th>
              </tr>
            </thead>
            <tbody>
              {pe.rich.entries.map((e, i) => (
                <tr key={i}>
                  <td className="num">{hexBig(e.productId, 4)}</td>
                  <td>{e.productName}</td>
                  <td className="num">{e.buildNumber}</td>
                  <td className="num">{e.count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}

      {pe.loadConfig && (
        <Panel title="Load configuration" sub="loader-enforced hardening metadata">
          <div className="fields" style={{ margin: -14 }}>
            {pe.loadConfig.map((f) => (
              <div className="field" key={f.name}>
                <span className="fname">{f.name}</span>
                <span className="foff">{hexBig(f.offset)}</span>
                <span className="fval">{f.value}</span>
                {f.desc && <span className="fdesc">{f.desc}</span>}
              </div>
            ))}
          </div>
        </Panel>
      )}

      {pe.debug.length > 0 && (
        <Panel title="Debug directory" tight>
          <table className="grid">
            <thead>
              <tr>
                <th>Type</th>
                <th className="num">Size</th>
                <th className="num">RVA</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {pe.debug.map((d, i) => (
                <tr key={i}>
                  <td>{d.typeName}</td>
                  <td className="num">{formatSize(d.sizeOfData)}</td>
                  <td className="num">{hexBig(d.addressOfRawData)}</td>
                  <td className="mono faint" style={{ wordBreak: 'break-all' }}>
                    {d.pdbPath ? `${d.pdbPath} · ${d.guid} · age ${d.age}` : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}

      {pe.tls && (
        <Panel title="Thread Local Storage">
          <div className="fields" style={{ margin: -14 }}>
            <F k="StartAddressOfRawData" v={hexBig(pe.tls.startAddressOfRawData, pe.is64 ? 12 : 8)} d="VA of the TLS initialisation template." />
            <F k="EndAddressOfRawData" v={hexBig(pe.tls.endAddressOfRawData, pe.is64 ? 12 : 8)} />
            <F k="AddressOfIndex" v={hexBig(pe.tls.addressOfIndex, pe.is64 ? 12 : 8)} d="Where the loader stores this module's TLS slot index." />
            <F k="AddressOfCallbacks" v={hexBig(pe.tls.addressOfCallbacks, pe.is64 ? 12 : 8)} d="Null-terminated array of callbacks run on every thread attach and detach." />
            <F k="SizeOfZeroFill" v={formatSize(pe.tls.sizeOfZeroFill)} />
            {pe.tls.callbacks.map((c, i) => (
              <F key={i} k={`Callback[${i}]`} v={hexBig(c, pe.is64 ? 12 : 8)} d="Runs before DllMain on process attach — a favourite anti-debug hook." />
            ))}
          </div>
        </Panel>
      )}

      {pe.certificates.length > 0 && (
        <Panel title="Certificate table" sub="appended after the last section, never mapped" tight>
          <table className="grid">
            <thead>
              <tr>
                <th className="num">File offset</th>
                <th className="num">Size</th>
                <th className="num">Revision</th>
                <th>Type</th>
              </tr>
            </thead>
            <tbody>
              {pe.certificates.map((c, i) => (
                <tr key={i}>
                  <td className="num">{hexBig(c.offset)}</td>
                  <td className="num">{formatSize(c.size)}</td>
                  <td className="num">{hexBig(c.revision, 4)}</td>
                  <td>{c.type}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}
    </>
  );
}

function F({ k, v, d }: { k: string; v: string; d?: string }) {
  return (
    <div className="field">
      <span className="fname">{k}</span>
      <span className="foff" />
      <span className="fval">{v}</span>
      {d && <span className="fdesc">{d}</span>}
    </div>
  );
}
