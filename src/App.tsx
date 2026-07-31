import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import './App.css';
import { DropZone } from './components/DropZone';
import { MemoryMap, type Highlight, type LayoutMode } from './components/MemoryMap';
import { Headers } from './components/Headers';
import { Overview } from './components/Overview';
import { Exports, Imports, Resources, Symbols } from './components/Tables';
import { HexView } from './components/HexView';
import { DisasmView } from './components/DisasmView';
import { CompareView } from './components/CompareView';
import { LearnSidebar } from './components/LearnSidebar';
import { parsePE, PEParseError } from './pe/parser';
import type { MemoryRegion, PEImage } from './pe/types';
import { parseMapFile, parsePdb, type PdbInfo, type Symbol } from './symbols/pdb';
import { SECTION_TOPIC_HINTS } from './knowledge/glossary';

type TabId =
  | 'overview'
  | 'map'
  | 'headers'
  | 'imports'
  | 'exports'
  | 'resources'
  | 'symbols'
  | 'disasm'
  | 'hex'
  | 'compare';

const BINARY_RE = /\.(dll|exe|sys|ocx|cpl|drv|efi|node|scr|mui|tlb|winmd)$/i;

const readFile = (f: File) =>
  new Promise<Uint8Array>((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(new Uint8Array(r.result as ArrayBuffer));
    r.onerror = () => reject(new Error(`Could not read ${f.name}`));
    r.readAsArrayBuffer(f);
  });

export default function App() {
  const [pe, setPe] = useState<PEImage | null>(null);
  const [compare, setCompare] = useState<PEImage | null>(null);
  const [pdb, setPdb] = useState<PdbInfo | null>(null);
  const [symbols, setSymbols] = useState<Symbol[]>([]);
  const [symbolFile, setSymbolFile] = useState<{ name: string; kind: 'pdb' | 'map' } | null>(null);
  const [tab, setTab] = useState<TabId>('overview');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [learnOpen, setLearnOpen] = useState(true);
  const [layout, setLayout] = useState<LayoutMode>('virtual');
  const [highlight, setHighlight] = useState<Highlight>('sections');
  const [selected, setSelected] = useState<string | null>(null);
  const [selectedRegion, setSelectedRegion] = useState<MemoryRegion | null>(null);
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const fileInput = useRef<HTMLInputElement>(null);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  const handleFiles = useCallback(
    async (files: File[]) => {
      if (!files.length) return;
      setBusy(true);
      setError(null);
      try {
        let image = pe;
        const binary = files.find((f) => BINARY_RE.test(f.name));
        if (binary) {
          const bytes = await readFile(binary);
          image = parsePE(bytes, binary.name);
          setPe(image);
          setSymbols([]);
          setPdb(null);
          setSymbolFile(null);
          setCompare(null);
          setSelected(null);
          setSelectedRegion(null);
          setTab('overview');
        }
        if (!image) {
          const unknown = files.find((f) => !/\.(pdb|map)$/i.test(f.name));
          if (unknown) {
            const bytes = await readFile(unknown);
            image = parsePE(bytes, unknown.name);
            setPe(image);
            setTab('overview');
          }
        }
        const sectionRvas = image ? image.sections.map((s) => s.virtualAddress) : [];

        const pdbFile = files.find((f) => /\.pdb$/i.test(f.name));
        if (pdbFile && image) {
          const info = parsePdb(await readFile(pdbFile), sectionRvas);
          setPdb(info);
          setSymbols(info.symbols);
          setSymbolFile({ name: pdbFile.name, kind: 'pdb' });
        }
        const mapFile = files.find((f) => /\.map$/i.test(f.name));
        if (mapFile && image) {
          const text = new TextDecoder().decode(await readFile(mapFile));
          const syms = parseMapFile(text, sectionRvas);
          if (syms.length) {
            setSymbols((cur) => (cur.length ? cur : syms));
            setSymbolFile((cur) => cur ?? { name: mapFile.name, kind: 'map' });
          }
        }
        if (!binary && !image) setError('Drop a PE binary (.dll, .exe, .sys) first — symbol files need an image to attach to.');
      } catch (e) {
        setError(e instanceof PEParseError ? e.message : `${(e as Error).message}`);
      } finally {
        setBusy(false);
      }
    },
    [pe],
  );

  const loadCompare = useCallback(async (files: File[]) => {
    const binary = files.find((f) => BINARY_RE.test(f.name)) ?? files[0];
    if (!binary) return;
    setBusy(true);
    setError(null);
    try {
      const bytes = await readFile(binary);
      setCompare(parsePE(bytes, binary.name));
    } catch (e) {
      setError(e instanceof PEParseError ? e.message : `${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    const prevent = (e: DragEvent) => {
      e.preventDefault();
    };
    const drop = (e: DragEvent) => {
      e.preventDefault();
      if (!e.dataTransfer?.files.length) return;
      const files = Array.from(e.dataTransfer.files);
      // While the Compare tab is open a dropped binary becomes the comparison target
      // instead of replacing the image you are already looking at.
      if (tab === 'compare' && pe && files.some((f) => BINARY_RE.test(f.name))) {
        void loadCompare(files);
      } else {
        void handleFiles(files);
      }
    };
    window.addEventListener('dragover', prevent);
    window.addEventListener('drop', drop);
    return () => {
      window.removeEventListener('dragover', prevent);
      window.removeEventListener('drop', drop);
    };
  }, [handleFiles, loadCompare, tab, pe]);

  const contextTopic = useMemo(() => {
    if (tab !== 'map' || !selectedRegion || !pe) return null;
    if (selectedRegion.kind === 'directory') {
      const idx = Number(selectedRegion.id.replace('dir-', ''));
      return (
        { 0: 'exports', 1: 'imports', 2: 'resources', 5: 'relocs', 6: 'debug', 9: 'tls', 10: 'security', 14: 'dotnet' } as Record<number, string>
      )[idx] ?? 'rva';
    }
    if (selectedRegion.kind === 'overlay') return 'overlay';
    if (selectedRegion.kind === 'headers') return 'headers';
    const s = selectedRegion.sectionIndex !== undefined ? pe.sections[selectedRegion.sectionIndex] : undefined;
    if (s) return SECTION_TOPIC_HINTS.find((t) => t.match.test(s.name))?.topic ?? 'entropy';
    return null;
  }, [tab, selectedRegion, pe]);

  const tabs: { id: TabId; label: string; count?: number; hide?: boolean }[] = pe
    ? [
        { id: 'overview', label: 'Overview' },
        { id: 'map', label: 'Memory Map', count: pe.sections.length },
        { id: 'headers', label: 'Headers' },
        { id: 'imports', label: 'Imports', count: pe.imports.reduce((a, m) => a + m.symbols.length, 0) },
        { id: 'exports', label: 'Exports', count: pe.exports?.symbols.length ?? 0 },
        { id: 'resources', label: 'Resources', count: pe.resourceCount, hide: !pe.resources },
        { id: 'symbols', label: 'Symbols', count: symbols.length || undefined },
        { id: 'disasm', label: 'Disassembly' },
        { id: 'hex', label: 'Hex' },
        { id: 'compare', label: 'Compare with…' },
      ]
    : [];

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="glyph">
            <i style={{ background: '#5b8dd9' }} />
            <i style={{ background: '#5b8dd9' }} />
            <i style={{ background: '#4fb3a5' }} />
            <i style={{ background: '#c9885f' }} />
            <i style={{ background: '#c96f9e' }} />
            <i style={{ background: '#a8a35e' }} />
          </span>
          DLL Visualizer
          <small>PE / PE32+ explorer</small>
        </div>

        {pe && (
          <>
            <span className="file-chip">
              <i className="dot" />
              <b title={pe.fileName}>{pe.fileName}</b>
              <span>{pe.is64 ? 'x64' : 'x86'}</span>
            </span>
            {symbolFile && (
              <span className={'file-chip ' + symbolFile.kind}>
                <i className="dot" />
                <b title={symbolFile.name}>{symbolFile.name}</b>
                <span>{symbols.length.toLocaleString()} syms</span>
              </span>
            )}
          </>
        )}

        <span className="spacer" />
        {busy && (
          <span className="loading">
            <i className="spinner" /> parsing…
          </span>
        )}
        {pe && (
          <>
            <button className="btn" onClick={() => fileInput.current?.click()}>
              Add file
            </button>
            <button
              className="btn"
              onClick={() => {
                setPe(null);
                setCompare(null);
                setSymbols([]);
                setPdb(null);
                setSymbolFile(null);
                setError(null);
              }}
            >
              Close
            </button>
          </>
        )}
        <button
          className="btn icon"
          title="Toggle theme"
          onClick={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))}
        >
          {theme === 'dark' ? '☾' : '☀'}
        </button>
        <a
          className="btn icon"
          href="https://github.com/vineeththomasalex/dll-visualizer"
          target="_blank"
          rel="noreferrer"
          title="Source on GitHub"
          style={{ display: 'inline-flex', alignItems: 'center' }}
        >
          <svg width="15" height="15" viewBox="0 0 16 16" fill="currentColor">
            <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z" />
          </svg>
        </a>
        <input
          ref={fileInput}
          type="file"
          multiple
          hidden
          accept=".dll,.exe,.sys,.ocx,.cpl,.drv,.efi,.node,.pdb,.map"
          onChange={(e) => void handleFiles(Array.from(e.target.files ?? []))}
        />
      </header>

      <div className="workspace">
        <div className="main-col">
          {pe && (
            <nav className="tabs">
              {tabs
                .filter((t) => !t.hide)
                .map((t) => (
                  <button key={t.id} className={'tab' + (tab === t.id ? ' active' : '')} onClick={() => setTab(t.id)}>
                    {t.label}
                    {t.count !== undefined && t.count > 0 && <span className="count">{t.count.toLocaleString()}</span>}
                  </button>
                ))}
            </nav>
          )}

          {!pe ? (
            <>
              {error && (
                <div style={{ padding: '14px 18px 0' }}>
                  <div className="banner err">
                    <span>✕</span>
                    <div>{error}</div>
                  </div>
                </div>
              )}
              <DropZone onFiles={(f) => void handleFiles(f)} />
            </>
          ) : (
            <div className={tab === 'map' ? 'view flush' : 'view'}>
              {error && (
                <div className="banner err">
                  <span>✕</span>
                  <div>{error}</div>
                </div>
              )}
              {tab === 'overview' && <Overview pe={pe} symbols={symbols} pdb={pdb} onGoto={(t) => setTab(t as TabId)} />}
              {tab === 'map' && (
                <MemoryMap
                  pe={pe}
                  symbols={symbols}
                  layout={layout}
                  setLayout={setLayout}
                  highlight={highlight}
                  setHighlight={setHighlight}
                  selected={selected}
                  onSelect={(id, region) => {
                    setSelected(id);
                    setSelectedRegion(region);
                  }}
                />
              )}
              {tab === 'headers' && <Headers pe={pe} />}
              {tab === 'imports' && <Imports pe={pe} />}
              {tab === 'exports' && <Exports pe={pe} symbols={symbols} />}
              {tab === 'resources' && <Resources pe={pe} />}
              {tab === 'symbols' && (
                <Symbols pe={pe} symbols={symbols} pdb={pdb} onDropHint={() => fileInput.current?.click()} />
              )}
              {tab === 'disasm' && <DisasmView pe={pe} symbols={symbols} />}
              {tab === 'hex' && <HexView pe={pe} />}
              {tab === 'compare' && (
                <CompareView
                  pe={pe}
                  other={compare}
                  busy={busy}
                  onPick={(f) => void loadCompare(f)}
                  onClear={() => setCompare(null)}
                  onSwap={() => {
                    if (!compare) return;
                    const a = pe;
                    setPe(compare);
                    setCompare(a);
                    setSymbols([]);
                    setPdb(null);
                    setSymbolFile(null);
                    setSelected(null);
                    setSelectedRegion(null);
                  }}
                />
              )}
            </div>
          )}
        </div>

        <LearnSidebar open={learnOpen} setOpen={setLearnOpen} tab={tab} pe={pe} contextTopic={contextTopic} />
      </div>
    </div>
  );
}
