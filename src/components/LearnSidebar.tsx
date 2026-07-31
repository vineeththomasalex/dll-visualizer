import { useEffect, useState } from 'react';
import { TIPS, TOPICS } from '../knowledge/glossary';
import type { PEImage } from '../pe/types';
import { formatSize, hexBig } from '../pe/reader';

const TAB_TOPIC: Record<string, string> = {
  overview: 'overview',
  map: 'loader',
  headers: 'headers',
  imports: 'imports',
  exports: 'exports',
  resources: 'resources',
  symbols: 'symbols',
  disasm: 'disasm',
  hex: 'rva',
  compare: 'compare',
};

export function LearnSidebar({
  open,
  setOpen,
  tab,
  pe,
  contextTopic,
}: {
  open: boolean;
  setOpen: (v: boolean) => void;
  tab: string;
  pe: PEImage | null;
  contextTopic?: string | null;
}) {
  const [pinned, setPinned] = useState<string | null>(null);
  const [tipIndex, setTipIndex] = useState(0);

  useEffect(() => {
    const t = setInterval(() => setTipIndex((i) => (i + 1) % TIPS.length), 9000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => setPinned(null), [tab]);

  const topicId = pinned ?? contextTopic ?? TAB_TOPIC[tab] ?? 'overview';
  const topic = TOPICS[topicId] ?? TOPICS.overview;

  const related = Object.values(TOPICS)
    .filter((t) => t.id !== topic.id)
    .slice(0, 20);

  return (
    <aside className={'learn' + (open ? '' : ' closed')}>
      <header>
        <button className="btn icon" onClick={() => setOpen(!open)} title={open ? 'Collapse' : 'Learn panel'}>
          {open ? '›' : '‹'}
        </button>
        <span className="t">Learn</span>
        <span className="spacer" />
        {open && pinned && (
          <button className="btn icon" onClick={() => setPinned(null)} title="Back to context">
            ↺
          </button>
        )}
      </header>
      {!open && <div className="vert-label">LEARN</div>}
      <div className="learn-body">
        <h4>{topic.title}</h4>
        <p>{topic.body}</p>
        {topic.bullets && (
          <ul>
            {topic.bullets.map((b, i) => (
              <li key={i}>{b}</li>
            ))}
          </ul>
        )}

        {pe && (
          <>
            <div style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-faint)', margin: '16px 0 6px' }}>
              This image
            </div>
            <div className="kv">
              <span>Type</span>
              <span>{pe.is64 ? 'PE32+' : 'PE32'}</span>
            </div>
            <div className="kv">
              <span>Base</span>
              <span>{hexBig(pe.imageBase, pe.is64 ? 12 : 8)}</span>
            </div>
            <div className="kv">
              <span>Mapped</span>
              <span>{formatSize(pe.sizeOfImage)}</span>
            </div>
            <div className="kv">
              <span>Sections</span>
              <span>{pe.sections.length}</span>
            </div>
            <div className="kv">
              <span>Mitigations</span>
              <span>
                {[pe.hasASLR && 'ASLR', pe.hasDEP && 'DEP', pe.hasCFG && 'CFG'].filter(Boolean).join(' ') || 'none'}
              </span>
            </div>
          </>
        )}

        <div style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-faint)', margin: '16px 0 6px' }}>
          More topics
        </div>
        <div className="topic-links">
          {related.map((t) => (
            <button key={t.id} className="tag" onClick={() => setPinned(t.id)}>
              {t.title}
            </button>
          ))}
        </div>

        <div className="tip">💡 {TIPS[tipIndex]}</div>
      </div>
    </aside>
  );
}
