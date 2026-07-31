import { useEffect, useRef, useState, type ReactNode } from 'react';

/** Cursor-following tooltip used by the memory map and charts. */
export function HoverCard({ children }: { children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState({ x: 0, y: 0 });

  useEffect(() => {
    const onMove = (e: MouseEvent) => setPos({ x: e.clientX, y: e.clientY });
    window.addEventListener('mousemove', onMove);
    return () => window.removeEventListener('mousemove', onMove);
  }, []);

  const el = ref.current;
  const w = el?.offsetWidth ?? 320;
  const h = el?.offsetHeight ?? 140;
  const x = Math.min(pos.x + 16, window.innerWidth - w - 12);
  const y = Math.min(pos.y + 16, window.innerHeight - h - 12);

  return (
    <div className="tooltip" ref={ref} style={{ left: x, top: Math.max(8, y) }}>
      {children}
    </div>
  );
}

export function Stat({ k, v, small }: { k: string; v: ReactNode; small?: boolean }) {
  return (
    <div className="stat">
      <div className="k">{k}</div>
      <div className={small ? 'v sm' : 'v'}>{v}</div>
    </div>
  );
}

export function Panel({
  title,
  sub,
  right,
  children,
  tight,
}: {
  title: ReactNode;
  sub?: ReactNode;
  right?: ReactNode;
  children: ReactNode;
  tight?: boolean;
}) {
  return (
    <section className="panel">
      <header>
        <span>{title}</span>
        {sub && <span className="sub">{sub}</span>}
        <span className="spacer" />
        {right}
      </header>
      <div className={tight ? 'body tight' : 'body'}>{children}</div>
    </section>
  );
}

export function Search({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder: string;
}) {
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === '/' && document.activeElement?.tagName !== 'INPUT') {
        e.preventDefault();
        ref.current?.focus();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);
  return (
    <label className="search">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" opacity="0.5">
        <circle cx="11" cy="11" r="7" />
        <path d="M20 20l-3.5-3.5" />
      </svg>
      <input
        ref={ref}
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        spellCheck={false}
      />
      {value && (
        <button className="faint" onClick={() => onChange('')} title="Clear">
          ✕
        </button>
      )}
    </label>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}
