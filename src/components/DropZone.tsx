import { useRef, useState } from 'react';

export function DropZone({ onFiles }: { onFiles: (files: File[]) => void }) {
  const [over, setOver] = useState(false);
  const input = useRef<HTMLInputElement>(null);

  return (
    <div className="landing">
      <div style={{ textAlign: 'center' }}>
        <h1>See inside a DLL</h1>
      </div>
      <p className="lede">
        Drop a Windows <b>.dll</b>, <b>.exe</b>, <b>.sys</b> or <b>.ocx</b> and get the exact layout the loader will
        build in memory: colour-coded sections, every header field explained, imports and exports grouped by purpose, the
        resource tree, and a live disassembly. Add the matching <b>.pdb</b> or <b>.map</b> to put real names on the
        addresses.
      </p>

      <div
        className={'dropzone' + (over ? ' over' : '')}
        onDragOver={(e) => {
          e.preventDefault();
          setOver(true);
        }}
        onDragLeave={() => setOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setOver(false);
          onFiles(Array.from(e.dataTransfer.files));
        }}
        onClick={() => input.current?.click()}
      >
        <div className="big">Drop your files here</div>
        <div className="sub">or click to browse · .dll .exe .sys .ocx .pdb .map</div>
        <input
          ref={input}
          type="file"
          multiple
          hidden
          accept=".dll,.exe,.sys,.ocx,.cpl,.drv,.efi,.node,.pdb,.map"
          onChange={(e) => onFiles(Array.from(e.target.files ?? []))}
        />
      </div>

      <div className="features">
        <div className="feature">
          <b>Memory map</b>
          <span>Every section as a proportional band, with data-directory overlays and permission colouring.</span>
        </div>
        <div className="feature">
          <b>Explained headers</b>
          <span>All DOS, COFF and optional-header fields with plain-English notes on what each one drives.</span>
        </div>
        <div className="feature">
          <b>Imports &amp; exports</b>
          <span>Grouped by module and by what they actually do — file I/O, crypto, networking, process control.</span>
        </div>
        <div className="feature">
          <b>Real disassembly</b>
          <span>Capstone compiled to WebAssembly, seeded from the entry point, exports and your symbols.</span>
        </div>
        <div className="feature">
          <b>Symbols</b>
          <span>A PDB reader that parses the MSF container in the browser, plus linker .map support.</span>
        </div>
        <div className="feature">
          <b>Security posture</b>
          <span>ASLR, DEP, CFG, SafeSEH, signatures and entropy — with the risky combinations called out.</span>
        </div>
      </div>

      <div className="privacy">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <rect x="4" y="10" width="16" height="11" rx="2" />
          <path d="M8 10V7a4 4 0 018 0v3" />
        </svg>
        100% client-side. Your binaries are parsed in this tab and never uploaded anywhere.
      </div>
    </div>
  );
}
