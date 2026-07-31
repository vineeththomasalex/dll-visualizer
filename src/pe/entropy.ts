/** Rolling Shannon entropy helpers used for the section heat strips. */
export function entropyOf(data: Uint8Array): number {
  if (!data.length) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < data.length; i++) counts[data[i]]++;
  let e = 0;
  for (let i = 0; i < 256; i++) {
    if (!counts[i]) continue;
    const p = counts[i] / data.length;
    e -= p * Math.log2(p);
  }
  return e;
}

export function entropyMap(data: Uint8Array, buckets: number): number[] {
  if (!data.length) return [];
  const out: number[] = [];
  const chunk = Math.max(1, Math.floor(data.length / buckets));
  for (let i = 0; i < data.length; i += chunk) {
    out.push(entropyOf(data.subarray(i, Math.min(i + chunk, data.length))));
    if (out.length >= buckets) break;
  }
  return out;
}

/** Maps 0..8 bits of entropy onto the cool→hot ramp used in the UI. */
export function entropyColor(e: number): string {
  const t = Math.max(0, Math.min(1, e / 8));
  const stops: [number, number, number][] = [
    [30, 41, 82],
    [56, 139, 176],
    [95, 194, 137],
    [232, 193, 92],
    [231, 106, 84],
  ];
  const pos = t * (stops.length - 1);
  const i = Math.min(stops.length - 2, Math.floor(pos));
  const f = pos - i;
  const c = stops[i].map((v, k) => Math.round(v + (stops[i + 1][k] - v) * f));
  return `rgb(${c[0]},${c[1]},${c[2]})`;
}
