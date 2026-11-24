export const short = (sha: string | undefined) => (sha ? sha.slice(0, 10) : "");

export const ms = (n: number | undefined) => (n === undefined ? "" : n < 1000 ? `${n}ms` : `${(n / 1000).toFixed(1)}s`);

export const ago = (at: number | undefined, now = Date.now()) => {
  if (at === undefined) return "";
  const s = Math.round((now - at) / 1000);
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return new Date(at).toLocaleDateString();
};
