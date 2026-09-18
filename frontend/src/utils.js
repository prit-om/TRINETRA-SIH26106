export function getBadgeColor(classification) {
  switch (classification) {
    case 'Safe': return 'bg-emerald-950 text-emerald-400 border-emerald-800';
    case 'Low Risk': return 'bg-amber-950 text-amber-400 border-amber-800';
    case 'Suspicious': return 'bg-orange-950 text-orange-400 border-orange-800';
    case 'Phishing': return 'bg-rose-950 text-pink-400 border-rose-800';
    case 'Critical': return 'bg-red-950 text-red-500 border-red-800';
    default: return 'bg-slate-900 text-cyan-400 border-slate-700';
  }
}

export function getRiskTextColor(score = 0) {
  if (score >= 75) return 'text-rose-500';
  if (score >= 40) return 'text-amber-400';
  return 'text-emerald-400';
}

export function formatBytes(bytes) {
  if (!Number.isFinite(Number(bytes)) || Number(bytes) < 0) return 'Unknown size';
  const value = Number(bytes);
  if (value < 1024) return `${value} B`;
  const units = ['KB', 'MB', 'GB'];
  let size = value / 1024;
  let unit = units[0];
  for (let i = 1; i < units.length && size >= 1024; i += 1) {
    size /= 1024;
    unit = units[i];
  }
  return `${size.toFixed(size >= 10 ? 1 : 2)} ${unit}`;
}

export function formatDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function clampScore(value) {
  const n = Number(value);
  return Number.isFinite(n) ? Math.min(100, Math.max(0, n)) : 0;
}

export function percent(value) {
  return Math.round(Math.min(1, Math.max(0, Number(value) || 0)) * 100);
}
