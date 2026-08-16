// Normalize a domain input: strip protocol, www., paths, query, trailing slash.
// Reject IPs and empty input. Returns null if invalid.
export function normalizeDomain(input: string): string | null {
  if (!input) return null;
  let value = input.trim().toLowerCase();
  if (!value) return null;
  // strip protocol
  value = value.replace(/^https?:\/\//, '');
  // strip everything after first /
  value = value.split('/')[0];
  // strip everything after ?
  value = value.split('?')[0];
  // strip port
  value = value.split(':')[0];
  // strip leading www.
  value = value.replace(/^www\./, '');
  // strip trailing dot
  value = value.replace(/\.$/, '');
  // must contain a dot and only valid hostname chars
  if (!value.includes('.')) return null;
  if (!/^[a-z0-9.-]+$/.test(value)) return null;
  // reject IP addresses
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return null;
  if (value.startsWith('-') || value.endsWith('-')) return null;
  return value;
}

export function randomToken(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
