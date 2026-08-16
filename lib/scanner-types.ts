// Shared types for scanner evidence and the rule engine.
// These mirror the edge-function scanner output shapes so the frontend
// can render evidence and the rule engine can run deterministically.

export interface HttpsEvidence {
  https_available: boolean;
  https_url: string | null;
  http_redirects_to_https: boolean | null;
  final_url: string | null;
  status_code: number | null;
  tls_protocol: string | null;
  error: string | null;
}

export interface CertificateEvidence {
  valid: boolean;
  hostname_match: boolean | null;
  subject: string | null;
  issuer: string | null;
  not_before: string | null;
  not_after: string | null;
  days_remaining: number | null;
  expired: boolean;
  san: string[];
  error: string | null;
}

export interface HeaderEvidence {
  headers: {
    name: string;
    value: string | null;
    present: boolean;
  }[];
  url: string;
  error: string | null;
}

export interface DnsEvidence {
  resolves: boolean;
  a_records: string[];
  aaaa_records: string[];
  nameservers: string[];
  txt_records: string[];
  cnames: string[];
  error: string | null;
}

export interface SpfEvidence {
  exists: boolean;
  records: string[];
  record_count: number;
  all_mechanism: string | null;
  appears_valid: boolean;
  error: string | null;
}

export interface CookieEvidence {
  cookies: {
    name: string;
    secure: boolean;
    httponly: boolean;
    samesite: string | null;
    domain: string | null;
    path: string | null;
    expires: string | null;
  }[];
  count: number;
  error: string | null;
}

export type ScannerEvidence =
  | HttpsEvidence
  | CertificateEvidence
  | HeaderEvidence
  | DnsEvidence
  | SpfEvidence
  | CookieEvidence;

export const CHECK_STEPS = [
  { id: 'WEB-HTTPS-001', name: 'HTTPS/TLS', label: 'HTTPS/TLS check' },
  { id: 'WEB-TLS-001', name: 'Certificate', label: 'SSL/TLS certificate check' },
  { id: 'WEB-HEADERS-001', name: 'Security Headers', label: 'HTTP security headers check' },
  { id: 'DNS-001', name: 'DNS', label: 'DNS configuration check' },
  { id: 'EMAIL-SPF-001', name: 'SPF', label: 'SPF check' },
  { id: 'WEB-COOKIE-001', name: 'Cookies', label: 'Cookie security check' },
] as const;

export const SCORE_BANDS = [
  { min: 90, max: 100, label: 'Excellent', color: 'green' },
  { min: 75, max: 89, label: 'Good', color: 'blue' },
  { min: 50, max: 74, label: 'Needs Improvement', color: 'amber' },
  { min: 25, max: 49, label: 'Poor', color: 'orange' },
  { min: 0, max: 24, label: 'Critical', color: 'red' },
] as const;

export function scoreLabel(score: number): string {
  const band = SCORE_BANDS.find((b) => score >= b.min && score <= b.max);
  return band?.label ?? 'Critical';
}

export function scoreColor(score: number): string {
  const band = SCORE_BANDS.find((b) => score >= b.min && score <= b.max);
  return band?.color ?? 'red';
}
