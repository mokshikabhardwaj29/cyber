import type {
  AssessmentResult,
  Confidence,
  Finding,
  Priority,
  Severity,
} from './types';

export interface RuleFindingInput {
  rule_id: string;
  title: string;
  category: AssessmentResult['category'];
  severity: Severity;
  confidence: Confidence;
  priority: Priority;
  asset: string;
  remediation_id: string | null;
  effort_minutes: number | null;
  difficulty: string | null;
  business_impact: string;
  evidence: Record<string, unknown>;
}

// Deterministic rule evaluation: map each assessment result to zero or one
// finding. The rule engine is the single source of truth — the UI never
// invents findings.
export function evaluateResults(
  results: AssessmentResult[],
  asset: string
): RuleFindingInput[] {
  const findings: RuleFindingInput[] = [];

  for (const r of results) {
    if (r.status === 'pass' || r.status === 'info') continue;
    if (r.confidence === 'unable_to_verify') continue;

    switch (r.check_id) {
      case 'WEB-HTTPS-001': {
        const ev = r.evidence as { https_available?: boolean; http_redirects_to_https?: boolean | null };
        if (ev.https_available === false) {
          findings.push(make('WEB-HTTPS-001', 'HTTPS is not enabled', r.category, 'high', 'high', 'critical', asset, 'REM-WEB-HTTPS-001', 15, 'easy', 'Without HTTPS, information exchanged with your website may not be protected in transit.', r.evidence));
        } else if (ev.http_redirects_to_https === false) {
          findings.push(make('WEB-HTTPS-001', 'HTTP does not redirect to HTTPS', r.category, 'medium', 'high', 'high', asset, 'REM-WEB-HTTPS-001', 15, 'easy', 'Visitors can still reach your site over an insecure connection.', r.evidence));
        }
        break;
      }
      case 'WEB-TLS-001': {
        const ev = r.evidence as { expired?: boolean; days_remaining?: number | null; hostname_match?: boolean | null };
        if (ev.expired === true) {
          findings.push(make('WEB-TLS-001', 'Your SSL/TLS certificate is expired', r.category, 'critical', 'high', 'critical', asset, 'REM-WEB-TLS-001', 15, 'easy', 'Visitors may see browser security warnings if the certificate has expired.', r.evidence));
        } else if (ev.days_remaining != null && ev.days_remaining <= 7) {
          findings.push(make('WEB-TLS-002', 'Your SSL/TLS certificate expires soon', r.category, 'high', 'high', 'high', asset, 'REM-WEB-TLS-002', 15, 'easy', 'Visitors may receive browser security warnings when the certificate expires.', r.evidence));
        } else if (ev.days_remaining != null && ev.days_remaining <= 30) {
          findings.push(make('WEB-TLS-002', 'Your SSL/TLS certificate expires soon', r.category, 'medium', 'high', 'medium', asset, 'REM-WEB-TLS-002', 15, 'easy', 'Visitors may receive browser security warnings when the certificate expires.', r.evidence));
        }
        if (ev.hostname_match === false) {
          findings.push(make('WEB-TLS-001', 'Your SSL/TLS certificate does not match your hostname', r.category, 'high', 'high', 'high', asset, 'REM-WEB-TLS-001', 15, 'easy', 'A hostname mismatch can cause browsers to warn visitors.', r.evidence));
        }
        break;
      }
      case 'WEB-HEADERS-001': {
        const ev = r.evidence as { headers?: { name: string; present: boolean }[] };
        const missing = ev.headers?.filter((h) => !h.present) ?? [];
        const headerRules: Record<string, { id: string; title: string; sev: Severity; rem: string; effort: number }> = {
          'Content-Security-Policy': { id: 'WEB-HEADERS-001', title: 'Content-Security-Policy header is missing', sev: 'medium', rem: 'REM-WEB-HEADERS-001', effort: 40 },
          'Strict-Transport-Security': { id: 'WEB-HEADERS-002', title: 'Strict-Transport-Security header is missing', sev: 'medium', rem: 'REM-WEB-HEADERS-002', effort: 10 },
          'X-Content-Type-Options': { id: 'WEB-HEADERS-003', title: 'X-Content-Type-Options header is missing', sev: 'low', rem: 'REM-WEB-HEADERS-003', effort: 5 },
          'Referrer-Policy': { id: 'WEB-HEADERS-004', title: 'Referrer-Policy header is missing', sev: 'low', rem: 'REM-WEB-HEADERS-004', effort: 5 },
          'Permissions-Policy': { id: 'WEB-HEADERS-005', title: 'Permissions-Policy header is missing', sev: 'low', rem: 'REM-WEB-HEADERS-005', effort: 10 },
        };
        for (const h of missing) {
          const rule = headerRules[h.name];
          if (!rule) continue;
          const conf = h.name === 'Permissions-Policy' ? 'medium' : 'high';
          findings.push(make(rule.id, rule.title, r.category, rule.sev, conf as Confidence, rule.sev === 'medium' ? 'medium' : 'low', asset, rule.rem, rule.effort, 'easy', `${h.name} helps protect your website visitors from browser-based risks.`, r.evidence));
        }
        break;
      }
      case 'DNS-001': {
        const ev = r.evidence as { resolves?: boolean; nameservers?: string[] };
        if (ev.resolves === false) {
          findings.push(make('DNS-001', 'Your domain does not resolve', r.category, 'high', 'high', 'high', asset, 'REM-DNS-001', 30, 'medium', 'If your domain does not resolve, visitors cannot reach your website.', r.evidence));
        } else if ((ev.nameservers?.length ?? 0) === 0) {
          findings.push(make('DNS-001', 'No nameservers detected for your domain', r.category, 'medium', 'high', 'medium', asset, 'REM-DNS-001', 30, 'medium', 'Without nameservers, your domain cannot function.', r.evidence));
        }
        break;
      }
      case 'EMAIL-SPF-001': {
        const ev = r.evidence as { exists?: boolean; record_count?: number; appears_valid?: boolean };
        if (ev.exists === false) {
          findings.push(make('EMAIL-SPF-001', 'SPF record is missing', r.category, 'medium', 'high', 'medium', asset, 'REM-EMAIL-SPF-001', 10, 'easy', 'SPF helps email providers identify which servers are authorized to send mail for your domain.', r.evidence));
        } else if ((ev.record_count ?? 0) > 1) {
          findings.push(make('EMAIL-SPF-001', 'SPF is misconfigured — multiple SPF records detected', r.category, 'medium', 'high', 'medium', asset, 'REM-EMAIL-SPF-002', 15, 'medium', 'Multiple SPF records can cause email providers to reject your email.', r.evidence));
        } else if (ev.appears_valid === false) {
          findings.push(make('EMAIL-SPF-001', 'SPF record appears invalid', r.category, 'medium', 'medium', 'medium', asset, 'REM-EMAIL-SPF-002', 15, 'medium', 'An invalid SPF record may not protect your email as intended.', r.evidence));
        }
        break;
      }
      case 'WEB-COOKIE-001': {
        const ev = r.evidence as { cookies?: { secure?: boolean; httponly?: boolean; samesite?: string | null }[]; count?: number };
        const cookies = ev.cookies ?? [];
        if (cookies.length === 0) break;
        const insecure = cookies.filter((c) => !c.secure || !c.httponly || !c.samesite);
        if (insecure.length > 0) {
          findings.push(make('WEB-COOKIE-001', 'Cookie security could be improved', r.category, 'low', 'medium', 'low', asset, 'REM-WEB-COOKIE-001', 15, 'medium', 'Cookie security settings help reduce certain types of unwanted cross-site requests.', r.evidence));
        }
        break;
      }
    }
  }

  return findings;
}

function make(
  rule_id: string,
  title: string,
  category: AssessmentResult['category'],
  severity: Severity,
  confidence: Confidence,
  priority: Priority,
  asset: string,
  remediation_id: string | null,
  effort_minutes: number | null,
  difficulty: string | null,
  business_impact: string,
  evidence: Record<string, unknown>
): RuleFindingInput {
  return { rule_id, title, category, severity, confidence, priority, asset, remediation_id, effort_minutes, difficulty, business_impact, evidence };
}

// Deterministic 0–100 security score from findings.
// Start at 100; subtract weights by severity. Resolved findings do not
// subtract. Clamp 0–100.
export function calculateScore(findings: Finding[]): number {
  const weights: Record<Severity, number> = {
    critical: 30,
    high: 18,
    medium: 9,
    low: 4,
    informational: 0,
  };
  let score = 100;
  for (const f of findings) {
    if (f.status === 'resolved' || f.status === 'accepted_risk') continue;
    score -= weights[f.severity] ?? 0;
  }
  return Math.max(0, Math.min(100, score));
}
