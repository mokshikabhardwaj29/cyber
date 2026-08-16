// secure360-verify-fix
// Re-runs a single safe check for a specific finding to verify if the issue
// has been resolved. Only supports the passive checks. Does not mark resolved
// unless the check actually passes.
import { createClient } from 'npm:@supabase/supabase-js@2.58.0';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Client-Info, Apikey',
};

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  try {
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const anonKey = Deno.env.get('SUPABASE_ANON_KEY')!;
    const supabase = createClient(supabaseUrl, serviceKey);

    const authHeader = req.headers.get('Authorization');
    if (!authHeader) return json({ error: 'Unauthorized' }, 401);

    const userClient = createClient(supabaseUrl, anonKey, {
      global: { headers: { Authorization: authHeader } },
    });
    const { data: { user }, error: userErr } = await userClient.auth.getUser();
    if (userErr || !user) return json({ error: 'Unauthorized' }, 401);

    const { finding_id } = await req.json();
    if (!finding_id) return json({ error: 'finding_id required' }, 400);

    // Fetch the finding
    const { data: finding } = await supabase
      .from('findings')
      .select('*')
      .eq('id', finding_id)
      .maybeSingle();
    if (!finding) return json({ error: 'Finding not found' }, 404);

    // Membership check
    const { data: member } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', finding.organization_id)
      .eq('user_id', user.id)
      .maybeSingle();
    if (!member) return json({ error: 'Access denied' }, 403);

    // Fetch the domain
    const { data: domain } = await supabase
      .from('domains')
      .select('normalized_domain, verification_status')
      .eq('id', finding.domain_id)
      .maybeSingle();
    if (!domain) return json({ error: 'Domain not found' }, 404);

    if (domain.verification_status !== 'verified') {
      return json({ error: 'Domain not verified' }, 403);
    }

    const asset = domain.normalized_domain;
    const verificationMethod = finding.rule_id;

    // Determine which check to re-run based on the rule
    let result;

    if (verificationMethod === 'WEB-HTTPS-001') {
      result = await scanHttps(asset);
    } else if (verificationMethod === 'WEB-TLS-001' || verificationMethod === 'WEB-TLS-002') {
      const httpsRes = await scanHttps(asset);
      result = await scanCertificate(asset, httpsRes.evidence as { https_available?: boolean });
    } else if (verificationMethod.startsWith('WEB-HEADERS-')) {
      const httpsRes = await scanHttps(asset);
      result = await scanHeaders(asset, httpsRes.evidence as { https_url?: string | null });
    } else if (verificationMethod === 'DNS-001') {
      result = await scanDns(asset);
    } else if (verificationMethod === 'EMAIL-SPF-001') {
      result = await scanSpf(asset);
    } else if (verificationMethod === 'WEB-COOKIE-001') {
      const httpsRes = await scanHttps(asset);
      result = await scanCookies(asset, httpsRes.evidence as { https_url?: string | null });
    } else {
      return json({ error: 'Cannot verify this finding type' }, 400);
    }

    // Check if the specific issue is resolved
    const resolved = checkResolved(verificationMethod, result, finding.evidence);

    if (resolved) {
      // Mark finding as resolved
      await supabase
        .from('findings')
        .update({
          status: 'resolved',
          resolved_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          evidence: { ...finding.evidence, verification: result.evidence, verified_at: new Date().toISOString() },
        })
        .eq('id', finding_id);

      // Recalculate score for the assessment
      const { data: allFindings } = await supabase
        .from('findings')
        .select('severity, status')
        .eq('assessment_id', finding.assessment_id);

      const weights: Record<string, number> = { critical: 30, high: 18, medium: 9, low: 4, informational: 0 };
      let score = 100;
      for (const f of allFindings ?? []) {
        if (f.status === 'resolved' || f.status === 'accepted_risk') continue;
        score -= weights[f.severity] ?? 0;
      }
      score = Math.max(0, Math.min(100, score));
      const label = score >= 90 ? 'Excellent' : score >= 75 ? 'Good' : score >= 50 ? 'Needs Improvement' : score >= 25 ? 'Poor' : 'Critical';

      await supabase
        .from('assessments')
        .update({ score, score_label: label })
        .eq('id', finding.assessment_id);

      // Add new score history entry
      await supabase.from('score_history').insert({
        organization_id: finding.organization_id,
        domain_id: finding.domain_id,
        assessment_id: finding.assessment_id,
        score,
        label,
      });

      // Audit log
      await supabase.from('audit_logs').insert({
        organization_id: finding.organization_id,
        user_id: user.id,
        action: 'finding.verified_resolved',
        target: finding.rule_id,
        details: { finding_id, score },
      });

      return json({
        verified: true,
        resolved: true,
        message: 'Fix verified. This issue has been resolved.',
        new_score: score,
        new_label: label,
        evidence: result.evidence,
      });
    } else {
      // Not resolved — update evidence but keep status
      await supabase
        .from('findings')
        .update({
          updated_at: new Date().toISOString(),
          evidence: { ...finding.evidence, last_verification: result.evidence, last_verified_at: new Date().toISOString() },
        })
        .eq('id', finding_id);

      return json({
        verified: true,
        resolved: false,
        message: 'The issue is still detected. Review the remediation steps and try again.',
        evidence: result.evidence,
      });
    }
  } catch (err) {
    return json(
      { error: err instanceof Error ? err.message : 'Verification failed' },
      500
    );
  }
});

function checkResolved(ruleId: string, result: { status: string; evidence: Record<string, unknown> }, _oldEvidence: Record<string, unknown>): boolean {
  if (result.status === 'pass' || result.status === 'info') return true;

  const ev = result.evidence;

  switch (ruleId) {
    case 'WEB-HTTPS-001':
      return ev.https_available === true && ev.http_redirects_to_https !== false;
    case 'WEB-TLS-001':
    case 'WEB-TLS-002': {
      if (ev.expired === true) return false;
      if (ev.days_remaining != null && ev.days_remaining <= 30) return false;
      return ev.valid === true;
    }
    case 'WEB-HEADERS-001':
    case 'WEB-HEADERS-002':
    case 'WEB-HEADERS-003':
    case 'WEB-HEADERS-004':
    case 'WEB-HEADERS-005': {
      const headers = (ev.headers as Array<{ name: string; present: boolean }>) || [];
      const headerName = ruleId === 'WEB-HEADERS-001' ? 'Content-Security-Policy' :
        ruleId === 'WEB-HEADERS-002' ? 'Strict-Transport-Security' :
        ruleId === 'WEB-HEADERS-003' ? 'X-Content-Type-Options' :
        ruleId === 'WEB-HEADERS-004' ? 'Referrer-Policy' :
        ruleId === 'WEB-HEADERS-005' ? 'Permissions-Policy' : '';
      const h = headers.find((x) => x.name === headerName);
      return h?.present === true;
    }
    case 'DNS-001':
      return ev.resolves === true && (ev.nameservers as string[]).length > 0;
    case 'EMAIL-SPF-001':
      return ev.exists === true && (ev.record_count as number) <= 1;
    case 'WEB-COOKIE-001': {
      const cookies = (ev.cookies as Array<{ secure: boolean; httponly: boolean; samesite: string | null }>) || [];
      if (cookies.length === 0) return true;
      return cookies.every((c) => c.secure && c.httponly && c.samesite);
    }
    default:
      return false;
  }
}

// ===== Scanners (same as assess function) =====

async function fetchWithTimeout(url: string, ms: number): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), ms);
  try {
    return await fetch(url, {
      signal: controller.signal,
      redirect: 'follow',
      headers: { 'User-Agent': 'Secure360-SMB/1.0 (passive security assessment)' },
    });
  } finally {
    clearTimeout(id);
  }
}

async function scanHttps(domain: string) {
  const evidence: Record<string, unknown> = { https_available: false, https_url: null, http_redirects_to_https: null, final_url: null, status_code: null, error: null };
  try {
    const resp = await fetchWithTimeout(`https://${domain}/`, 10000);
    evidence.https_available = true;
    evidence.https_url = `https://${domain}/`;
    evidence.final_url = resp.url;
    evidence.status_code = resp.status;
    try {
      const httpResp = await fetchWithTimeout(`http://${domain}/`, 10000);
      evidence.http_redirects_to_https = httpResp.url.startsWith('https://');
    } catch { evidence.http_redirects_to_https = null; }
    const status = evidence.https_available && evidence.http_redirects_to_https ? 'pass' : evidence.https_available ? 'warn' : 'fail';
    return { status, confidence: 'high', evidence };
  } catch (err) {
    evidence.error = err instanceof Error ? err.message : 'HTTPS failed';
    return { status: 'fail', confidence: 'high', evidence };
  }
}

async function scanCertificate(domain: string, httpsEv: { https_available?: boolean }) {
  const evidence: Record<string, unknown> = { valid: false, hostname_match: null, not_after: null, days_remaining: null, expired: false, error: null };
  if (!httpsEv.https_available) {
    evidence.error = 'HTTPS not available';
    return { status: 'error', confidence: 'unable_to_verify', evidence };
  }
  try {
    const conn = await Deno.connectTls({ hostname: domain, port: 443 });
    conn.close();
    evidence.valid = true;
    evidence.hostname_match = true;
    try {
      const crtResp = await fetchWithTimeout(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`, 10000);
      if (crtResp.ok) {
        const crtData = await crtResp.json();
        if (Array.isArray(crtData) && crtData.length > 0 && crtData[0].not_after) {
          const notAfter = new Date(crtData[0].not_after);
          const daysRemaining = Math.floor((notAfter.getTime() - Date.now()) / 86400000);
          evidence.not_after = notAfter.toISOString();
          evidence.days_remaining = daysRemaining;
          evidence.expired = daysRemaining < 0;
        }
      }
    } catch { /* fall through */ }
    if (evidence.days_remaining === null) return { status: 'pass', confidence: 'medium', evidence };
    const status = evidence.expired ? 'fail' : (evidence.days_remaining as number) <= 30 ? 'warn' : 'pass';
    return { status, confidence: 'high', evidence };
  } catch (err) {
    evidence.error = err instanceof Error ? err.message : 'TLS failed';
    return { status: 'fail', confidence: 'high', evidence };
  }
}

async function scanHeaders(domain: string, httpsEv: { https_url?: string | null }) {
  const targetHeaders = ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy'];
  const evidence: Record<string, unknown> = { headers: targetHeaders.map((h) => ({ name: h, value: null, present: false })), url: null, error: null };
  try {
    const resp = await fetchWithTimeout(httpsEv.https_url || `https://${domain}/`, 10000);
    (evidence.headers as Array<{ name: string; value: string | null; present: boolean }>).forEach((h) => {
      const v = resp.headers.get(h.name);
      h.value = v; h.present = v !== null;
    });
    const allPresent = (evidence.headers as Array<{ present: boolean }>).every((h) => h.present);
    return { status: allPresent ? 'pass' : 'warn', confidence: 'high', evidence };
  } catch (err) {
    evidence.error = err instanceof Error ? err.message : 'Header fetch failed';
    return { status: 'error', confidence: 'unable_to_verify', evidence };
  }
}

async function scanDns(domain: string) {
  const evidence: Record<string, unknown> = { resolves: false, a_records: [], nameservers: [], error: null };
  try {
    const aResp = await fetchWithTimeout(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`, 10000);
    const aData = await aResp.json();
    evidence.a_records = (aData.Answer || []).filter((a: { type: number }) => a.type === 1).map((a: { data: string }) => a.data);
    evidence.resolves = (evidence.a_records as string[]).length > 0;
    const nsResp = await fetchWithTimeout(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=NS`, 10000);
    const nsData = await nsResp.json();
    evidence.nameservers = (nsData.Answer || []).filter((a: { type: number }) => a.type === 2).map((a: { data: string }) => a.data);
    const status = !evidence.resolves ? 'fail' : (evidence.nameservers as string[]).length === 0 ? 'warn' : 'pass';
    return { status, confidence: 'high', evidence };
  } catch (err) {
    evidence.error = err instanceof Error ? err.message : 'DNS failed';
    return { status: 'error', confidence: 'unable_to_verify', evidence };
  }
}

async function scanSpf(domain: string) {
  const evidence: Record<string, unknown> = { exists: false, records: [], record_count: 0, appears_valid: false, error: null };
  try {
    const resp = await fetchWithTimeout(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=TXT`, 10000);
    const data = await resp.json();
    const allTxt = (data.Answer || []).filter((a: { type: number }) => a.type === 16).map((a: { data: string }) => a.data.replace(/^"|"$/g, ''));
    const spfRecords = allTxt.filter((t: string) => t.startsWith('v=spf1'));
    evidence.records = spfRecords;
    evidence.record_count = spfRecords.length;
    evidence.exists = spfRecords.length > 0;
    if (spfRecords.length > 0) {
      const allMatch = spfRecords[0].match(/(\+|-|~|\?)?all/);
      evidence.appears_valid = spfRecords[0].startsWith('v=spf1') && allMatch !== null;
    }
    const status = spfRecords.length === 0 ? 'warn' : spfRecords.length > 1 ? 'warn' : !evidence.appears_valid ? 'warn' : 'pass';
    return { status, confidence: 'high', evidence };
  } catch (err) {
    evidence.error = err instanceof Error ? err.message : 'SPF failed';
    return { status: 'error', confidence: 'unable_to_verify', evidence };
  }
}

async function scanCookies(domain: string, httpsEv: { https_url?: string | null }) {
  const evidence: Record<string, unknown> = { cookies: [], count: 0, error: null };
  try {
    const resp = await fetchWithTimeout(httpsEv.https_url || `https://${domain}/`, 10000);
    let setCookies: string[] = [];
    try { setCookies = (resp.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie?.() ?? []; } catch { /* ignore */ }
    if (setCookies.length === 0) {
      const raw = resp.headers.get('set-cookie');
      if (raw) setCookies = raw.split(/,(?=\s*\w+=)/);
    }
    const cookies = setCookies.map((sc: string) => {
      const parts = sc.split(';').map((p) => p.trim());
      const name = (parts[0] || '').split('=')[0] || '';
      const attrs = parts.slice(1);
      const attrMap: Record<string, string> = {};
      attrs.forEach((a) => { const [k, ...v] = a.split('='); attrMap[k.toLowerCase()] = v.join('='); });
      return { name, secure: attrs.some((a) => a.toLowerCase() === 'secure'), httponly: attrs.some((a) => a.toLowerCase() === 'httponly'), samesite: attrMap['samesite'] || null, domain: attrMap['domain'] || null, path: attrMap['path'] || null, expires: attrMap['expires'] || null };
    });
    evidence.cookies = cookies;
    evidence.count = cookies.length;
    if (cookies.length === 0) return { status: 'pass', confidence: 'high', evidence };
    const hasInsecure = cookies.some((c: { secure: boolean; httponly: boolean; samesite: string | null }) => !c.secure || !c.httponly || !c.samesite);
    return { status: hasInsecure ? 'warn' : 'pass', confidence: 'medium', evidence };
  } catch (err) {
    evidence.error = err instanceof Error ? err.message : 'Cookie fetch failed';
    return { status: 'error', confidence: 'unable_to_verify', evidence };
  }
}

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}
