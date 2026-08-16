// secure360-verify-domain
// Verifies domain ownership via DNS TXT record lookup using Google's
// DNS-over-HTTPS resolver. Passive, read-only, rate-limited by the resolver.
import { createClient } from 'npm:@supabase/supabase-js@2.58.0';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Client-Info, Apikey',
};

interface VerifyRequest {
  domain_id: string;
}

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  try {
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabase = createClient(supabaseUrl, supabaseKey);

    const authHeader = req.headers.get('Authorization');
    if (!authHeader) {
      return json({ error: 'Unauthorized' }, 401);
    }

    // Verify the user's JWT and get their session
    const userClient = createClient(supabaseUrl, Deno.env.get('SUPABASE_ANON_KEY')!, {
      global: { headers: { Authorization: authHeader } },
    });
    const { data: { user }, error: userErr } = await userClient.auth.getUser();
    if (userErr || !user) {
      return json({ error: 'Unauthorized' }, 401);
    }

    const body: VerifyRequest = await req.json();
    const { domain_id } = body;
    if (!domain_id) {
      return json({ error: 'domain_id is required' }, 400);
    }

    // Fetch the domain + verification record using service role (bypasses RLS,
    // but we verify membership manually).
    const { data: domain } = await supabase
      .from('domains')
      .select('id, organization_id, domain, normalized_domain, verification_status')
      .eq('id', domain_id)
      .maybeSingle();

    if (!domain) {
      return json({ error: 'Domain not found' }, 404);
    }

    // Check the user is a member of this org
    const { data: member } = await supabase
      .from('organization_members')
      .select('role')
      .eq('organization_id', domain.organization_id)
      .eq('user_id', user.id)
      .maybeSingle();

    if (!member) {
      return json({ error: 'Access denied' }, 403);
    }

    const { data: verif } = await supabase
      .from('domain_verifications')
      .select('*')
      .eq('domain_id', domain_id)
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (!verif) {
      return json({ error: 'No verification record found' }, 404);
    }

    if (domain.verification_status === 'verified') {
      return json({ verified: true, message: 'Domain is already verified.' });
    }

    // Look up TXT records via DNS-over-HTTPS (Google resolver)
    const dnsUrl = `https://dns.google/resolve?name=${encodeURIComponent(domain.normalized_domain)}&type=TXT`;
    const dnsResp = await fetchWithTimeout(dnsUrl, 10000);
    const dnsData = await dnsResp.json();

    const txtRecords: string[] = (dnsData.Answer || [])
      .filter((a: { type: number }) => a.type === 16) // TXT
      .map((a: { data: string }) => a.data.replace(/^"|"$/g, ''));

    // Check if our verification token is present in any TXT record
    const expectedToken = `secure360-verification=${verif.token}`;
    const found = txtRecords.some(
      (t) => t === expectedToken || t.includes(`secure360-verification=${verif.token}`)
    );

    // Increment attempts
    await supabase
      .from('domain_verifications')
      .update({ attempts: verif.attempts + 1 })
      .eq('id', verif.id);

    if (found) {
      // Mark verified
      await supabase
        .from('domains')
        .update({ verification_status: 'verified', verified_at: new Date().toISOString() })
        .eq('id', domain_id);
      await supabase
        .from('domain_verifications')
        .update({ status: 'verified', verified_at: new Date().toISOString() })
        .eq('id', verif.id);

      // Audit log
      await supabase.from('audit_logs').insert({
        organization_id: domain.organization_id,
        user_id: user.id,
        action: 'domain.verified',
        target: domain.domain,
        details: { method: 'dns_txt' },
      });

      return json({ verified: true, message: 'Domain verified successfully!' });
    }

    // Mark failed attempt
    await supabase
      .from('domain_verifications')
      .update({ status: 'failed' })
      .eq('id', verif.id);

    return json({
      verified: false,
      message: 'Verification TXT record not found yet. DNS changes can take a few minutes to propagate.',
      txt_records_found: txtRecords.length,
    });
  } catch (err) {
    return json(
      { error: err instanceof Error ? err.message : 'Verification failed' },
      500
    );
  }
});

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

async function fetchWithTimeout(url: string, ms: number): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), ms);
  try {
    return await fetch(url, { signal: controller.signal });
  } finally {
    clearTimeout(id);
  }
}
