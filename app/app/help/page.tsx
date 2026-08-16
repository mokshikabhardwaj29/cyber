'use client';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  HelpCircle,
  ShieldCheck,
  Lock,
  Globe,
  Mail,
  Cookie,
  Server,
  ArrowRight,
} from 'lucide-react';

const FAQ = [
  {
    q: 'What does Secure360 check?',
    a: 'Secure360 performs six passive, non-destructive checks: HTTPS availability, SSL/TLS certificate validity, HTTP security headers, DNS configuration, SPF records, and cookie security. No exploitation, scanning, or destructive testing is performed.',
  },
  {
    q: 'Do I need to be a developer to use this?',
    a: 'No. Secure360 is designed for small business owners. Every finding is explained in plain English with step-by-step fix instructions. Technical details are available but hidden by default.',
  },
  {
    q: 'How does domain verification work?',
    a: 'Before scanning, you prove you own the domain by adding a TXT record to your DNS configuration. This ensures we only scan domains you control.',
  },
  {
    q: 'Is this safe for my website?',
    a: 'Yes. All checks are passive and read-only. We only look at publicly available information — DNS records, HTTP headers, and certificate data. We never attempt to exploit, brute-force, or attack your site.',
  },
  {
    q: 'How is the security score calculated?',
    a: 'Your score starts at 100 and points are deducted based on the severity of findings: critical (-30), high (-18), medium (-9), low (-4). Resolved findings are added back. The score is a helpful indicator, not a guarantee.',
  },
  {
    q: 'What happens when I fix an issue?',
    a: 'Click "Verify Fix" on any finding. Secure360 re-runs the specific check to confirm the issue is resolved. If verified, your finding is marked resolved and your security score is recalculated.',
  },
  {
    q: 'What if a check can\'t be completed?',
    a: 'Sometimes a check can\'t run (e.g., a site is unreachable). These are marked as "Unable to Verify" and do not count against your score. We distinguish between a real security issue and a technical failure.',
  },
];

const CHECKS = [
  { icon: Lock, title: 'HTTPS/TLS', desc: 'Verifies your site uses HTTPS and redirects HTTP traffic.' },
  { icon: ShieldCheck, title: 'SSL/TLS Certificate', desc: 'Checks certificate validity, expiration, and hostname match.' },
  { icon: Server, title: 'Security Headers', desc: 'Inspects CSP, HSTS, X-Content-Type-Options, and more.' },
  { icon: Globe, title: 'DNS Configuration', desc: 'Checks DNS resolution, nameservers, and record health.' },
  { icon: Mail, title: 'SPF', desc: 'Verifies your SPF record exists and is valid for email security.' },
  { icon: Cookie, title: 'Cookie Security', desc: 'Inspects Secure, HttpOnly, and SameSite cookie attributes.' },
];

export default function HelpPage() {
  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Help & FAQ</h1>
        <p className="mt-1 text-sm text-muted-foreground">Learn how Secure360 keeps your business secure.</p>
      </div>

      {/* What we check */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">What Secure360 Checks</CardTitle>
          <CardDescription>Six passive, non-destructive security checks</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-2">
            {CHECKS.map((c) => (
              <div key={c.title} className="flex items-start gap-3">
                <div className="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-lg bg-primary/10">
                  <c.icon className="h-5 w-5 text-primary" />
                </div>
                <div>
                  <p className="text-sm font-medium">{c.title}</p>
                  <p className="text-xs text-muted-foreground">{c.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* FAQ */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg">
            <HelpCircle className="h-5 w-5 text-primary" />
            Frequently Asked Questions
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {FAQ.map((item) => (
            <div key={item.q} className="border-b border-border pb-4 last:border-0">
              <p className="font-medium">{item.q}</p>
              <p className="mt-1 text-sm text-muted-foreground">{item.a}</p>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* Product principle */}
      <Card className="bg-navy text-navy-foreground">
        <CardContent className="p-6">
          <h3 className="font-semibold">Our Product Principle</h3>
          <p className="mt-2 text-sm text-navy-foreground/70">
            Secure360 answers four simple questions: What&apos;s wrong? Why does it matter? What should I do? Did I fix it?
          </p>
          <p className="mt-2 text-sm text-navy-foreground/70">
            We do not turn this into a complicated vulnerability scanner. This is a cybersecurity health check and action plan for small-business owners.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
