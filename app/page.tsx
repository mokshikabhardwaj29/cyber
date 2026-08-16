'use client';

import Link from 'next/link';
import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth-context';
import { Button } from '@/components/ui/button';
import {
  ShieldCheck,
  Lock,
  Globe,
  FileCheck,
  TrendingUp,
  ArrowRight,
  CheckCircle2,
} from 'lucide-react';

export default function LandingPage() {
  const { user, loading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!loading && user) {
      router.push('/app/dashboard');
    }
  }, [user, loading, router]);

  return (
    <div className="min-h-screen bg-navy text-navy-foreground">
      <header className="border-b border-white/10">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-7 w-7 text-primary" />
            <span className="text-lg font-semibold">Secure360 SMB</span>
          </div>
          <div className="flex items-center gap-3">
            <Link href="/login">
              <Button variant="ghost" className="text-navy-foreground hover:bg-white/10">
                Log in
              </Button>
            </Link>
            <Link href="/signup">
              <Button>Get started</Button>
            </Link>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-6">
        <section className="py-20 md:py-28">
          <div className="mx-auto max-w-3xl text-center">
            <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-white/15 bg-white/5 px-4 py-1.5 text-sm text-navy-foreground/80">
              <Lock className="h-4 w-4 text-primary" />
              Safe, passive security checks — no hacking required
            </div>
            <h1 className="text-4xl font-bold leading-tight tracking-tight md:text-6xl">
              A simple cybersecurity health check for your small business
            </h1>
            <p className="mt-6 text-lg text-navy-foreground/70 md:text-xl">
              Secure360 scans your website and domain for common security gaps,
              explains them in plain English, and gives you a step-by-step plan to fix them.
            </p>
            <div className="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row">
              <Link href="/signup">
                <Button size="lg" className="w-full sm:w-auto">
                  Start your free assessment
                  <ArrowRight className="ml-2 h-4 w-4" />
                </Button>
              </Link>
              <Link href="/login">
                <Button size="lg" variant="outline" className="w-full border-white/20 bg-transparent text-navy-foreground hover:bg-white/10 sm:w-auto">
                  I already have an account
                </Button>
              </Link>
            </div>
          </div>
        </section>

        <section className="grid gap-6 pb-20 md:grid-cols-3">
          {[
            {
              icon: Globe,
              title: 'Website & Domain Checks',
              desc: 'HTTPS, SSL certificates, security headers, DNS, SPF, and cookie security — all assessed safely.',
            },
            {
              icon: FileCheck,
              title: 'Plain-English Findings',
              desc: 'No jargon. Every finding explains what is wrong, why it matters, and exactly how to fix it.',
            },
            {
              icon: TrendingUp,
              title: 'Track Your Progress',
              desc: 'A clear 0–100 security score, prioritized action plan, and verify-fix to confirm improvements.',
            },
          ].map((f) => (
            <div
              key={f.title}
              className="rounded-xl border border-white/10 bg-white/5 p-6 backdrop-blur"
            >
              <f.icon className="mb-4 h-8 w-8 text-primary" />
              <h3 className="mb-2 text-lg font-semibold">{f.title}</h3>
              <p className="text-sm text-navy-foreground/70">{f.desc}</p>
            </div>
          ))}
        </section>

        <section className="pb-24">
          <div className="rounded-2xl border border-white/10 bg-white/5 p-8 md:p-12">
            <h2 className="mb-8 text-center text-2xl font-bold">What Secure360 checks</h2>
            <div className="grid gap-3 md:grid-cols-2">
              {[
                'Is HTTPS enabled and does HTTP redirect to HTTPS?',
                'Is your SSL/TLS certificate valid and not expiring soon?',
                'Are important security headers present (CSP, HSTS, etc.)?',
                'Does your domain resolve correctly with healthy DNS?',
                'Is an SPF record configured for your email domain?',
                'Are cookies set with Secure, HttpOnly, and SameSite?',
              ].map((item) => (
                <div key={item} className="flex items-start gap-3">
                  <CheckCircle2 className="mt-0.5 h-5 w-5 flex-shrink-0 text-success" />
                  <span className="text-sm text-navy-foreground/80">{item}</span>
                </div>
              ))}
            </div>
          </div>
        </section>
      </main>

      <footer className="border-t border-white/10">
        <div className="mx-auto max-w-6xl px-6 py-8 text-center text-sm text-navy-foreground/50">
          Secure360 SMB — Safe, passive, non-destructive security assessments.
        </div>
      </footer>
    </div>
  );
}
