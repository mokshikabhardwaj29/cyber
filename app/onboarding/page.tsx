'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth-context';
import { supabase } from '@/lib/supabase';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { ShieldCheck, Loader2, AlertCircle, Building2 } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

const INDUSTRIES = [
  'E-commerce / Retail',
  'Professional Services',
  'Healthcare',
  'Education',
  'Finance / Accounting',
  'Hospitality / Restaurant',
  'Construction / Trades',
  'Non-profit',
  'Technology / SaaS',
  'Manufacturing',
  'Real Estate',
  'Other',
];

const COUNTRIES = [
  'United States', 'United Kingdom', 'Canada', 'Australia', 'Germany',
  'France', 'Spain', 'Italy', 'Netherlands', 'Ireland', 'Other',
];

export default function OnboardingPage() {
  const router = useRouter();
  const { user, loading, refreshOrg } = useAuth();
  const { toast } = useToast();
  const [name, setName] = useState('');
  const [industry, setIndustry] = useState('');
  const [country, setCountry] = useState('');
  const [timezone, setTimezone] = useState('UTC');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!loading && !user) {
      router.push('/login');
    }
    if (!loading && user) {
      // If user already has an org, skip onboarding
      supabase
        .from('organization_members')
        .select('organization_id')
        .eq('user_id', user.id)
        .maybeSingle()
        .then(({ data }) => {
          if (data) {
            router.push('/app/dashboard');
          }
        });
    }
  }, [user, loading, router]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!user) return;
    setError(null);
    setSubmitting(true);

    try {
      const { data: org, error: orgError } = await supabase
        .from('organizations')
        .insert({
          name,
          industry: industry || null,
          country: country || null,
          timezone,
          owner_id: user.id,
        })
        .select()
        .single();

      if (orgError) throw orgError;

      const { error: memberError } = await supabase.from('organization_members').insert({
        organization_id: org.id,
        user_id: user.id,
        role: 'owner',
      });

      if (memberError) throw memberError;

      // Create default notification preferences
      await supabase.from('notification_preferences').insert({
        user_id: user.id,
        organization_id: org.id,
      });

      // Audit log
      await supabase.from('audit_logs').insert({
        organization_id: org.id,
        user_id: user.id,
        action: 'organization.created',
        target: org.id,
        details: { name },
      });

      await refreshOrg();
      toast({ title: 'Business created', description: `${name} is ready to secure.` });
      router.push('/app/dashboard');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create business. Please try again.');
    } finally {
      setSubmitting(false);
    }
  }

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-navy text-navy-foreground">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="flex min-h-screen flex-col bg-navy text-navy-foreground">
      <div className="flex flex-1 items-center justify-center px-4 py-12">
        <div className="w-full max-w-lg">
          <div className="mb-8 text-center">
            <div className="mb-3 inline-flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10">
              <Building2 className="h-6 w-6 text-primary" />
            </div>
            <h1 className="text-2xl font-bold">Set up your business</h1>
            <p className="mt-2 text-navy-foreground/60">
              Tell us about your business so we can tailor your security plan.
            </p>
          </div>
          <Card className="border-white/10 bg-white/5 text-navy-foreground backdrop-blur">
            <CardContent className="pt-6">
              <form onSubmit={handleSubmit} className="space-y-4">
                {error && (
                  <div className="flex items-center gap-2 rounded-md bg-red-500/10 p-3 text-sm text-red-300">
                    <AlertCircle className="h-4 w-4 flex-shrink-0" />
                    {error}
                  </div>
                )}
                <div className="space-y-2">
                  <Label htmlFor="name">Business name</Label>
                  <Input
                    id="name"
                    required
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="ABC Store"
                    className="border-white/10 bg-white/5"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="industry">Industry (optional)</Label>
                  <Select value={industry} onValueChange={setIndustry}>
                    <SelectTrigger className="border-white/10 bg-white/5">
                      <SelectValue placeholder="Select an industry" />
                    </SelectTrigger>
                    <SelectContent>
                      {INDUSTRIES.map((i) => (
                        <SelectItem key={i} value={i}>{i}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="country">Country (optional)</Label>
                  <Select value={country} onValueChange={setCountry}>
                    <SelectTrigger className="border-white/10 bg-white/5">
                      <SelectValue placeholder="Select a country" />
                    </SelectTrigger>
                    <SelectContent>
                      {COUNTRIES.map((c) => (
                        <SelectItem key={c} value={c}>{c}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="timezone">Timezone</Label>
                  <Input
                    id="timezone"
                    value={timezone}
                    onChange={(e) => setTimezone(e.target.value)}
                    placeholder="UTC"
                    className="border-white/10 bg-white/5"
                  />
                </div>
                <Button type="submit" disabled={submitting} className="w-full">
                  {submitting ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Create business'}
                </Button>
              </form>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
