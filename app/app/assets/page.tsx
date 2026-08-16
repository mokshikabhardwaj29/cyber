'use client';

import { useState, useEffect, useCallback } from 'react';
import { useAuth } from '@/lib/auth-context';
import { supabase } from '@/lib/supabase';
import { normalizeDomain, randomToken } from '@/lib/domain';
import type { Domain, DomainVerification, Assessment } from '@/lib/types';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog';
import { Badge } from '@/components/ui/badge';
import { useToast } from '@/hooks/use-toast';
import {
  Globe,
  Plus,
  Loader2,
  CheckCircle2,
  AlertCircle,
  ShieldCheck,
  Clock,
  Trash2,
  RefreshCw,
  Copy,
  ExternalLink,
  ScanLine,
} from 'lucide-react';
import { formatRelativeTime } from '@/lib/format';
import Link from 'next/link';
import { cn } from '@/lib/utils';

export default function AssetsPage() {
  const { organization, user } = useAuth();
  const { toast } = useToast();
  const [domains, setDomains] = useState<Domain[]>([]);
  const [loading, setLoading] = useState(true);
  const [addOpen, setAddOpen] = useState(false);
  const [newDomain, setNewDomain] = useState('');
  const [adding, setAdding] = useState(false);
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [verifications, setVerifications] = useState<Record<string, DomainVerification>>({});
  const [latestAssessments, setLatestAssessments] = useState<Record<string, Assessment | null>>({});

  const loadDomains = useCallback(async () => {
    if (!organization) return;
    setLoading(true);
    const { data } = await supabase
      .from('domains')
      .select('*')
      .eq('organization_id', organization.id)
      .order('created_at', { ascending: false });
    setDomains((data ?? []) as unknown as Domain[]);

    // Load verifications and latest assessment for each domain
    const verifMap: Record<string, DomainVerification> = {};
    const assessMap: Record<string, Assessment | null> = {};
    for (const d of (data ?? []) as unknown as Domain[]) {
      const { data: v } = await supabase
        .from('domain_verifications')
        .select('*')
        .eq('domain_id', d.id)
        .order('created_at', { ascending: false })
        .limit(1)
        .maybeSingle();
      if (v) verifMap[d.id] = v as unknown as DomainVerification;

      const { data: a } = await supabase
        .from('assessments')
        .select('*')
        .eq('domain_id', d.id)
        .order('created_at', { ascending: false })
        .limit(1)
        .maybeSingle();
      assessMap[d.id] = (a as unknown as Assessment) ?? null;
    }
    setVerifications(verifMap);
    setLatestAssessments(assessMap);
    setLoading(false);
  }, [organization]);

  useEffect(() => {
    loadDomains();
  }, [loadDomains]);

  // Realtime subscription for domain changes
  useEffect(() => {
    if (!organization) return;
    const channel = supabase
      .channel('domains-changes')
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'domains', filter: `organization_id=eq.${organization.id}` },
        () => loadDomains()
      )
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'assessments' },
        () => loadDomains()
      )
      .subscribe();
    return () => {
      supabase.removeChannel(channel);
    };
  }, [organization, loadDomains]);

  async function handleAddDomain(e: React.FormEvent) {
    e.preventDefault();
    if (!organization || !user) return;
    const normalized = normalizeDomain(newDomain);
    if (!normalized) {
      toast({ title: 'Invalid domain', description: 'Please enter a valid domain name like example.com', variant: 'destructive' });
      return;
    }

    setAdding(true);
    try {
      // Check for duplicate
      const { data: existing } = await supabase
        .from('domains')
        .select('id')
        .eq('organization_id', organization.id)
        .eq('normalized_domain', normalized)
        .maybeSingle();
      if (existing) {
        toast({ title: 'Domain already added', description: `${normalized} is already in your assets.`, variant: 'destructive' });
        setAdding(false);
        return;
      }

      const token = randomToken();
      // Simple hash for storage (not cryptographic — the token itself is a random secret)
      const tokenHash = await sha256(token);

      const { data: domain, error } = await supabase
        .from('domains')
        .insert({
          organization_id: organization.id,
          domain: newDomain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0],
          normalized_domain: normalized,
          added_by: user.id,
        })
        .select()
        .single();

      if (error) throw error;

      await supabase.from('domain_verifications').insert({
        domain_id: domain.id,
        method: 'dns_txt',
        token,
        token_hash: tokenHash,
      });

      await supabase.from('audit_logs').insert({
        organization_id: organization.id,
        user_id: user.id,
        action: 'domain.added',
        target: normalized,
        details: {},
      });

      toast({ title: 'Domain added', description: `${normalized} added. Verify ownership to start assessments.` });
      setNewDomain('');
      setAddOpen(false);
      loadDomains();
    } catch (err) {
      toast({ title: 'Failed to add domain', description: err instanceof Error ? err.message : 'Unknown error', variant: 'destructive' });
    } finally {
      setAdding(false);
    }
  }

  async function handleVerify(domainId: string) {
    setVerifyingId(domainId);
    try {
      const resp = await fetch(`${process.env.NEXT_PUBLIC_SUPABASE_URL}/functions/v1/secure360-verify-domain`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${(await supabase.auth.getSession()).data.session?.access_token}`,
        },
        body: JSON.stringify({ domain_id: domainId }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        toast({ title: 'Verification failed', description: data.error ?? 'Unknown error', variant: 'destructive' });
      } else if (data.verified) {
        toast({ title: 'Domain verified!', description: 'You can now run security assessments.' });
        loadDomains();
      } else {
        toast({ title: 'Not verified yet', description: data.message ?? 'TXT record not found. Wait for DNS propagation.', variant: 'destructive' });
        loadDomains();
      }
    } catch (err) {
      toast({ title: 'Verification error', description: err instanceof Error ? err.message : 'Unknown error', variant: 'destructive' });
    } finally {
      setVerifyingId(null);
    }
  }

  async function handleDelete(domainId: string, domainName: string) {
    const { error } = await supabase.from('domains').delete().eq('id', domainId);
    if (error) {
      toast({ title: 'Failed to delete', description: error.message, variant: 'destructive' });
    } else {
      toast({ title: 'Domain removed', description: `${domainName} has been removed.` });
      loadDomains();
    }
  }

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Assets</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Add and verify the domains you want to assess.
          </p>
        </div>
        <Dialog open={addOpen} onOpenChange={setAddOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="mr-2 h-4 w-4" />
              Add Domain
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Add a domain</DialogTitle>
              <DialogDescription>
                Enter the domain you own and want to assess. We&apos;ll ask you to verify ownership.
              </DialogDescription>
            </DialogHeader>
            <form onSubmit={handleAddDomain} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="domain">Domain name</Label>
                <Input
                  id="domain"
                  placeholder="example.com"
                  value={newDomain}
                  onChange={(e) => setNewDomain(e.target.value)}
                  autoFocus
                />
                <p className="text-xs text-muted-foreground">
                  Enter a domain you own, like yourbusiness.com. Do not include http:// or www.
                </p>
              </div>
              <div className="flex justify-end gap-2">
                <Button type="button" variant="outline" onClick={() => setAddOpen(false)}>
                  Cancel
                </Button>
                <Button type="submit" disabled={adding}>
                  {adding ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Add domain'}
                </Button>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      {domains.length === 0 ? (
        <Card className="border-dashed">
          <CardContent className="flex flex-col items-center justify-center py-16 text-center">
            <Globe className="mb-4 h-12 w-12 text-muted-foreground/50" />
            <h3 className="text-lg font-semibold">No domains yet</h3>
            <p className="mt-1 max-w-sm text-sm text-muted-foreground">
              Add your first domain to start assessing its security. You&apos;ll verify ownership before any checks run.
            </p>
            <Button className="mt-4" onClick={() => setAddOpen(true)}>
              <Plus className="mr-2 h-4 w-4" />
              Add your first domain
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {domains.map((d) => {
            const verif = verifications[d.id];
            const latest = latestAssessments[d.id];
            const isVerified = d.verification_status === 'verified';
            return (
              <Card key={d.id} className="overflow-hidden">
                <CardContent className="p-6">
                  <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                    <div className="flex items-start gap-3">
                      <div className={cn(
                        'mt-0.5 flex h-10 w-10 items-center justify-center rounded-lg',
                        isVerified ? 'bg-success/10' : 'bg-warning/10'
                      )}>
                        {isVerified ? (
                          <ShieldCheck className="h-5 w-5 text-success" />
                        ) : (
                          <Clock className="h-5 w-5 text-warning" />
                        )}
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <h3 className="text-lg font-semibold">{d.domain}</h3>
                          {isVerified ? (
                            <Badge className="bg-success/10 text-success hover:bg-success/10">Verified</Badge>
                          ) : (
                            <Badge variant="secondary" className="bg-warning/10 text-warning hover:bg-warning/10">Pending verification</Badge>
                          )}
                        </div>
                        <p className="mt-0.5 text-xs text-muted-foreground">
                          Added {formatRelativeTime(d.created_at)}
                          {latest && ` · Last assessed ${formatRelativeTime(latest.created_at)}`}
                        </p>
                      </div>
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      {isVerified ? (
                        <>
                          <Link href={`/app/assessments?domain=${d.id}`}>
                            <Button size="sm">
                              <ScanLine className="mr-2 h-4 w-4" />
                              Run Assessment
                            </Button>
                          </Link>
                          {latest && latest.status === 'completed' && (
                            <Link href={`/app/findings?assessment=${latest.id}`}>
                              <Button size="sm" variant="outline">View Findings</Button>
                            </Link>
                          )}
                          <AlertDialog>
                            <AlertDialogTrigger asChild>
                              <Button size="icon" variant="ghost" className="text-muted-foreground hover:text-destructive">
                                <Trash2 className="h-4 w-4" />
                              </Button>
                            </AlertDialogTrigger>
                            <AlertDialogContent>
                              <AlertDialogHeader>
                                <AlertDialogTitle>Remove {d.domain}?</AlertDialogTitle>
                                <AlertDialogDescription>
                                  This will permanently remove the domain and all its assessments, findings, and history. This cannot be undone.
                                </AlertDialogDescription>
                              </AlertDialogHeader>
                              <AlertDialogFooter>
                                <AlertDialogCancel>Cancel</AlertDialogCancel>
                                <AlertDialogAction
                                  className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                                  onClick={() => handleDelete(d.id, d.domain)}
                                >
                                  Remove
                                </AlertDialogAction>
                              </AlertDialogFooter>
                            </AlertDialogContent>
                          </AlertDialog>
                        </>
                      ) : (
                        <>
                          <Button
                            size="sm"
                            onClick={() => handleVerify(d.id)}
                            disabled={verifyingId === d.id}
                          >
                            {verifyingId === d.id ? (
                              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                            ) : (
                              <RefreshCw className="mr-2 h-4 w-4" />
                            )}
                            Verify Now
                          </Button>
                          <AlertDialog>
                            <AlertDialogTrigger asChild>
                              <Button size="icon" variant="ghost" className="text-muted-foreground hover:text-destructive">
                                <Trash2 className="h-4 w-4" />
                              </Button>
                            </AlertDialogTrigger>
                            <AlertDialogContent>
                              <AlertDialogHeader>
                                <AlertDialogTitle>Remove {d.domain}?</AlertDialogTitle>
                                <AlertDialogDescription>
                                  This will remove the domain and its verification record.
                                </AlertDialogDescription>
                              </AlertDialogHeader>
                              <AlertDialogFooter>
                                <AlertDialogCancel>Cancel</AlertDialogCancel>
                                <AlertDialogAction
                                  className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                                  onClick={() => handleDelete(d.id, d.domain)}
                                >
                                  Remove
                                </AlertDialogAction>
                              </AlertDialogFooter>
                            </AlertDialogContent>
                          </AlertDialog>
                        </>
                      )}
                    </div>
                  </div>

                  {!isVerified && verif && (
                    <div className="mt-4 rounded-lg border border-border bg-muted/50 p-4">
                      <h4 className="flex items-center gap-2 text-sm font-semibold">
                        <ShieldCheck className="h-4 w-4 text-primary" />
                        Verify ownership via DNS TXT record
                      </h4>
                      <p className="mt-1 text-sm text-muted-foreground">
                        Add the following TXT record to your domain&apos;s DNS configuration:
                      </p>
                      <div className="mt-3 space-y-2">
                        <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                          <div className="rounded-md bg-background p-2">
                            <p className="text-xs font-medium text-muted-foreground">Type</p>
                            <p className="text-sm font-mono">TXT</p>
                          </div>
                          <div className="rounded-md bg-background p-2">
                            <p className="text-xs font-medium text-muted-foreground">Name / Host</p>
                            <p className="text-sm font-mono">@</p>
                          </div>
                          <div className="rounded-md bg-background p-2">
                            <p className="text-xs font-medium text-muted-foreground">Value</p>
                            <div className="flex items-center gap-1">
                              <p className="truncate text-sm font-mono">secure360-verification={verif.token}</p>
                              <Button
                                size="icon"
                                variant="ghost"
                                className="h-6 w-6 flex-shrink-0"
                                onClick={() => {
                                  navigator.clipboard.writeText(`secure360-verification=${verif.token}`);
                                  toast({ title: 'Copied', description: 'Verification token copied.' });
                                }}
                              >
                                <Copy className="h-3 w-3" />
                              </Button>
                            </div>
                          </div>
                        </div>
                      </div>
                      <div className="mt-3 flex items-start gap-2 rounded-md bg-blue-50 p-3 text-xs text-blue-700 dark:bg-blue-950/30 dark:text-blue-300">
                        <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0" />
                        <p>
                          DNS changes can take a few minutes to propagate. After adding the record, click &quot;Verify Now&quot;.
                          Need help? Check your DNS provider&apos;s documentation.
                        </p>
                      </div>
                      <a
                        href={`https://dns.google/query?name=${d.normalized_domain}&type=TXT`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="mt-2 inline-flex items-center gap-1 text-xs text-primary hover:underline"
                      >
                        Check your DNS records <ExternalLink className="h-3 w-3" />
                      </a>
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

async function sha256(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash), (b) => b.toString(16).padStart(2, '0')).join('');
}
