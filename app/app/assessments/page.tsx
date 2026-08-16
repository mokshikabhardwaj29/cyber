'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { useSearchParams } from 'next/navigation';
import { useAuth } from '@/lib/auth-context';
import { supabase } from '@/lib/supabase';
import type { Domain, Assessment } from '@/lib/types';
import { CHECK_STEPS, scoreLabel, scoreColor } from '@/lib/scanner-types';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { useToast } from '@/hooks/use-toast';
import {
  ScanLine,
  Loader2,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Circle,
  HelpCircle,
  ShieldCheck,
  TrendingUp,
  Clock,
  Play,
  X,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { formatDateTime, formatRelativeTime } from '@/lib/format';
import Link from 'next/link';
import { StatusIcon } from '@/components/severity';

export default function AssessmentsPage() {
  const { organization, user } = useAuth();
  const { toast } = useToast();
  const searchParams = useSearchParams();
  const [domains, setDomains] = useState<Domain[]>([]);
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [selectedDomain, setSelectedDomain] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [starting, setStarting] = useState(false);
  const [activeAssessment, setActiveAssessment] = useState<Assessment | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const loadData = useCallback(async () => {
    if (!organization) return;
    setLoading(true);
    const { data: doms } = await supabase
      .from('domains')
      .select('*')
      .eq('organization_id', organization.id)
      .eq('verification_status', 'verified')
      .order('created_at', { ascending: false });
    setDomains((doms ?? []) as unknown as Domain[]);

    const { data: assess } = await supabase
      .from('assessments')
      .select('*')
      .eq('organization_id', organization.id)
      .order('created_at', { ascending: false })
      .limit(20);
    setAssessments((assess ?? []) as unknown as Assessment[]);

    if (!selectedDomain && (doms ?? []).length > 0) {
      const queryDomain = searchParams.get('domain');
      if (queryDomain && (doms ?? []).some((d) => d.id === queryDomain)) {
        setSelectedDomain(queryDomain);
      } else {
        setSelectedDomain((doms ?? [])[0].id);
      }
    }
    setLoading(false);
  }, [organization, selectedDomain, searchParams]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Check for running assessment and poll
  useEffect(() => {
    if (!organization) return;

    async function checkRunning() {
      const { data } = await supabase
        .from('assessments')
        .select('*')
        .eq('organization_id', organization!.id)
        .in('status', ['queued', 'running'])
        .order('created_at', { ascending: false })
        .limit(1)
        .maybeSingle();
      if (data) {
        setActiveAssessment(data as unknown as Assessment);
      }
    }

    checkRunning();

    const channel = supabase
      .channel('assessments-realtime')
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'assessments', filter: `organization_id=eq.${organization.id}` },
        (payload) => {
          const newAssess = payload.new as Assessment;
          if (newAssess.status === 'running' || newAssess.status === 'queued') {
            setActiveAssessment(newAssess);
          } else {
            setActiveAssessment((prev) => {
              if (prev && prev.id === newAssess.id) {
                return newAssess;
              }
              return prev;
            });
            loadData();
          }
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, [organization, loadData]);

  // Poll active assessment for progress updates
  useEffect(() => {
    if (activeAssessment && (activeAssessment.status === 'running' || activeAssessment.status === 'queued')) {
      if (pollRef.current) clearInterval(pollRef.current);
      pollRef.current = setInterval(async () => {
        const { data } = await supabase
          .from('assessments')
          .select('*')
          .eq('id', activeAssessment.id)
          .maybeSingle();
        if (data) {
          const updated = data as unknown as Assessment;
          setActiveAssessment(updated);
          if (updated.status === 'completed' || updated.status === 'failed' || updated.status === 'cancelled') {
            if (pollRef.current) {
              clearInterval(pollRef.current);
              pollRef.current = null;
            }
            loadData();
            if (updated.status === 'completed') {
              toast({
                title: 'Assessment complete',
                description: `Score: ${updated.score}/100 (${updated.score_label}).`,
              });
            }
          }
        }
      }, 2000);
    }
    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    };
  }, [activeAssessment?.id, activeAssessment?.status, loadData, toast]);

  async function startAssessment() {
    if (!organization || !user || !selectedDomain) return;
    setStarting(true);
    try {
      const { data: assess, error } = await supabase
        .from('assessments')
        .insert({
          organization_id: organization.id,
          domain_id: selectedDomain,
          created_by: user.id,
          status: 'queued',
        })
        .select()
        .single();

      if (error) throw error;

      // Call the edge function to run the assessment
      const session = await supabase.auth.getSession();
      const resp = await fetch(`${process.env.NEXT_PUBLIC_SUPABASE_URL}/functions/v1/secure360-assess`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.data.session?.access_token}`,
        },
        body: JSON.stringify({ domain_id: selectedDomain, assessment_id: assess.id }),
      });

      if (!resp.ok) {
        const errData = await resp.json();
        throw new Error(errData.error ?? 'Assessment failed to start');
      }

      setActiveAssessment(assess as unknown as Assessment);
      toast({ title: 'Assessment started', description: 'Running security checks...' });
    } catch (err) {
      toast({ title: 'Failed to start', description: err instanceof Error ? err.message : 'Unknown error', variant: 'destructive' });
    } finally {
      setStarting(false);
    }
  }

  async function cancelAssessment() {
    if (!activeAssessment || !organization) return;
    await supabase
      .from('assessments')
      .update({ status: 'cancelled', completed_at: new Date().toISOString() })
      .eq('id', activeAssessment.id);
    setActiveAssessment(null);
    toast({ title: 'Assessment cancelled' });
    loadData();
  }

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  if (domains.length === 0) {
    return (
      <div className="mx-auto max-w-5xl">
        <h1 className="text-2xl font-bold">Assessments</h1>
        <Card className="mt-6 border-dashed">
          <CardContent className="flex flex-col items-center justify-center py-16 text-center">
            <ScanLine className="mb-4 h-12 w-12 text-muted-foreground/50" />
            <h3 className="text-lg font-semibold">No verified domains yet</h3>
            <p className="mt-1 max-w-sm text-sm text-muted-foreground">
              Add and verify a domain before you can run a security assessment.
            </p>
            <Link href="/app/assets">
              <Button className="mt-4">Go to Assets</Button>
            </Link>
          </CardContent>
        </Card>
      </div>
    );
  }

  const isRunning = activeAssessment && (activeAssessment.status === 'running' || activeAssessment.status === 'queued');
  const progressPct = activeAssessment
    ? Math.round((activeAssessment.steps_completed.length / activeAssessment.steps_total) * 100)
    : 0;

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Assessments</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Run a safe, passive security assessment on your verified domain.
        </p>
      </div>

      {/* Start new assessment */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Start a new assessment</CardTitle>
          <CardDescription>
            Select a verified domain and run all six security checks.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col gap-4 sm:flex-row sm:items-end">
            <div className="flex-1 space-y-2">
              <label className="text-sm font-medium">Domain</label>
              <Select value={selectedDomain} onValueChange={setSelectedDomain} disabled={!!isRunning}>
                <SelectTrigger>
                  <SelectValue placeholder="Select a domain" />
                </SelectTrigger>
                <SelectContent>
                  {domains.map((d) => (
                    <SelectItem key={d.id} value={d.id}>
                      {d.domain}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <Button onClick={startAssessment} disabled={!!isRunning || starting}>
              {starting ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Play className="mr-2 h-4 w-4" />
              )}
              {isRunning ? 'Assessment running...' : 'Start Assessment'}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Live progress */}
      {activeAssessment && (
        <Card className="animate-fade-in">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="flex items-center gap-2 text-lg">
                  {isRunning ? (
                    <Loader2 className="h-5 w-5 animate-spin text-primary" />
                  ) : activeAssessment.status === 'completed' ? (
                    <CheckCircle2 className="h-5 w-5 text-success" />
                  ) : activeAssessment.status === 'failed' ? (
                    <XCircle className="h-5 w-5 text-danger" />
                  ) : (
                    <XCircle className="h-5 w-5 text-muted-foreground" />
                  )}
                  Assessment {activeAssessment.status}
                </CardTitle>
                <CardDescription className="mt-1">
                  {formatDateTime(activeAssessment.created_at)}
                </CardDescription>
              </div>
              {isRunning && (
                <Button variant="outline" size="sm" onClick={cancelAssessment}>
                  <X className="mr-2 h-4 w-4" />
                  Cancel
                </Button>
              )}
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <div className="mb-2 flex items-center justify-between text-sm">
                <span className="font-medium">
                  {activeAssessment.steps_completed.length} of {activeAssessment.steps_total} checks complete
                </span>
                <span className="text-muted-foreground">{progressPct}%</span>
              </div>
              <Progress value={progressPct} className="h-2" />
            </div>

            <div className="space-y-2">
              {CHECK_STEPS.map((step) => {
                const stepStatus = activeAssessment.progress[step.id];
                const isCurrent = activeAssessment.current_step === step.label;
                return (
                  <div
                    key={step.id}
                    className={cn(
                      'flex items-center gap-3 rounded-lg border p-3 transition-colors',
                      isCurrent && 'border-primary bg-primary/5',
                      !stepStatus && 'border-border opacity-60'
                    )}
                  >
                    {stepStatus === 'pass' ? (
                      <CheckCircle2 className="h-5 w-5 text-success" />
                    ) : stepStatus === 'warn' ? (
                      <AlertTriangle className="h-5 w-5 text-warning" />
                    ) : stepStatus === 'fail' ? (
                      <XCircle className="h-5 w-5 text-danger" />
                    ) : stepStatus === 'error' ? (
                      <HelpCircle className="h-5 w-5 text-muted-foreground" />
                    ) : isCurrent ? (
                      <Loader2 className="h-5 w-5 animate-spin text-primary" />
                    ) : (
                      <Circle className="h-5 w-5 text-muted-foreground/40" />
                    )}
                    <span className={cn('text-sm', isCurrent && 'font-medium')}>
                      {step.label}
                    </span>
                    {stepStatus && stepStatus !== 'running' && (
                      <Badge variant="outline" className="ml-auto text-xs">
                        {stepStatus}
                      </Badge>
                    )}
                  </div>
                );
              })}
            </div>

            {activeAssessment.status === 'completed' && activeAssessment.score != null && (
              <div className="flex items-center justify-between rounded-lg border border-border bg-muted/50 p-4">
                <div className="flex items-center gap-3">
                  <ShieldCheck className={cn('h-8 w-8', `text-${scoreColor(activeAssessment.score)}`)} />
                  <div>
                    <p className="text-2xl font-bold">{activeAssessment.score}/100</p>
                    <p className="text-sm text-muted-foreground">{activeAssessment.score_label}</p>
                  </div>
                </div>
                <Link href={`/app/findings?assessment=${activeAssessment.id}`}>
                  <Button>View Findings</Button>
                </Link>
              </div>
            )}

            {activeAssessment.status === 'failed' && (
              <div className="rounded-lg border border-danger/30 bg-danger/5 p-4 text-sm text-danger">
                Assessment failed. This may be due to a network timeout or the domain being unreachable. Try again later.
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Assessment history */}
      <div>
        <h2 className="mb-3 text-lg font-semibold">Assessment History</h2>
        {assessments.length === 0 ? (
          <Card className="border-dashed">
            <CardContent className="flex flex-col items-center justify-center py-12 text-center">
              <Clock className="mb-3 h-10 w-10 text-muted-foreground/50" />
              <p className="text-sm text-muted-foreground">No assessments yet. Start your first one above.</p>
            </CardContent>
          </Card>
        ) : (
          <div className="space-y-2">
            {assessments.map((a) => {
              const domain = domains.find((d) => d.id === a.domain_id);
              return (
                <Card key={a.id} className="hover:shadow-md transition-shadow">
                  <CardContent className="flex items-center justify-between p-4">
                    <div className="flex items-center gap-3">
                      {a.status === 'completed' ? (
                        <ShieldCheck className={cn('h-8 w-8', `text-${scoreColor(a.score ?? 0)}`)} />
                      ) : a.status === 'running' ? (
                        <Loader2 className="h-8 w-8 animate-spin text-primary" />
                      ) : a.status === 'failed' ? (
                        <XCircle className="h-8 w-8 text-danger" />
                      ) : (
                        <Circle className="h-8 w-8 text-muted-foreground" />
                      )}
                      <div>
                        <p className="font-medium">{domain?.domain ?? 'Unknown domain'}</p>
                        <p className="text-xs text-muted-foreground">
                          {formatRelativeTime(a.created_at)} · {a.status}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      {a.score != null && (
                        <div className="text-right">
                          <p className={cn('text-lg font-bold', `text-${scoreColor(a.score)}`)}>{a.score}/100</p>
                          <p className="text-xs text-muted-foreground">{a.score_label}</p>
                        </div>
                      )}
                      {a.status === 'completed' && (
                        <Link href={`/app/findings?assessment=${a.id}`}>
                          <Button variant="outline" size="sm">View</Button>
                        </Link>
                      )}
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
