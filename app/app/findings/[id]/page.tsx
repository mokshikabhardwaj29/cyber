'use client';

import { useState, useEffect, useCallback } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth-context';
import { supabase } from '@/lib/supabase';
import type { FindingWithGuide } from '@/lib/types';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
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
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from '@/components/ui/accordion';
import { SeverityBadge, FindingStatusBadge, ConfidenceBadge } from '@/components/severity';
import { useToast } from '@/hooks/use-toast';
import {
  ArrowLeft,
  Loader2,
  CheckCircle2,
  AlertTriangle,
  Wrench,
  ShieldCheck,
  Clock,
  TrendingUp,
  ChevronDown,
  ChevronUp,
  ExternalLink,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import Link from 'next/link';
import { formatDateTime } from '@/lib/format';

export default function FindingDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const { organization } = useAuth();
  const { toast } = useToast();
  const [finding, setFinding] = useState<FindingWithGuide | null>(null);
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<{ resolved: boolean; message: string; new_score?: number } | null>(null);
  const [showTechnical, setShowTechnical] = useState(false);
  const [updatingStatus, setUpdatingStatus] = useState(false);

  const loadFinding = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    const { data } = await supabase
      .from('findings')
      .select(`
        *,
        remediation_guide:remediation_guides!findings_remediation_id_fkey(*),
        security_rule:security_rules!findings_rule_id_fkey(*)
      `)
      .eq('id', id)
      .maybeSingle();
    setFinding(data as unknown as FindingWithGuide | null);
    setLoading(false);
  }, [id]);

  useEffect(() => {
    loadFinding();
  }, [loadFinding]);

  async function handleVerifyFix() {
    if (!finding) return;
    setVerifying(true);
    setVerifyResult(null);
    try {
      const session = await supabase.auth.getSession();
      const resp = await fetch(`${process.env.NEXT_PUBLIC_SUPABASE_URL}/functions/v1/secure360-verify-fix`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.data.session?.access_token}`,
        },
        body: JSON.stringify({ finding_id: finding.id }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error ?? 'Verification failed');
      }
      setVerifyResult({ resolved: data.resolved, message: data.message, new_score: data.new_score });
      if (data.resolved) {
        toast({
          title: 'Fix verified!',
          description: `Your security score is now ${data.new_score}/100.`,
        });
        loadFinding();
      } else {
        toast({
          title: 'Issue still detected',
          description: data.message,
          variant: 'destructive',
        });
      }
    } catch (err) {
      toast({ title: 'Verification failed', description: err instanceof Error ? err.message : 'Unknown error', variant: 'destructive' });
    } finally {
      setVerifying(false);
    }
  }

  async function updateStatus(status: 'open' | 'in_progress' | 'accepted_risk') {
    if (!finding || !organization) return;
    setUpdatingStatus(true);
    const { error } = await supabase
      .from('findings')
      .update({ status, updated_at: new Date().toISOString() })
      .eq('id', finding.id);
    if (error) {
      toast({ title: 'Failed to update', description: error.message, variant: 'destructive' });
    } else {
      toast({ title: 'Status updated', description: `Finding marked as ${status.replace('_', ' ')}.` });
      loadFinding();
    }
    setUpdatingStatus(false);
  }

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  if (!finding) {
    return (
      <div className="mx-auto max-w-3xl">
        <p className="text-muted-foreground">Finding not found.</p>
        <Link href="/app/findings">
          <Button variant="outline" className="mt-4">Back to Findings</Button>
        </Link>
      </div>
    );
  }

  const guide = finding.remediation_guide;
  const rule = finding.security_rule;
  const isResolved = finding.status === 'resolved';

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div>
        <Link href="/app/findings" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
          <ArrowLeft className="h-4 w-4" />
          Back to Findings
        </Link>
      </div>

      {/* Header */}
      <Card>
        <CardContent className="p-6">
          <div className="flex items-start justify-between gap-4">
            <div className="space-y-2">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={finding.severity} />
                <FindingStatusBadge status={finding.status} />
                <Badge variant="outline">{finding.category}</Badge>
              </div>
              <h1 className="text-xl font-bold">{finding.title}</h1>
              <p className="text-sm text-muted-foreground">
                Affected asset: <span className="font-medium text-foreground">{finding.asset}</span>
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Verify result banner */}
      {verifyResult && (
        <Card className={cn('animate-fade-in', verifyResult.resolved ? 'border-success/30 bg-success/5' : 'border-warning/30 bg-warning/5')}>
          <CardContent className="flex items-center gap-3 p-4">
            {verifyResult.resolved ? (
              <CheckCircle2 className="h-6 w-6 text-success" />
            ) : (
              <AlertTriangle className="h-6 w-6 text-warning" />
            )}
            <div>
              <p className={cn('font-medium', verifyResult.resolved ? 'text-success' : 'text-warning')}>
                {verifyResult.resolved ? 'Fix verified' : 'Not resolved yet'}
              </p>
              <p className="text-sm text-muted-foreground">{verifyResult.message}</p>
              {verifyResult.new_score != null && (
                <p className="mt-1 flex items-center gap-1 text-sm">
                  <TrendingUp className="h-4 w-4 text-success" />
                  Security score updated to {verifyResult.new_score}/100
                </p>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Why it matters */}
      {guide && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Why it matters</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">{guide.why_it_matters}</p>
            <div className="mt-4 flex flex-wrap gap-4 text-sm">
              <div className="flex items-center gap-1.5">
                <Clock className="h-4 w-4 text-muted-foreground" />
                <span>Estimated: {finding.effort_minutes ?? guide.effort_minutes} min</span>
              </div>
              <div className="flex items-center gap-1.5">
                <Wrench className="h-4 w-4 text-muted-foreground" />
                <span>Difficulty: {finding.difficulty ?? guide.difficulty}</span>
              </div>
              <div className="flex items-center gap-1.5">
                <ShieldCheck className="h-4 w-4 text-muted-foreground" />
                <ConfidenceBadge confidence={finding.confidence} />
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Recommended action + steps */}
      {guide && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">How to fix</CardTitle>
            <CardDescription>{guide.recommended_action}</CardDescription>
          </CardHeader>
          <CardContent>
            <ol className="space-y-3">
              {(guide.steps as string[]).map((step, i) => (
                <li key={i} className="flex items-start gap-3">
                  <span className="flex h-6 w-6 flex-shrink-0 items-center justify-center rounded-full bg-primary/10 text-xs font-semibold text-primary">
                    {i + 1}
                  </span>
                  <span className="text-sm">{step}</span>
                </li>
              ))}
            </ol>
          </CardContent>
        </Card>
      )}

      {/* Actions */}
      {!isResolved && (
        <Card>
          <CardContent className="flex flex-wrap items-center gap-3 p-4">
            <Button onClick={handleVerifyFix} disabled={verifying}>
              {verifying ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <ShieldCheck className="mr-2 h-4 w-4" />
              )}
              Verify Fix
            </Button>
            {finding.status !== 'in_progress' && (
              <Button variant="outline" onClick={() => updateStatus('in_progress')} disabled={updatingStatus}>
                Mark as In Progress
              </Button>
            )}
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button variant="ghost" disabled={updatingStatus}>
                  Accept Risk
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>Accept this risk?</AlertDialogTitle>
                  <AlertDialogDescription>
                    You acknowledge this finding and accept the risk. It will be excluded from your security score but remains visible in your findings.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                  <AlertDialogAction onClick={() => updateStatus('accepted_risk')}>
                    Accept Risk
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </CardContent>
        </Card>
      )}

      {isResolved && (
        <Card className="border-success/30 bg-success/5">
          <CardContent className="flex items-center gap-3 p-4">
            <CheckCircle2 className="h-6 w-6 text-success" />
            <div>
              <p className="font-medium text-success">Issue resolved</p>
              <p className="text-sm text-muted-foreground">
                This finding was verified as resolved on {finding.resolved_at ? formatDateTime(finding.resolved_at) : 'N/A'}.
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Technical details */}
      <Card>
        <CardHeader>
          <button
            onClick={() => setShowTechnical((v) => !v)}
            className="flex items-center justify-between text-left"
          >
            <CardTitle className="text-base">Technical Details</CardTitle>
            {showTechnical ? <ChevronUp className="h-5 w-5" /> : <ChevronDown className="h-5 w-5" />}
          </button>
          <CardDescription>Advanced information for your website administrator</CardDescription>
        </CardHeader>
        {showTechnical && (
          <CardContent>
            <div className="space-y-3">
              <div>
                <p className="text-xs font-medium text-muted-foreground">Rule ID</p>
                <p className="font-mono text-sm">{finding.rule_id}</p>
              </div>
              <div>
                <p className="text-xs font-medium text-muted-foreground">Evidence</p>
                <pre className="mt-1 overflow-x-auto rounded-lg bg-muted p-3 text-xs">
                  {JSON.stringify(finding.evidence, null, 2)}
                </pre>
              </div>
              {rule && (
                <div>
                  <p className="text-xs font-medium text-muted-foreground">Rule Definition</p>
                  <pre className="mt-1 overflow-x-auto rounded-lg bg-muted p-3 text-xs">
                    {JSON.stringify(rule, null, 2)}
                  </pre>
                </div>
              )}
              <div>
                <p className="text-xs font-medium text-muted-foreground">Discovered</p>
                <p className="text-sm">{formatDateTime(finding.created_at)}</p>
              </div>
            </div>
          </CardContent>
        )}
      </Card>
    </div>
  );
}
