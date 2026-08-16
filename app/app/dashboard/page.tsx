'use client';

import { useEffect, useState, useCallback } from 'react';
import { useAuth } from '@/lib/auth-context';
import { supabase } from '@/lib/supabase';
import type { Domain, Assessment, Finding, ScoreHistoryEntry } from '@/lib/types';
import { scoreLabel, scoreColor } from '@/lib/scanner-types';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { SeverityBadge, SeverityDot } from '@/components/severity';
import {
  ShieldCheck,
  AlertTriangle,
  Globe,
  TrendingUp,
  Loader2,
  ArrowRight,
  Clock,
  CheckCircle2,
  Zap,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { formatRelativeTime } from '@/lib/format';
import Link from 'next/link';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ReferenceLine,
} from 'recharts';

interface DashboardData {
  domains: Domain[];
  latestAssessment: Assessment | null;
  latestDomain: Domain | null;
  findings: Finding[];
  scoreHistory: ScoreHistoryEntry[];
}

export default function DashboardPage() {
  const { organization } = useAuth();
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);

  const loadDashboard = useCallback(async () => {
    if (!organization) return;
    setLoading(true);

    const { data: domains } = await supabase
      .from('domains')
      .select('*')
      .eq('organization_id', organization.id)
      .eq('verification_status', 'verified')
      .order('created_at', { ascending: false });

    const { data: assessments } = await supabase
      .from('assessments')
      .select('*')
      .eq('organization_id', organization.id)
      .eq('status', 'completed')
      .order('completed_at', { ascending: false })
      .limit(1);

    const latestAssessment = (assessments?.[0] as unknown as Assessment) ?? null;
    const latestDomain = latestAssessment
      ? (domains ?? []).find((d) => d.id === latestAssessment.domain_id) ?? null
      : null;

    let findings: Finding[] = [];
    if (latestAssessment) {
      const { data: f } = await supabase
        .from('findings')
        .select('*')
        .eq('assessment_id', latestAssessment.id)
        .neq('status', 'resolved')
        .order('severity', { ascending: false });
      findings = (f ?? []) as unknown as Finding[];
    }

    let scoreHistory: ScoreHistoryEntry[] = [];
    if (latestDomain) {
      const { data: sh } = await supabase
        .from('score_history')
        .select('*')
        .eq('domain_id', latestDomain.id)
        .order('recorded_at', { ascending: true })
        .limit(12);
      scoreHistory = (sh ?? []) as unknown as ScoreHistoryEntry[];
    }

    setData({
      domains: (domains ?? []) as unknown as Domain[],
      latestAssessment,
      latestDomain,
      findings,
      scoreHistory,
    });
    setLoading(false);
  }, [organization]);

  useEffect(() => {
    loadDashboard();

    if (!organization) return;
    const channel = supabase
      .channel('dashboard-realtime')
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'assessments', filter: `organization_id=eq.${organization.id}` },
        () => loadDashboard()
      )
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'findings', filter: `organization_id=eq.${organization.id}` },
        () => loadDashboard()
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, [organization, loadDashboard]);

  if (loading || !data) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  const { domains, latestAssessment, latestDomain, findings, scoreHistory } = data;

  // No domains
  if (domains.length === 0) {
    return (
      <div className="mx-auto max-w-5xl">
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <Card className="mt-6 border-dashed">
          <CardContent className="flex flex-col items-center justify-center py-16 text-center">
            <Globe className="mb-4 h-12 w-12 text-muted-foreground/50" />
            <h3 className="text-lg font-semibold">Welcome to Secure360</h3>
            <p className="mt-1 max-w-sm text-sm text-muted-foreground">
              Add and verify your first domain to start assessing your security.
            </p>
            <Link href="/app/assets">
              <Button className="mt-4">
                <Globe className="mr-2 h-4 w-4" />
                Add your first domain
              </Button>
            </Link>
          </CardContent>
        </Card>
      </div>
    );
  }

  // No assessments yet
  if (!latestAssessment || !latestDomain) {
    return (
      <div className="mx-auto max-w-5xl space-y-6">
        <div>
          <h1 className="text-2xl font-bold">Dashboard</h1>
          <p className="mt-1 text-sm text-muted-foreground">Welcome to {organization?.name}.</p>
        </div>
        <Card className="border-dashed">
          <CardContent className="flex flex-col items-center justify-center py-16 text-center">
            <ShieldCheck className="mb-4 h-12 w-12 text-primary/50" />
            <h3 className="text-lg font-semibold">No assessments yet</h3>
            <p className="mt-1 max-w-sm text-sm text-muted-foreground">
              You have {domains.length} verified {domains.length === 1 ? 'domain' : 'domains'}. Run your first assessment to see your security score.
            </p>
            <Link href="/app/assessments">
              <Button className="mt-4">
                <Zap className="mr-2 h-4 w-4" />
                Run your first assessment
              </Button>
            </Link>
          </CardContent>
        </Card>
      </div>
    );
  }

  const score = latestAssessment.score ?? 0;
  const color = scoreColor(score);
  const label = latestAssessment.score_label ?? scoreLabel(score);

  const counts = {
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
  };

  // Fix these first: sort by severity, then effort
  const fixFirst = [...findings]
    .sort((a, b) => {
      const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
      return sevOrder[a.severity] - sevOrder[b.severity];
    })
    .slice(0, 5);

  // Score history chart data
  const chartData = scoreHistory.map((s, i) => ({
    name: new Date(s.recorded_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
    score: s.score,
    index: i + 1,
  }));

  // Score improvement
  const firstScore = scoreHistory[0]?.score ?? null;
  const currentScore = scoreHistory[scoreHistory.length - 1]?.score ?? null;
  const improvement = firstScore != null && currentScore != null ? currentScore - firstScore : null;

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {organization?.name} · Last assessed {formatRelativeTime(latestAssessment.completed_at ?? latestAssessment.created_at)}
        </p>
      </div>

      {/* Top row: score + summary */}
      <div className="grid gap-4 md:grid-cols-3">
        {/* Security Score */}
        <Card className="md:col-span-1">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
              <ShieldCheck className="h-4 w-4" />
              Security Score
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col items-center">
              <div className={cn('relative flex h-32 w-32 items-center justify-center rounded-full', `border-4 border-${color}`)}>
                <div className="text-center">
                  <span className={cn('text-3xl font-bold', `text-${color}`)}>{score}</span>
                  <span className="block text-xs text-muted-foreground">/ 100</span>
                </div>
              </div>
              <p className={cn('mt-3 text-sm font-semibold', `text-${color}`)}>{label}</p>
              <p className="mt-1 text-center text-xs text-muted-foreground">
                {score >= 75 ? 'Your security looks good.' : 'Improvements are recommended.'}
              </p>
            </div>
          </CardContent>
        </Card>

        {/* Findings summary */}
        <Card className="md:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
              <AlertTriangle className="h-4 w-4" />
              Open Findings
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
              <FindingCount label="Critical" count={counts.critical} color="red" />
              <FindingCount label="High" count={counts.high} color="orange" />
              <FindingCount label="Medium" count={counts.medium} color="amber" />
              <FindingCount label="Low" count={counts.low} color="blue" />
            </div>
            <div className="mt-4 flex items-center gap-4 border-t border-border pt-4">
              <div className="flex items-center gap-2">
                <Globe className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm">
                  {domains.length} {domains.length === 1 ? 'Website' : 'Websites'}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <Clock className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm">
                  {latestDomain.domain}
                </span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Fix These First */}
      {fixFirst.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <Zap className="h-5 w-5 text-warning" />
              Fix These First
            </CardTitle>
            <CardDescription>Priority actions to improve your security score</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {fixFirst.map((f) => (
              <Link
                key={f.id}
                href={`/app/findings/${f.id}`}
                className="flex items-center justify-between rounded-lg border border-border p-3 transition-colors hover:bg-muted/50"
              >
                <div className="flex items-center gap-3">
                  <SeverityDot severity={f.severity} />
                  <div>
                    <p className="text-sm font-medium">{f.title}</p>
                    <p className="text-xs text-muted-foreground">{f.asset}</p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  {f.effort_minutes != null && (
                    <span className="text-xs text-muted-foreground">
                      ~{f.effort_minutes} min
                    </span>
                  )}
                  <ArrowRight className="h-4 w-4 text-muted-foreground" />
                </div>
              </Link>
            ))}
          </CardContent>
        </Card>
      )}

      {fixFirst.length === 0 && (
        <Card className="border-success/30 bg-success/5">
          <CardContent className="flex items-center gap-4 p-6">
            <CheckCircle2 className="h-10 w-10 text-success" />
            <div>
              <p className="font-semibold text-success">All clear!</p>
              <p className="text-sm text-muted-foreground">
                No open findings from your last assessment. Great work keeping your site secure.
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Score history */}
      {chartData.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <TrendingUp className="h-5 w-5 text-primary" />
              Score History
            </CardTitle>
            {improvement != null && improvement !== 0 && (
              <CardDescription>
                Your security score {improvement > 0 ? 'improved' : 'changed'} by {Math.abs(improvement)} {Math.abs(improvement) === 1 ? 'point' : 'points'}.
              </CardDescription>
            )}
          </CardHeader>
          <CardContent>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={chartData} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-border" />
                  <XAxis dataKey="name" tick={{ fontSize: 12 }} className="text-muted-foreground" />
                  <YAxis domain={[0, 100]} tick={{ fontSize: 12 }} className="text-muted-foreground" />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'hsl(var(--popover))',
                      border: '1px solid hsl(var(--border))',
                      borderRadius: '8px',
                      fontSize: '12px',
                    }}
                  />
                  <ReferenceLine y={75} stroke="hsl(var(--success))" strokeDasharray="5 5" label={{ value: 'Good', fontSize: 10, fill: 'hsl(var(--success))' }} />
                  <Line
                    type="monotone"
                    dataKey="score"
                    stroke="hsl(var(--primary))"
                    strokeWidth={3}
                    dot={{ fill: 'hsl(var(--primary))', r: 5 }}
                    activeDot={{ r: 7 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Quick actions */}
      <div className="grid gap-4 md:grid-cols-3">
        <Link href="/app/assessments">
          <Card className="cursor-pointer transition-shadow hover:shadow-md">
            <CardContent className="flex items-center gap-3 p-4">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                <Zap className="h-5 w-5 text-primary" />
              </div>
              <div>
                <p className="text-sm font-medium">Run new assessment</p>
                <p className="text-xs text-muted-foreground">Check your security again</p>
              </div>
            </CardContent>
          </Card>
        </Link>
        <Link href="/app/findings">
          <Card className="cursor-pointer transition-shadow hover:shadow-md">
            <CardContent className="flex items-center gap-3 p-4">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-warning/10">
                <AlertTriangle className="h-5 w-5 text-warning" />
              </div>
              <div>
                <p className="text-sm font-medium">View all findings</p>
                <p className="text-xs text-muted-foreground">{findings.length} open {findings.length === 1 ? 'item' : 'items'}</p>
              </div>
            </CardContent>
          </Card>
        </Link>
        <Link href="/app/security-plan">
          <Card className="cursor-pointer transition-shadow hover:shadow-md">
            <CardContent className="flex items-center gap-3 p-4">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-success/10">
                <CheckCircle2 className="h-5 w-5 text-success" />
              </div>
              <div>
                <p className="text-sm font-medium">My security plan</p>
                <p className="text-xs text-muted-foreground">Your action checklist</p>
              </div>
            </CardContent>
          </Card>
        </Link>
      </div>
    </div>
  );
}

function FindingCount({ label, count, color }: { label: string; count: number; color: string }) {
  return (
    <div className="flex flex-col items-center rounded-lg border border-border p-3">
      <span className={cn('text-2xl font-bold', `text-${color === 'red' ? 'danger' : color === 'orange' ? 'warning' : color === 'amber' ? 'warning' : 'primary'}`)}>
        {count}
      </span>
      <span className="text-xs text-muted-foreground">{label}</span>
    </div>
  );
}
