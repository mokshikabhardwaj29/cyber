'use client';

import { useState, useEffect, useCallback } from 'react';
import { useAuth } from '@/lib/auth-context';
import { supabase } from '@/lib/supabase';
import type { Assessment, Domain, AssessmentResult, Finding, RemediationGuide } from '@/lib/types';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { SeverityBadge, StatusIcon } from '@/components/severity';
import { useToast } from '@/hooks/use-toast';
import {
  Loader2,
  FileText,
  Download,
  Printer,
  ShieldCheck,
} from 'lucide-react';
import { scoreColor } from '@/lib/scanner-types';
import { formatDateTime, formatDate } from '@/lib/format';
import { cn } from '@/lib/utils';

export default function ReportsPage() {
  const { organization } = useAuth();
  const { toast } = useToast();
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [selectedId, setSelectedId] = useState<string>('');
  const [reportData, setReportData] = useState<{
    assessment: Assessment;
    domain: Domain;
    results: AssessmentResult[];
    findings: (Finding & { remediation_guide?: RemediationGuide | null })[];
  } | null>(null);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);

  const loadAssessments = useCallback(async () => {
    if (!organization) return;
    const { data } = await supabase
      .from('assessments')
      .select('*')
      .eq('organization_id', organization.id)
      .eq('status', 'completed')
      .order('completed_at', { ascending: false });
    setAssessments((data ?? []) as unknown as Assessment[]);
    if ((data ?? []).length > 0 && !selectedId) {
      setSelectedId((data ?? [])[0].id);
    }
    setLoading(false);
  }, [organization, selectedId]);

  useEffect(() => {
    loadAssessments();
  }, [loadAssessments]);

  useEffect(() => {
    async function loadReport() {
      if (!selectedId || !organization) return;
      const { data: assess } = await supabase
        .from('assessments')
        .select('*')
        .eq('id', selectedId)
        .maybeSingle();
      if (!assess) return;

      const { data: domain } = await supabase
        .from('domains')
        .select('*')
        .eq('id', (assess as Assessment).domain_id)
        .maybeSingle();

      const { data: results } = await supabase
        .from('assessment_results')
        .select('*')
        .eq('assessment_id', selectedId)
        .order('observed_at', { ascending: true });

      const { data: findings } = await supabase
        .from('findings')
        .select(`
          *,
          remediation_guide:remediation_guides!findings_remediation_id_fkey(*)
        `)
        .eq('assessment_id', selectedId)
        .order('severity', { ascending: false });

      setReportData({
        assessment: assess as unknown as Assessment,
        domain: domain as unknown as Domain,
        results: (results ?? []) as unknown as AssessmentResult[],
        findings: (findings ?? []) as unknown as (Finding & { remediation_guide?: RemediationGuide | null })[],
      });
    }
    loadReport();
  }, [selectedId, organization]);

  function handlePrint() {
    setGenerating(true);
    setTimeout(() => {
      window.print();
      setGenerating(false);
    }, 300);
  }

  function handleDownload() {
    toast({ title: 'Preparing PDF', description: 'Use your browser\'s print dialog to save as PDF.' });
    setTimeout(() => window.print(), 300);
  }

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  if (assessments.length === 0) {
    return (
      <div className="mx-auto max-w-4xl">
        <h1 className="text-2xl font-bold">Reports</h1>
        <Card className="mt-6 border-dashed">
          <CardContent className="flex flex-col items-center justify-center py-16 text-center">
            <FileText className="mb-4 h-12 w-12 text-muted-foreground/50" />
            <h3 className="text-lg font-semibold">No reports yet</h3>
            <p className="mt-1 max-w-sm text-sm text-muted-foreground">
              Complete an assessment to generate a security report.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  const { assessment, domain, results, findings } = reportData ?? {};

  const findingCounts = {
    critical: findings?.filter((f) => f.severity === 'critical').length ?? 0,
    high: findings?.filter((f) => f.severity === 'high').length ?? 0,
    medium: findings?.filter((f) => f.severity === 'medium').length ?? 0,
    low: findings?.filter((f) => f.severity === 'low').length ?? 0,
  };

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      {/* Controls - hidden in print */}
      <div className="no-print">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold">Reports</h1>
            <p className="mt-1 text-sm text-muted-foreground">Generate a printable security report.</p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" onClick={handleDownload}>
              <Download className="mr-2 h-4 w-4" />
              Download PDF
            </Button>
            <Button onClick={handlePrint} disabled={generating}>
              {generating ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Printer className="mr-2 h-4 w-4" />}
              Print
            </Button>
          </div>
        </div>

        <div className="mt-4">
          <Select value={selectedId} onValueChange={setSelectedId}>
            <SelectTrigger className="w-full max-w-md">
              <SelectValue placeholder="Select an assessment" />
            </SelectTrigger>
            <SelectContent>
              {assessments.map((a) => (
                <SelectItem key={a.id} value={a.id}>
                  Score {a.score}/100 - {formatDate(a.completed_at ?? a.created_at)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {/* Report */}
      {assessment && domain && (
        <Card className="print-full">
          <CardContent className="p-8">
            {/* Report header */}
            <div className="border-b border-border pb-6">
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="h-6 w-6 text-primary" />
                    <span className="text-lg font-bold">Secure360 SMB</span>
                  </div>
                  <h2 className="mt-3 text-2xl font-bold">Security Assessment Report</h2>
                  <p className="mt-1 text-sm text-muted-foreground">
                    {organization?.name} · {domain.domain}
                  </p>
                </div>
                <div className="text-right">
                  <div className={cn('text-4xl font-bold', `text-${scoreColor(assessment.score ?? 0)}`)}>
                    {assessment.score}/100
                  </div>
                  <p className="text-sm text-muted-foreground">{assessment.score_label}</p>
                </div>
              </div>
              <div className="mt-4 grid grid-cols-2 gap-4 text-sm md:grid-cols-4">
                <div>
                  <p className="text-xs text-muted-foreground">Business</p>
                  <p className="font-medium">{organization?.name}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Domain</p>
                  <p className="font-medium">{domain.domain}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Assessment Date</p>
                  <p className="font-medium">{formatDateTime(assessment.completed_at ?? assessment.created_at)}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Risk Level</p>
                  <p className="font-medium capitalize">{assessment.risk_level}</p>
                </div>
              </div>
            </div>

            {/* Finding summary */}
            <div className="mt-6">
              <h3 className="mb-3 text-lg font-semibold">Finding Summary</h3>
              <div className="grid grid-cols-4 gap-3">
                {[
                  { label: 'Critical', count: findingCounts.critical, color: 'text-danger' },
                  { label: 'High', count: findingCounts.high, color: 'text-warning' },
                  { label: 'Medium', count: findingCounts.medium, color: 'text-warning' },
                  { label: 'Low', count: findingCounts.low, color: 'text-primary' },
                ].map((c) => (
                  <div key={c.label} className="rounded-lg border border-border p-3 text-center">
                    <p className={cn('text-2xl font-bold', c.color)}>{c.count}</p>
                    <p className="text-xs text-muted-foreground">{c.label}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Check results */}
            <div className="mt-6">
              <h3 className="mb-3 text-lg font-semibold">Assessment Results</h3>
              <div className="space-y-2">
                {results?.map((r) => (
                  <div key={r.id} className="flex items-center gap-3 rounded-lg border border-border p-3">
                    <StatusIcon status={r.status} />
                    <div className="flex-1">
                      <p className="text-sm font-medium">{r.check_name}</p>
                      <p className="text-xs text-muted-foreground">{r.category}</p>
                    </div>
                    <span className={cn(
                      'text-xs font-medium capitalize',
                      r.status === 'pass' ? 'text-success' :
                      r.status === 'warn' ? 'text-warning' :
                      r.status === 'fail' ? 'text-danger' :
                      'text-muted-foreground'
                    )}>
                      {r.status}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Detailed findings */}
            <div className="mt-6">
              <h3 className="mb-3 text-lg font-semibold">Detailed Findings</h3>
              {findings && findings.length > 0 ? (
                <div className="space-y-3">
                  {findings.map((f) => (
                    <div key={f.id} className="rounded-lg border border-border p-4">
                      <div className="flex items-center justify-between">
                        <p className="font-medium">{f.title}</p>
                        <SeverityBadge severity={f.severity} />
                      </div>
                      <p className="mt-2 text-sm text-muted-foreground">{f.business_impact}</p>
                      {f.remediation_guide && (
                        <div className="mt-3 rounded-md bg-muted p-3">
                          <p className="text-xs font-medium text-muted-foreground">Recommended Action</p>
                          <p className="text-sm">{f.remediation_guide.recommended_action}</p>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">No findings from this assessment.</p>
              )}
            </div>

            {/* Footer */}
            <div className="mt-8 border-t border-border pt-4">
              <p className="text-xs text-muted-foreground">
                This report was generated by Secure360 SMB on {formatDateTime(new Date().toISOString())}.
                All checks are passive and non-destructive. Results reflect the configuration observed at the time of assessment.
              </p>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
