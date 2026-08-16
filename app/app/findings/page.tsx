'use client';

import { useState, useEffect, useCallback } from 'react';
import { useSearchParams } from 'next/navigation';
import { useAuth } from '@/lib/auth-context';
import { supabase } from '@/lib/supabase';
import type { Finding, FindingWithGuide } from '@/lib/types';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { SeverityBadge, FindingStatusBadge } from '@/components/severity';
import { useToast } from '@/hooks/use-toast';
import {
  AlertTriangle,
  Loader2,
  Filter,
  ChevronRight,
  Clock,
} from 'lucide-react';
import Link from 'next/link';
import { formatRelativeTime } from '@/lib/format';

const CATEGORIES = ['HTTPS/TLS', 'Certificate', 'Security Headers', 'DNS', 'SPF', 'Cookies'];
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'];
const STATUSES = ['open', 'in_progress', 'resolved', 'accepted_risk'];

export default function FindingsPage() {
  const { organization } = useAuth();
  const searchParams = useSearchParams();
  const assessmentId = searchParams.get('assessment');
  const { toast } = useToast();
  const [findings, setFindings] = useState<FindingWithGuide[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [filterCategory, setFilterCategory] = useState<string>('all');
  const [filterStatus, setFilterStatus] = useState<string>('open');

  const loadFindings = useCallback(async () => {
    if (!organization) return;
    setLoading(true);

    let query = supabase
      .from('findings')
      .select(`
        *,
        remediation_guide:remediation_guides!findings_remediation_id_fkey(*),
        security_rule:security_rules!findings_rule_id_fkey(*)
      `)
      .eq('organization_id', organization.id)
      .order('created_at', { ascending: false });

    if (assessmentId) {
      query = query.eq('assessment_id', assessmentId);
    }
    if (filterSeverity !== 'all') {
      query = query.eq('severity', filterSeverity);
    }
    if (filterCategory !== 'all') {
      query = query.eq('category', filterCategory);
    }
    if (filterStatus !== 'all') {
      query = query.eq('status', filterStatus);
    }

    const { data } = await query;
    setFindings((data ?? []) as unknown as FindingWithGuide[]);
    setLoading(false);
  }, [organization, assessmentId, filterSeverity, filterCategory, filterStatus]);

  useEffect(() => {
    loadFindings();
  }, [loadFindings]);

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Findings</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {assessmentId ? 'Findings from your latest assessment.' : 'All security findings across your domains.'}
        </p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-medium">Filter:</span>
        </div>
        <Select value={filterStatus} onValueChange={setFilterStatus}>
          <SelectTrigger className="w-36">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            {STATUSES.map((s) => (
              <SelectItem key={s} value={s} className="capitalize">{s.replace('_', ' ')}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={filterSeverity} onValueChange={setFilterSeverity}>
          <SelectTrigger className="w-36">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All severities</SelectItem>
            {SEVERITIES.map((s) => (
              <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={filterCategory} onValueChange={setFilterCategory}>
          <SelectTrigger className="w-44">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All categories</SelectItem>
            {CATEGORIES.map((c) => (
              <SelectItem key={c} value={c}>{c}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <span className="ml-auto text-sm text-muted-foreground">
          {findings.length} {findings.length === 1 ? 'finding' : 'findings'}
        </span>
      </div>

      {/* Findings list */}
      {findings.length === 0 ? (
        <Card className="border-dashed">
          <CardContent className="flex flex-col items-center justify-center py-16 text-center">
            <AlertTriangle className="mb-4 h-12 w-12 text-muted-foreground/50" />
            <h3 className="text-lg font-semibold">No findings</h3>
            <p className="mt-1 max-w-sm text-sm text-muted-foreground">
              {filterStatus !== 'all' || filterSeverity !== 'all' || filterCategory !== 'all'
                ? 'No findings match your filters. Try adjusting them.'
                : 'No security findings to show. Run an assessment to check your domain.'}
            </p>
            {!assessmentId && (
              <Link href="/app/assessments">
                <Button className="mt-4">Run Assessment</Button>
              </Link>
            )}
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {findings.map((f) => (
            <Link key={f.id} href={`/app/findings/${f.id}`}>
              <Card className="cursor-pointer transition-shadow hover:shadow-md">
                <CardContent className="flex items-center justify-between p-4">
                  <div className="flex items-start gap-3">
                    <div className="mt-1">
                      <SeverityBadge severity={f.severity} />
                    </div>
                    <div className="min-w-0">
                      <p className="truncate font-medium">{f.title}</p>
                      <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                        <span>{f.asset}</span>
                        <span>·</span>
                        <span>{f.category}</span>
                        {f.effort_minutes != null && (
                          <>
                            <span>·</span>
                            <span className="flex items-center gap-1">
                              <Clock className="h-3 w-3" />
                              ~{f.effort_minutes} min
                            </span>
                          </>
                        )}
                        <span>·</span>
                        <span>{formatRelativeTime(f.created_at)}</span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <FindingStatusBadge status={f.status} />
                    <ChevronRight className="h-5 w-5 text-muted-foreground" />
                  </div>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
