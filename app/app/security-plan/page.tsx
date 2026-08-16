'use client';

import { useState, useEffect, useCallback } from 'react';
import { useAuth } from '@/lib/auth-context';
import { supabase } from '@/lib/supabase';
import type { Finding } from '@/lib/types';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { SeverityBadge, FindingStatusBadge } from '@/components/severity';
import { useToast } from '@/hooks/use-toast';
import {
  Loader2,
  Clock,
  Wrench,
  CheckCircle2,
  AlertTriangle,
  ListChecks,
  Calendar,
} from 'lucide-react';
import Link from 'next/link';
import { cn } from '@/lib/utils';

export default function SecurityPlanPage() {
  const { organization } = useAuth();
  const { toast } = useToast();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [updatingId, setUpdatingId] = useState<string | null>(null);

  const loadFindings = useCallback(async () => {
    if (!organization) return;
    setLoading(true);
    const { data } = await supabase
      .from('findings')
      .select('*')
      .eq('organization_id', organization.id)
      .in('status', ['open', 'in_progress'])
      .order('severity', { ascending: false });
    setFindings((data ?? []) as unknown as Finding[]);
    setLoading(false);
  }, [organization]);

  useEffect(() => {
    loadFindings();
  }, [loadFindings]);

  async function markInProgress(id: string) {
    setUpdatingId(id);
    await supabase
      .from('findings')
      .update({ status: 'in_progress', updated_at: new Date().toISOString() })
      .eq('id', id);
    toast({ title: 'Marked as in progress' });
    setUpdatingId(null);
    loadFindings();
  }

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  // Split by priority
  const fixToday = findings.filter((f) => f.severity === 'critical' || f.severity === 'high');
  const fixThisWeek = findings.filter((f) => f.severity === 'medium');
  const improveLater = findings.filter((f) => f.severity === 'low' || f.severity === 'informational');

  const sections = [
    { title: 'Fix Today', items: fixToday, icon: AlertTriangle, color: 'danger', desc: 'Critical and high-priority findings that need immediate attention' },
    { title: 'Fix This Week', items: fixThisWeek, icon: Calendar, color: 'warning', desc: 'Medium-priority findings to address soon' },
    { title: 'Improve Later', items: improveLater, icon: CheckCircle2, color: 'primary', desc: 'Low-priority improvements for when you have time' },
  ];

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold">My Security Plan</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Your cybersecurity tasks, organized by priority. Work through them at your own pace.
        </p>
      </div>

      {findings.length === 0 ? (
        <Card className="border-dashed">
          <CardContent className="flex flex-col items-center justify-center py-16 text-center">
            <CheckCircle2 className="mb-4 h-12 w-12 text-success" />
            <h3 className="text-lg font-semibold">Your security plan is clear</h3>
            <p className="mt-1 max-w-sm text-sm text-muted-foreground">
              No open findings. Run a new assessment to keep your security up to date.
            </p>
            <Link href="/app/assessments">
              <Button className="mt-4">Run Assessment</Button>
            </Link>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-6">
          {sections.map((section) => (
            <div key={section.title}>
              <div className="mb-3 flex items-center gap-2">
                <section.icon className={cn('h-5 w-5', `text-${section.color}`)} />
                <h2 className="text-lg font-semibold">{section.title}</h2>
                <Badge variant="secondary">{section.items.length}</Badge>
              </div>
              <p className="mb-3 text-sm text-muted-foreground">{section.desc}</p>
              {section.items.length === 0 ? (
                <Card className="border-dashed">
                  <CardContent className="py-6 text-center text-sm text-muted-foreground">
                    Nothing here. You&apos;re all caught up.
                  </CardContent>
                </Card>
              ) : (
                <div className="space-y-2">
                  {section.items.map((f) => (
                    <Card key={f.id} className="hover:shadow-sm transition-shadow">
                      <CardContent className="flex items-center justify-between p-4">
                        <div className="flex items-start gap-3">
                          <div className="mt-1">
                            <SeverityBadge severity={f.severity} />
                          </div>
                          <div>
                            <Link href={`/app/findings/${f.id}`}>
                              <p className="font-medium hover:underline">{f.title}</p>
                            </Link>
                            <div className="mt-1 flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                              <span>{f.asset}</span>
                              {f.effort_minutes != null && (
                                <span className="flex items-center gap-1">
                                  <Clock className="h-3 w-3" />
                                  ~{f.effort_minutes} min
                                </span>
                              )}
                              {f.difficulty && (
                                <span className="flex items-center gap-1">
                                  <Wrench className="h-3 w-3" />
                                  {f.difficulty}
                                </span>
                              )}
                              <FindingStatusBadge status={f.status} />
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          {f.status === 'open' && (
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => markInProgress(f.id)}
                              disabled={updatingId === f.id}
                            >
                              {updatingId === f.id ? (
                                <Loader2 className="h-4 w-4 animate-spin" />
                              ) : (
                                'Start'
                              )}
                            </Button>
                          )}
                          <Link href={`/app/findings/${f.id}`}>
                            <Button size="sm" variant="ghost">Open</Button>
                          </Link>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
