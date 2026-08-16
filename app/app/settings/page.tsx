'use client';

import { useState, useEffect, useCallback } from 'react';
import { useAuth } from '@/lib/auth-context';
import { supabase } from '@/lib/supabase';
import type { NotificationPreferences, AuditLog } from '@/lib/types';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useToast } from '@/hooks/use-toast';
import {
  Loader2,
  Bell,
  Building2,
  ScrollText,
  Save,
} from 'lucide-react';
import { formatDateTime } from '@/lib/format';
import { cn } from '@/lib/utils';

const NOTIF_PREFS = [
  { key: 'high_critical_findings', label: 'High & Critical Findings', desc: 'Get notified when high or critical findings are detected' },
  { key: 'certificate_expiring', label: 'Certificate Expiring', desc: 'Warnings when your SSL/TLS certificate is about to expire' },
  { key: 'assessment_completed', label: 'Assessment Completed', desc: 'Notification when an assessment finishes running' },
  { key: 'score_drop', label: 'Score Drop', desc: 'Alert when your security score drops significantly' },
  { key: 'finding_returned', label: 'Finding Returned', desc: 'Alert when a previously resolved finding reappears' },
] as const;

export default function SettingsPage() {
  const { organization, user, membership, refreshOrg } = useAuth();
  const { toast } = useToast();
  const [prefs, setPrefs] = useState<NotificationPreferences | null>(null);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [savingPrefs, setSavingPrefs] = useState(false);
  const [savingOrg, setSavingOrg] = useState(false);
  const [orgName, setOrgName] = useState('');
  const [orgIndustry, setOrgIndustry] = useState('');
  const [orgCountry, setOrgCountry] = useState('');

  const loadData = useCallback(async () => {
    if (!organization || !user) return;
    setLoading(true);

    const { data: p } = await supabase
      .from('notification_preferences')
      .select('*')
      .eq('user_id', user.id)
      .eq('organization_id', organization.id)
      .maybeSingle();
    setPrefs(p as unknown as NotificationPreferences | null);

    const { data: logs } = await supabase
      .from('audit_logs')
      .select('*')
      .eq('organization_id', organization.id)
      .order('created_at', { ascending: false })
      .limit(20);
    setAuditLogs((logs ?? []) as unknown as AuditLog[]);

    setOrgName(organization.name);
    setOrgIndustry(organization.industry ?? '');
    setOrgCountry(organization.country ?? '');

    setLoading(false);
  }, [organization, user]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  async function togglePref(key: keyof NotificationPreferences, value: boolean) {
    if (!prefs || !user || !organization) return;
    const updated = { ...prefs, [key]: value };
    setPrefs(updated);
    setSavingPrefs(true);
    await supabase
      .from('notification_preferences')
      .update({ [key]: value })
      .eq('id', prefs.id);
    setSavingPrefs(false);
  }

  async function saveOrg() {
    if (!organization) return;
    setSavingOrg(true);
    const { error } = await supabase
      .from('organizations')
      .update({
        name: orgName,
        industry: orgIndustry || null,
        country: orgCountry || null,
      })
      .eq('id', organization.id);
    if (error) {
      toast({ title: 'Failed to save', description: error.message, variant: 'destructive' });
    } else {
      await refreshOrg();
      toast({ title: 'Settings saved' });
    }
    setSavingOrg(false);
  }

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  const canEdit = membership?.role === 'owner' || membership?.role === 'admin';

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Settings</h1>
        <p className="mt-1 text-sm text-muted-foreground">Manage your business profile and notification preferences.</p>
      </div>

      {/* Business profile */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg">
            <Building2 className="h-5 w-5 text-primary" />
            Business Profile
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="orgName">Business name</Label>
            <Input id="orgName" value={orgName} onChange={(e) => setOrgName(e.target.value)} disabled={!canEdit} />
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="orgIndustry">Industry</Label>
              <Input id="orgIndustry" value={orgIndustry} onChange={(e) => setOrgIndustry(e.target.value)} disabled={!canEdit} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="orgCountry">Country</Label>
              <Input id="orgCountry" value={orgCountry} onChange={(e) => setOrgCountry(e.target.value)} disabled={!canEdit} />
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-sm text-muted-foreground">Your role: <span className="font-medium text-foreground capitalize">{membership?.role}</span></span>
            <span className="text-sm text-muted-foreground">·</span>
            <span className="text-sm text-muted-foreground">{user?.email}</span>
          </div>
          {canEdit && (
            <Button onClick={saveOrg} disabled={savingOrg || !orgName}>
              {savingOrg ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Save className="mr-2 h-4 w-4" />}
              Save Changes
            </Button>
          )}
        </CardContent>
      </Card>

      {/* Notification preferences */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg">
            <Bell className="h-5 w-5 text-primary" />
            Notification Preferences
          </CardTitle>
          <CardDescription>Choose what you want to be notified about.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {NOTIF_PREFS.map((p) => (
            <div key={p.key} className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium">{p.label}</p>
                <p className="text-xs text-muted-foreground">{p.desc}</p>
              </div>
              <Switch
                checked={prefs?.[p.key] ?? true}
                onCheckedChange={(v) => togglePref(p.key as keyof NotificationPreferences, v)}
              />
            </div>
          ))}
          {savingPrefs && <p className="text-xs text-muted-foreground">Saving...</p>}
        </CardContent>
      </Card>

      {/* Audit log */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg">
            <ScrollText className="h-5 w-5 text-primary" />
            Audit Log
          </CardTitle>
          <CardDescription>Recent activity in your organization.</CardDescription>
        </CardHeader>
        <CardContent>
          {auditLogs.length === 0 ? (
            <p className="text-sm text-muted-foreground">No activity yet.</p>
          ) : (
            <div className="space-y-2">
              {auditLogs.map((log) => (
                <div key={log.id} className="flex items-center justify-between border-b border-border pb-2 last:border-0">
                  <div>
                    <p className="text-sm font-mono">{log.action}</p>
                    {log.target && <p className="text-xs text-muted-foreground">{log.target}</p>}
                  </div>
                  <span className="text-xs text-muted-foreground">{formatDateTime(log.created_at)}</span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
