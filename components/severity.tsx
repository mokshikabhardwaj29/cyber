'use client';

import { cn } from '@/lib/utils';
import type { Severity, CheckStatus, Confidence, FindingStatus } from '@/lib/types';
import {
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Info,
  HelpCircle,
  Circle,
  Loader2,
} from 'lucide-react';

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  const styles: Record<Severity, { bg: string; text: string; label: string }> = {
    critical: { bg: 'bg-red-50 dark:bg-red-950/50', text: 'text-red-700 dark:text-red-300', label: 'Critical' },
    high: { bg: 'bg-orange-50 dark:bg-orange-950/50', text: 'text-orange-700 dark:text-orange-300', label: 'High' },
    medium: { bg: 'bg-amber-50 dark:bg-amber-950/50', text: 'text-amber-700 dark:text-amber-300', label: 'Medium' },
    low: { bg: 'bg-blue-50 dark:bg-blue-950/50', text: 'text-blue-700 dark:text-blue-300', label: 'Low' },
    informational: { bg: 'bg-slate-100 dark:bg-slate-800', text: 'text-slate-600 dark:text-slate-300', label: 'Info' },
  };
  const s = styles[severity];
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium',
        s.bg,
        s.text,
        className
      )}
    >
      <SeverityDot severity={severity} />
      {s.label}
    </span>
  );
}

export function SeverityDot({ severity }: { severity: Severity }) {
  const colors: Record<Severity, string> = {
    critical: 'bg-red-500',
    high: 'bg-orange-500',
    medium: 'bg-amber-500',
    low: 'bg-blue-500',
    informational: 'bg-slate-400',
  };
  return <span className={cn('inline-block h-2 w-2 rounded-full', colors[severity])} />;
}

export function StatusIcon({
  status,
  className,
}: {
  status: CheckStatus;
  className?: string;
}) {
  switch (status) {
    case 'pass':
      return <CheckCircle2 className={cn('h-5 w-5 text-success', className)} />;
    case 'warn':
      return <AlertTriangle className={cn('h-5 w-5 text-warning', className)} />;
    case 'fail':
      return <XCircle className={cn('h-5 w-5 text-danger', className)} />;
    case 'error':
      return <HelpCircle className={cn('h-5 w-5 text-muted-foreground', className)} />;
    case 'info':
      return <Info className={cn('h-5 w-5 text-primary', className)} />;
    default:
      return <Circle className={cn('h-5 w-5 text-muted-foreground', className)} />;
  }
}

export function ConfidenceBadge({ confidence }: { confidence: Confidence }) {
  const map: Record<Confidence, { label: string; className: string }> = {
    high: { label: 'High confidence', className: 'text-success' },
    medium: { label: 'Medium confidence', className: 'text-primary' },
    low: { label: 'Low confidence', className: 'text-warning' },
    unable_to_verify: { label: 'Unable to verify', className: 'text-muted-foreground' },
  };
  const c = map[confidence];
  return <span className={cn('text-xs font-medium', c.className)}>{c.label}</span>;
}

export function FindingStatusBadge({ status }: { status: FindingStatus }) {
  const map: Record<FindingStatus, { label: string; className: string }> = {
    open: { label: 'Open', className: 'bg-red-50 text-red-700 dark:bg-red-950/50 dark:text-red-300' },
    in_progress: { label: 'In Progress', className: 'bg-blue-50 text-blue-700 dark:bg-blue-950/50 dark:text-blue-300' },
    resolved: { label: 'Resolved', className: 'bg-green-50 text-green-700 dark:bg-green-950/50 dark:text-green-300' },
    accepted_risk: { label: 'Accepted Risk', className: 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300' },
  };
  const s = map[status];
  return <span className={cn('inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium', s.className)}>{s.label}</span>;
}

export function LoadingSpinner({ className }: { className?: string }) {
  return <Loader2 className={cn('h-5 w-5 animate-spin', className)} />;
}
