export type Role = 'owner' | 'admin' | 'member' | 'viewer';

export type VerificationStatus = 'pending' | 'verified' | 'failed';
export type AssessmentStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
export type CheckStatus = 'pass' | 'warn' | 'fail' | 'error' | 'info';
export type Confidence = 'high' | 'medium' | 'low' | 'unable_to_verify';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type Priority = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type FindingStatus = 'open' | 'in_progress' | 'resolved' | 'accepted_risk';

export type Category =
  | 'HTTPS/TLS'
  | 'Certificate'
  | 'Security Headers'
  | 'DNS'
  | 'SPF'
  | 'Cookies';

export interface Organization {
  id: string;
  name: string;
  industry: string | null;
  country: string | null;
  timezone: string | null;
  owner_id: string;
  created_at: string;
}

export interface OrganizationMember {
  id: string;
  organization_id: string;
  user_id: string;
  role: Role;
  created_at: string;
}

export interface Domain {
  id: string;
  organization_id: string;
  domain: string;
  normalized_domain: string;
  added_by: string;
  verification_status: VerificationStatus;
  verified_at: string | null;
  created_at: string;
}

export interface DomainVerification {
  id: string;
  domain_id: string;
  method: 'dns_txt' | 'meta_tag';
  token: string;
  token_hash: string;
  status: VerificationStatus;
  attempts: number;
  verified_at: string | null;
  created_at: string;
}

export interface AssessmentProgress {
  [checkId: string]: CheckStatus;
}

export interface Assessment {
  id: string;
  organization_id: string;
  domain_id: string;
  status: AssessmentStatus;
  progress: AssessmentProgress;
  current_step: string | null;
  steps_completed: string[];
  steps_total: number;
  score: number | null;
  score_label: string | null;
  risk_level: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  created_by: string;
}

export interface AssessmentResult {
  id: string;
  assessment_id: string;
  organization_id: string;
  check_id: string;
  check_name: string;
  category: Category;
  status: CheckStatus;
  confidence: Confidence;
  evidence: Record<string, unknown>;
  is_demo: boolean;
  observed_at: string;
}

export interface Finding {
  id: string;
  organization_id: string;
  domain_id: string;
  assessment_id: string;
  rule_id: string;
  title: string;
  category: Category;
  severity: Severity;
  confidence: Confidence;
  priority: Priority;
  status: FindingStatus;
  asset: string;
  remediation_id: string | null;
  effort_minutes: number | null;
  difficulty: string | null;
  business_impact: string | null;
  evidence: Record<string, unknown>;
  resolved_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface SecurityRule {
  rule_id: string;
  category: Category;
  check_id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  description: string | null;
  remediation_id: string | null;
  effort_minutes: number | null;
  difficulty: string | null;
  verification_method: string | null;
}

export interface RemediationGuide {
  remediation_id: string;
  rule_id: string;
  why_it_matters: string;
  recommended_action: string;
  steps: string[];
  verification_method: string | null;
  difficulty: string | null;
  effort_minutes: number | null;
}

export interface ScoreHistoryEntry {
  id: string;
  organization_id: string;
  domain_id: string;
  assessment_id: string;
  score: number;
  label: string | null;
  recorded_at: string;
}

export interface NotificationRow {
  id: string;
  organization_id: string;
  user_id: string;
  type: string;
  title: string;
  message: string;
  severity: string | null;
  read: boolean;
  link: string | null;
  created_at: string;
}

export interface NotificationPreferences {
  id: string;
  user_id: string;
  organization_id: string;
  high_critical_findings: boolean;
  certificate_expiring: boolean;
  assessment_completed: boolean;
  score_drop: boolean;
  finding_returned: boolean;
}

export interface AuditLog {
  id: string;
  organization_id: string;
  user_id: string | null;
  action: string;
  target: string | null;
  details: Record<string, unknown>;
  ip: string | null;
  created_at: string;
}

export interface DomainWithLatest extends Domain {
  latest_assessment?: Assessment;
  verification?: DomainVerification;
}

export interface FindingWithGuide extends Finding {
  remediation_guide?: RemediationGuide | null;
  security_rule?: SecurityRule | null;
}
