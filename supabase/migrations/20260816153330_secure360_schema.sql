/*
# Secure360 SMB — Core Schema

## Purpose
Full-stack cybersecurity assessment SaaS for small businesses. Organizations own domains; domains are verified via DNS TXT; assessments run passive scanners (HTTPS, TLS, headers, DNS, SPF, cookies) and generate deterministic findings, a platform risk score, and a 0–100 security score.

## New Tables
- organizations, organization_members, domains, domain_verifications,
  assessments, assessment_results, findings, security_rules, remediation_guides,
  risk_scores, score_history, notifications, notification_preferences, audit_logs.

## Security
- RLS enabled on every table. Org-scoped tables filtered through organization_members membership.
- security_rules + remediation_guides are read-only reference data.
*/

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS organizations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  industry text,
  country text,
  timezone text DEFAULT 'UTC',
  owner_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS organization_members (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('owner','admin','member','viewer')),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, user_id)
);
ALTER TABLE organization_members ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS domains (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  domain text NOT NULL,
  normalized_domain text NOT NULL,
  added_by uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  verification_status text NOT NULL DEFAULT 'pending' CHECK (verification_status IN ('pending','verified','failed')),
  verified_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE domains ENABLE ROW LEVEL SECURITY;
CREATE INDEX IF NOT EXISTS idx_domains_org ON domains(organization_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_domains_org_norm ON domains(organization_id, normalized_domain);

CREATE TABLE IF NOT EXISTS domain_verifications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  domain_id uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  method text NOT NULL DEFAULT 'dns_txt' CHECK (method IN ('dns_txt','meta_tag')),
  token text NOT NULL,
  token_hash text NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','verified','failed')),
  attempts int NOT NULL DEFAULT 0,
  verified_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE domain_verifications ENABLE ROW LEVEL SECURITY;
CREATE INDEX IF NOT EXISTS idx_domain_verif_domain ON domain_verifications(domain_id);

CREATE TABLE IF NOT EXISTS assessments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  domain_id uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','completed','failed','cancelled')),
  progress jsonb NOT NULL DEFAULT '{}'::jsonb,
  current_step text,
  steps_completed text[] NOT NULL DEFAULT '{}',
  steps_total int NOT NULL DEFAULT 6,
  score int,
  score_label text,
  risk_level text,
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE
);
ALTER TABLE assessments ENABLE ROW LEVEL SECURITY;
CREATE INDEX IF NOT EXISTS idx_assess_org ON assessments(organization_id);
CREATE INDEX IF NOT EXISTS idx_assess_domain ON assessments(domain_id);
CREATE INDEX IF NOT EXISTS idx_assess_status ON assessments(status);

CREATE TABLE IF NOT EXISTS assessment_results (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  check_id text NOT NULL,
  check_name text NOT NULL,
  category text NOT NULL,
  status text NOT NULL CHECK (status IN ('pass','warn','fail','error','info')),
  confidence text NOT NULL DEFAULT 'high' CHECK (confidence IN ('high','medium','low','unable_to_verify')),
  evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
  is_demo boolean NOT NULL DEFAULT false,
  observed_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE assessment_results ENABLE ROW LEVEL SECURITY;
CREATE INDEX IF NOT EXISTS idx_results_assess ON assessment_results(assessment_id);
CREATE INDEX IF NOT EXISTS idx_results_org ON assessment_results(organization_id);

CREATE TABLE IF NOT EXISTS findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  domain_id uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  rule_id text NOT NULL,
  title text NOT NULL,
  category text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('critical','high','medium','low','informational')),
  confidence text NOT NULL CHECK (confidence IN ('high','medium','low','unable_to_verify')),
  priority text NOT NULL CHECK (priority IN ('critical','high','medium','low','informational')),
  status text NOT NULL DEFAULT 'open' CHECK (status IN ('open','in_progress','resolved','accepted_risk')),
  asset text NOT NULL,
  remediation_id text,
  effort_minutes int,
  difficulty text,
  business_impact text,
  evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
  resolved_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
CREATE INDEX IF NOT EXISTS idx_findings_org ON findings(organization_id);
CREATE INDEX IF NOT EXISTS idx_findings_assess ON findings(assessment_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

CREATE TABLE IF NOT EXISTS security_rules (
  rule_id text PRIMARY KEY,
  category text NOT NULL,
  check_id text NOT NULL,
  title text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('critical','high','medium','low','informational')),
  confidence text NOT NULL DEFAULT 'high',
  description text,
  remediation_id text,
  effort_minutes int,
  difficulty text,
  verification_method text,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE security_rules ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS remediation_guides (
  remediation_id text PRIMARY KEY,
  rule_id text NOT NULL,
  why_it_matters text NOT NULL,
  recommended_action text NOT NULL,
  steps jsonb NOT NULL DEFAULT '[]'::jsonb,
  verification_method text,
  difficulty text,
  effort_minutes int,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE remediation_guides ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS risk_scores (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  domain_id uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  risk_score numeric NOT NULL DEFAULT 0,
  risk_level text,
  factors jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE risk_scores ENABLE ROW LEVEL SECURITY;
CREATE INDEX IF NOT EXISTS idx_risk_assess ON risk_scores(assessment_id);

CREATE TABLE IF NOT EXISTS score_history (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  domain_id uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  score int NOT NULL,
  label text,
  recorded_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE score_history ENABLE ROW LEVEL SECURITY;
CREATE INDEX IF NOT EXISTS idx_score_hist_org ON score_history(organization_id);
CREATE INDEX IF NOT EXISTS idx_score_hist_domain ON score_history(domain_id);

CREATE TABLE IF NOT EXISTS notifications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  type text NOT NULL,
  title text NOT NULL,
  message text NOT NULL,
  severity text,
  read boolean NOT NULL DEFAULT false,
  link text,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;
CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id);
CREATE INDEX IF NOT EXISTS idx_notif_org ON notifications(organization_id);

CREATE TABLE IF NOT EXISTS notification_preferences (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  high_critical_findings boolean NOT NULL DEFAULT true,
  certificate_expiring boolean NOT NULL DEFAULT true,
  assessment_completed boolean NOT NULL DEFAULT true,
  score_drop boolean NOT NULL DEFAULT true,
  finding_returned boolean NOT NULL DEFAULT true,
  UNIQUE (user_id, organization_id)
);
ALTER TABLE notification_preferences ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS audit_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  action text NOT NULL,
  target text,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  ip text,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_logs(organization_id);

-- ========== POLICIES ==========

-- organizations
DROP POLICY IF EXISTS "select_own_orgs" ON organizations;
CREATE POLICY "select_own_orgs" ON organizations FOR SELECT
  TO authenticated USING (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = organizations.id AND m.user_id = auth.uid())
  );
DROP POLICY IF EXISTS "insert_own_orgs" ON organizations;
CREATE POLICY "insert_own_orgs" ON organizations FOR INSERT
  TO authenticated WITH CHECK (auth.uid() = owner_id);
DROP POLICY IF EXISTS "update_own_orgs" ON organizations;
CREATE POLICY "update_own_orgs" ON organizations FOR UPDATE
  TO authenticated USING (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = organizations.id AND m.user_id = auth.uid() AND m.role IN ('owner','admin'))
  ) WITH CHECK (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = organizations.id AND m.user_id = auth.uid() AND m.role IN ('owner','admin'))
  );
DROP POLICY IF EXISTS "delete_own_orgs" ON organizations;
CREATE POLICY "delete_own_orgs" ON organizations FOR DELETE
  TO authenticated USING (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = organizations.id AND m.user_id = auth.uid() AND m.role = 'owner')
  );

-- organization_members
DROP POLICY IF EXISTS "select_own_membership" ON organization_members;
CREATE POLICY "select_own_membership" ON organization_members FOR SELECT
  TO authenticated USING (user_id = auth.uid());
DROP POLICY IF EXISTS "insert_own_membership" ON organization_members;
CREATE POLICY "insert_own_membership" ON organization_members FOR INSERT
  TO authenticated WITH CHECK (user_id = auth.uid());
DROP POLICY IF EXISTS "update_own_membership" ON organization_members;
CREATE POLICY "update_own_membership" ON organization_members FOR UPDATE
  TO authenticated USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());
DROP POLICY IF EXISTS "delete_own_membership" ON organization_members;
CREATE POLICY "delete_own_membership" ON organization_members FOR DELETE
  TO authenticated USING (user_id = auth.uid());

-- domains
DROP POLICY IF EXISTS "select_org_domains" ON domains;
CREATE POLICY "select_org_domains" ON domains FOR SELECT
  TO authenticated USING (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = domains.organization_id AND m.user_id = auth.uid())
  );
DROP POLICY IF EXISTS "insert_org_domains" ON domains;
CREATE POLICY "insert_org_domains" ON domains FOR INSERT
  TO authenticated WITH CHECK (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = domains.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin','member'))
  );
DROP POLICY IF EXISTS "update_org_domains" ON domains;
CREATE POLICY "update_org_domains" ON domains FOR UPDATE
  TO authenticated USING (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = domains.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin','member'))
  ) WITH CHECK (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = domains.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin','member'))
  );
DROP POLICY IF EXISTS "delete_org_domains" ON domains;
CREATE POLICY "delete_org_domains" ON domains FOR DELETE
  TO authenticated USING (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = domains.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin'))
  );

-- domain_verifications
DROP POLICY IF EXISTS "select_org_verifs" ON domain_verifications;
CREATE POLICY "select_org_verifs" ON domain_verifications FOR SELECT
  TO authenticated USING (
    EXISTS (SELECT 1 FROM organization_members m
            JOIN domains d ON d.organization_id = m.organization_id
            WHERE d.id = domain_verifications.domain_id AND m.user_id = auth.uid())
  );
DROP POLICY IF EXISTS "insert_org_verifs" ON domain_verifications;
CREATE POLICY "insert_org_verifs" ON domain_verifications FOR INSERT
  TO authenticated WITH CHECK (
    EXISTS (SELECT 1 FROM organization_members m
            JOIN domains d ON d.organization_id = m.organization_id
            WHERE d.id = domain_verifications.domain_id AND m.user_id = auth.uid())
  );
DROP POLICY IF EXISTS "update_org_verifs" ON domain_verifications;
CREATE POLICY "update_org_verifs" ON domain_verifications FOR UPDATE
  TO authenticated USING (
    EXISTS (SELECT 1 FROM organization_members m
            JOIN domains d ON d.organization_id = m.organization_id
            WHERE d.id = domain_verifications.domain_id AND m.user_id = auth.uid())
  ) WITH CHECK (
    EXISTS (SELECT 1 FROM organization_members m
            JOIN domains d ON d.organization_id = m.organization_id
            WHERE d.id = domain_verifications.domain_id AND m.user_id = auth.uid())
  );
DROP POLICY IF EXISTS "delete_org_verifs" ON domain_verifications;
CREATE POLICY "delete_org_verifs" ON domain_verifications FOR DELETE
  TO authenticated USING (
    EXISTS (SELECT 1 FROM organization_members m
            JOIN domains d ON d.organization_id = m.organization_id
            WHERE d.id = domain_verifications.domain_id AND m.user_id = auth.uid())
  );

-- assessments
DROP POLICY IF EXISTS "select_org_assess" ON assessments;
CREATE POLICY "select_org_assess" ON assessments FOR SELECT
  TO authenticated USING (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = assessments.organization_id AND m.user_id = auth.uid())
  );
DROP POLICY IF EXISTS "insert_org_assess" ON assessments;
CREATE POLICY "insert_org_assess" ON assessments FOR INSERT
  TO authenticated WITH CHECK (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = assessments.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin','member'))
  );
DROP POLICY IF EXISTS "update_org_assess" ON assessments;
CREATE POLICY "update_org_assess" ON assessments FOR UPDATE
  TO authenticated USING (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = assessments.organization_id AND m.user_id = auth.uid())
  ) WITH CHECK (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = assessments.organization_id AND m.user_id = auth.uid())
  );
DROP POLICY IF EXISTS "delete_org_assess" ON assessments;
CREATE POLICY "delete_org_assess" ON assessments FOR DELETE
  TO authenticated USING (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = assessments.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin'))
  );

-- assessment_results
DROP POLICY IF EXISTS "select_org_results" ON assessment_results;
CREATE POLICY "select_org_results" ON assessment_results FOR SELECT
  TO authenticated USING (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = assessment_results.organization_id AND m.user_id = auth.uid())
  );
DROP POLICY IF EXISTS "insert_org_results" ON assessment_results;
CREATE POLICY "insert_org_results" ON assessment_results FOR INSERT
  TO authenticated WITH CHECK (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = assessment_results.organization_id AND m.user_id = auth.uid())
  );
DROP POLICY IF EXISTS "update_org_results" ON assessment_results;
CREATE POLICY "update_org_results" ON assessment_results FOR UPDATE
  TO authenticated USING (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = assessment_results.organization_id AND m.user_id = auth.uid())
  ) WITH CHECK (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = assessment_results.organization_id AND m.user_id = auth.uid())
  );
DROP POLICY IF EXISTS "delete_org_results" ON assessment_results;
CREATE POLICY "delete_org_results" ON assessment_results FOR DELETE
  TO authenticated USING (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = assessment_results.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin'))
  );

-- findings
DROP POLICY IF EXISTS "select_org_findings" ON findings;
CREATE POLICY "select_org_findings" ON findings FOR SELECT
  TO authenticated USING (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = findings.organization_id AND m.user_id = auth.uid())
  );
DROP POLICY IF EXISTS "insert_org_findings" ON findings;
CREATE POLICY "insert_org_findings" ON findings FOR INSERT
  TO authenticated WITH CHECK (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = findings.organization_id AND m.user_id = auth.uid())
  );
DROP POLICY IF EXISTS "update_org_findings" ON findings;
CREATE POLICY "update_org_findings" ON findings FOR UPDATE
  TO authenticated USING (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = findings.organization_id AND m.user_id = auth.uid())
  ) WITH CHECK (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = findings.organization_id AND m.user_id = auth.uid())
  );
DROP POLICY IF EXISTS "delete_org_findings" ON findings;
CREATE POLICY "delete_org_findings" ON findings FOR DELETE
  TO authenticated USING (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = findings.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin'))
  );

-- risk_scores
DROP POLICY IF EXISTS "select_org_risk" ON risk_scores;
CREATE POLICY "select_org_risk" ON risk_scores FOR SELECT
  TO authenticated USING (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = risk_scores.organization_id AND m.user_id = auth.uid())
  );
DROP POLICY IF EXISTS "insert_org_risk" ON risk_scores;
CREATE POLICY "insert_org_risk" ON risk_scores FOR INSERT
  TO authenticated WITH CHECK (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = risk_scores.organization_id AND m.user_id = auth.uid())
  );
DROP POLICY IF EXISTS "update_org_risk" ON risk_scores;
CREATE POLICY "update_org_risk" ON risk_scores FOR UPDATE
  TO authenticated USING (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = risk_scores.organization_id AND m.user_id = auth.uid())
  ) WITH CHECK (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = risk_scores.organization_id AND m.user_id = auth.uid())
  );
DROP POLICY IF EXISTS "delete_org_risk" ON risk_scores;
CREATE POLICY "delete_org_risk" ON risk_scores FOR DELETE
  TO authenticated USING (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = risk_scores.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin'))
  );

-- score_history
DROP POLICY IF EXISTS "select_org_scorehist" ON score_history;
CREATE POLICY "select_org_scorehist" ON score_history FOR SELECT
  TO authenticated USING (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = score_history.organization_id AND m.user_id = auth.uid())
  );
DROP POLICY IF EXISTS "insert_org_scorehist" ON score_history;
CREATE POLICY "insert_org_scorehist" ON score_history FOR INSERT
  TO authenticated WITH CHECK (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = score_history.organization_id AND m.user_id = auth.uid())
  );
DROP POLICY IF EXISTS "delete_org_scorehist" ON score_history;
CREATE POLICY "delete_org_scorehist" ON score_history FOR DELETE
  TO authenticated USING (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = score_history.organization_id AND m.user_id = auth.uid() AND m.role IN ('owner','admin'))
  );

-- notifications
DROP POLICY IF EXISTS "select_own_notifs" ON notifications;
CREATE POLICY "select_own_notifs" ON notifications FOR SELECT
  TO authenticated USING (user_id = auth.uid());
DROP POLICY IF EXISTS "insert_own_notifs" ON notifications;
CREATE POLICY "insert_own_notifs" ON notifications FOR INSERT
  TO authenticated WITH CHECK (user_id = auth.uid());
DROP POLICY IF EXISTS "update_own_notifs" ON notifications;
CREATE POLICY "update_own_notifs" ON notifications FOR UPDATE
  TO authenticated USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());
DROP POLICY IF EXISTS "delete_own_notifs" ON notifications;
CREATE POLICY "delete_own_notifs" ON notifications FOR DELETE
  TO authenticated USING (user_id = auth.uid());

-- notification_preferences
DROP POLICY IF EXISTS "select_own_notifprefs" ON notification_preferences;
CREATE POLICY "select_own_notifprefs" ON notification_preferences FOR SELECT
  TO authenticated USING (user_id = auth.uid());
DROP POLICY IF EXISTS "insert_own_notifprefs" ON notification_preferences;
CREATE POLICY "insert_own_notifprefs" ON notification_preferences FOR INSERT
  TO authenticated WITH CHECK (user_id = auth.uid());
DROP POLICY IF EXISTS "update_own_notifprefs" ON notification_preferences;
CREATE POLICY "update_own_notifprefs" ON notification_preferences FOR UPDATE
  TO authenticated USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());
DROP POLICY IF EXISTS "delete_own_notifprefs" ON notification_preferences;
CREATE POLICY "delete_own_notifprefs" ON notification_preferences FOR DELETE
  TO authenticated USING (user_id = auth.uid());

-- audit_logs
DROP POLICY IF EXISTS "select_org_audit" ON audit_logs;
CREATE POLICY "select_org_audit" ON audit_logs FOR SELECT
  TO authenticated USING (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = audit_logs.organization_id AND m.user_id = auth.uid())
  );
DROP POLICY IF EXISTS "insert_org_audit" ON audit_logs;
CREATE POLICY "insert_org_audit" ON audit_logs FOR INSERT
  TO authenticated WITH CHECK (
    EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id = audit_logs.organization_id AND m.user_id = auth.uid())
  );

-- reference data
DROP POLICY IF EXISTS "select_rules" ON security_rules;
CREATE POLICY "select_rules" ON security_rules FOR SELECT
  TO authenticated USING (true);
DROP POLICY IF EXISTS "select_guides" ON remediation_guides;
CREATE POLICY "select_guides" ON remediation_guides FOR SELECT
  TO authenticated USING (true);
