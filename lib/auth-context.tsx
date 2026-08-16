'use client';

import { createContext, useContext, useEffect, useState, useCallback } from 'react';
import type { Session, User } from '@supabase/supabase-js';
import { supabase } from './supabase';
import type { Organization, OrganizationMember } from './types';

interface AuthContextValue {
  session: Session | null;
  user: User | null;
  loading: boolean;
  organization: Organization | null;
  membership: OrganizationMember | null;
  refreshOrg: () => Promise<void>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue>({
  session: null,
  user: null,
  loading: true,
  organization: null,
  membership: null,
  refreshOrg: async () => {},
  signOut: async () => {},
});

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [organization, setOrganization] = useState<Organization | null>(null);
  const [membership, setMembership] = useState<OrganizationMember | null>(null);

  const refreshOrg = useCallback(async () => {
    if (!user) {
      setOrganization(null);
      setMembership(null);
      return;
    }
    const { data: member } = await supabase
      .from('organization_members')
      .select('organization_id, role, id, user_id, created_at')
      .eq('user_id', user.id)
      .maybeSingle();

    if (member) {
      const mem = member as unknown as OrganizationMember;
      setMembership(mem);
      const { data: org } = await supabase
        .from('organizations')
        .select('*')
        .eq('id', mem.organization_id)
        .maybeSingle();
      setOrganization(org as unknown as Organization | null);
    } else {
      setMembership(null);
      setOrganization(null);
    }
  }, [user]);

  useEffect(() => {
    let mounted = true;

    supabase.auth.getSession().then(({ data }) => {
      if (!mounted) return;
      setSession(data.session);
      setUser(data.session?.user ?? null);
      setLoading(false);
    });

    const { data: listener } = supabase.auth.onAuthStateChange((_event, sess) => {
      setSession(sess);
      setUser(sess?.user ?? null);
      setLoading(false);
    });

    return () => {
      mounted = false;
      listener.subscription.unsubscribe();
    };
  }, []);

  useEffect(() => {
    if (loading) return;
    refreshOrg();
  }, [user, loading, refreshOrg]);

  const signOut = useCallback(async () => {
    await supabase.auth.signOut();
    setOrganization(null);
    setMembership(null);
  }, []);

  return (
    <AuthContext.Provider
      value={{ session, user, loading, organization, membership, refreshOrg, signOut }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
