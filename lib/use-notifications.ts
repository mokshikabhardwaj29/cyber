'use client';

import { useEffect, useState } from 'react';
import { supabase } from './supabase';
import { useAuth } from './auth-context';
import type { NotificationRow } from './types';

export function useNotifications() {
  const { user } = useAuth();
  const [notifications, setNotifications] = useState<NotificationRow[]>([]);
  const [unread, setUnread] = useState(0);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!user) {
      setNotifications([]);
      setUnread(0);
      setLoading(false);
      return;
    }

    let active = true;

    async function load() {
      const { data } = await supabase
        .from('notifications')
        .select('*')
        .eq('user_id', user!.id)
        .order('created_at', { ascending: false })
        .limit(20);
      if (!active) return;
      setNotifications((data ?? []) as unknown as NotificationRow[]);
      setUnread((data ?? []).filter((n) => !n.read).length);
      setLoading(false);
    }

    load();

    const channel = supabase
      .channel('notifications')
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'notifications', filter: `user_id=eq.${user.id}` },
        () => load()
      )
      .subscribe();

    return () => {
      active = false;
      supabase.removeChannel(channel);
    };
  }, [user]);

  async function markRead(id: string) {
    await supabase.from('notifications').update({ read: true }).eq('id', id);
  }

  async function markAllRead() {
    if (!user) return;
    await supabase.from('notifications').update({ read: true }).eq('user_id', user.id).eq('read', false);
  }

  return { notifications, unread, loading, markRead, markAllRead };
}
