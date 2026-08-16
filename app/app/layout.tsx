'use client';

import { useEffect, useState } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import Link from 'next/link';
import { useAuth } from '@/lib/auth-context';
import { useNotifications } from '@/lib/use-notifications';
import { supabase } from '@/lib/supabase';
import { Button } from '@/components/ui/button';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import {
  ShieldCheck,
  LayoutDashboard,
  Globe,
  ScanLine,
  AlertTriangle,
  ListChecks,
  FileText,
  Settings,
  HelpCircle,
  Bell,
  Loader2,
  LogOut,
  Menu,
  X,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { formatRelativeTime } from '@/lib/format';

const NAV = [
  { href: '/app/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { href: '/app/assets', label: 'Assets', icon: Globe },
  { href: '/app/assessments', label: 'Assessments', icon: ScanLine },
  { href: '/app/findings', label: 'Findings', icon: AlertTriangle },
  { href: '/app/security-plan', label: 'Security Plan', icon: ListChecks },
  { href: '/app/reports', label: 'Reports', icon: FileText },
  { href: '/app/settings', label: 'Settings', icon: Settings },
  { href: '/app/help', label: 'Help', icon: HelpCircle },
];

export default function AppShell({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const { user, loading, organization, signOut } = useAuth();
  const { notifications, unread, markAllRead } = useNotifications();
  const [showNotifs, setShowNotifs] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    if (!loading && !user) {
      router.push('/login');
      return;
    }
    if (!loading && user && !organization && pathname !== '/onboarding') {
      router.push('/onboarding');
    }
  }, [user, loading, organization, pathname, router]);

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-navy text-navy-foreground">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  if (!user || !organization) {
    return null;
  }

  const initials = user.email?.slice(0, 2).toUpperCase() ?? '?';

  async function handleSignOut() {
    await signOut();
    router.push('/');
  }

  return (
    <div className="flex min-h-screen bg-background">
      {/* Sidebar - desktop */}
      <aside className="fixed inset-y-0 left-0 z-40 hidden w-64 flex-col border-r border-border bg-navy text-navy-foreground md:flex">
        <SidebarContent
          pathname={pathname}
          organization={organization}
          onClose={() => {}}
        />
      </aside>

      {/* Sidebar - mobile */}
      {mobileOpen && (
        <>
          <div
            className="fixed inset-0 z-40 bg-black/50 md:hidden"
            onClick={() => setMobileOpen(false)}
          />
          <aside className="fixed inset-y-0 left-0 z-50 flex w-64 flex-col bg-navy text-navy-foreground md:hidden">
            <SidebarContent
              pathname={pathname}
              organization={organization}
              onClose={() => setMobileOpen(false)}
            />
          </aside>
        </>
      )}

      {/* Main */}
      <div className="flex flex-1 flex-col md:pl-64">
        <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-border bg-background/95 px-4 backdrop-blur md:px-6">
          <div className="flex items-center gap-3">
            <Button
              variant="ghost"
              size="icon"
              className="md:hidden"
              onClick={() => setMobileOpen(true)}
            >
              <Menu className="h-5 w-5" />
            </Button>
            <h2 className="text-sm font-medium text-muted-foreground">
              {organization.name}
            </h2>
          </div>
          <div className="flex items-center gap-2">
            <div className="relative">
              <Button
                variant="ghost"
                size="icon"
                onClick={() => {
                  setShowNotifs((v) => !v);
                  if (!showNotifs && unread > 0) markAllRead();
                }}
                className="relative"
              >
                <Bell className="h-5 w-5" />
                {unread > 0 && (
                  <span className="absolute right-1.5 top-1.5 flex h-4 w-4 items-center justify-center rounded-full bg-danger text-[10px] font-bold text-white">
                    {unread}
                  </span>
                )}
              </Button>
              {showNotifs && (
                <div className="absolute right-0 top-12 z-50 w-80 rounded-lg border border-border bg-popover shadow-lg">
                  <div className="flex items-center justify-between border-b border-border px-4 py-3">
                    <span className="text-sm font-semibold">Notifications</span>
                    <Button variant="ghost" size="sm" onClick={() => setShowNotifs(false)}>
                      <X className="h-4 w-4" />
                    </Button>
                  </div>
                  <div className="max-h-96 overflow-y-auto">
                    {notifications.length === 0 ? (
                      <p className="px-4 py-8 text-center text-sm text-muted-foreground">
                        No notifications yet.
                      </p>
                    ) : (
                      notifications.map((n) => (
                        <div
                          key={n.id}
                          className={cn(
                            'border-b border-border px-4 py-3 last:border-0',
                            !n.read && 'bg-primary/5'
                          )}
                        >
                          <p className="text-sm font-medium">{n.title}</p>
                          <p className="mt-0.5 text-xs text-muted-foreground">{n.message}</p>
                          <p className="mt-1 text-[10px] text-muted-foreground">
                            {formatRelativeTime(n.created_at)}
                          </p>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}
            </div>
            <Avatar className="h-8 w-8">
              <AvatarFallback className="bg-primary/10 text-xs font-medium text-primary">
                {initials}
              </AvatarFallback>
            </Avatar>
            <Button variant="ghost" size="icon" onClick={handleSignOut} title="Sign out">
              <LogOut className="h-5 w-5" />
            </Button>
          </div>
        </header>
        <main className="flex-1 px-4 py-6 md:px-6 md:py-8">{children}</main>
      </div>
    </div>
  );

  function SidebarContent({
    pathname,
    organization,
    onClose,
  }: {
    pathname: string;
    organization: { name: string };
    onClose: () => void;
  }) {
    return (
      <>
        <div className="flex items-center justify-between border-b border-white/10 px-5 py-4">
          <Link href="/app/dashboard" className="flex items-center gap-2" onClick={onClose}>
            <ShieldCheck className="h-7 w-7 text-primary" />
            <span className="text-lg font-semibold">Secure360</span>
          </Link>
          <Button variant="ghost" size="icon" className="md:hidden text-navy-foreground" onClick={onClose}>
            <X className="h-5 w-5" />
          </Button>
        </div>
        <nav className="flex-1 space-y-1 px-3 py-4">
          {NAV.map((item) => {
            const active = pathname === item.href || pathname.startsWith(item.href + '/');
            return (
              <Link
                key={item.href}
                href={item.href}
                onClick={onClose}
                className={cn(
                  'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors',
                  active
                    ? 'bg-primary text-primary-foreground'
                    : 'text-navy-foreground/70 hover:bg-white/10 hover:text-navy-foreground'
                )}
              >
                <item.icon className="h-5 w-5" />
                {item.label}
              </Link>
            );
          })}
        </nav>
        <div className="border-t border-white/10 px-5 py-4">
          <p className="truncate text-sm font-medium text-navy-foreground">{organization.name}</p>
          <p className="truncate text-xs text-navy-foreground/50">{user?.email}</p>
        </div>
      </>
    );
  }
}
