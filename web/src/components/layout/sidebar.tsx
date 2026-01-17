'use client';

import { useEffect, useState } from 'react';
import { Server, History, Settings, Activity, Home, Menu, X } from 'lucide-react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { AnimatePresence, motion } from 'motion/react';

const navItems = [
  { href: '/', icon: Home, label: 'Overview' },
  { href: '/workers', icon: Server, label: 'Workers' },
  { href: '/builds', icon: History, label: 'Build History' },
  { href: '/metrics', icon: Activity, label: 'Metrics' },
  { href: '/settings', icon: Settings, label: 'Settings' },
];

const STORAGE_KEY = 'rch.sidebar.open';

interface SidebarContentProps {
  pathname: string;
  onNavigate?: () => void;
  variant: 'desktop' | 'mobile';
}

function SidebarContent({ pathname, onNavigate, variant }: SidebarContentProps) {
  return (
    <>
      <div className="p-4 border-b border-border">
        <Link href="/" className="flex items-center gap-2" onClick={onNavigate}>
          <div className="w-8 h-8 rounded-lg bg-primary flex items-center justify-center">
            <Server className="w-5 h-5 text-primary-foreground" />
          </div>
          <span className="text-lg font-semibold">RCH Dashboard</span>
        </Link>
      </div>

      <nav className="flex-1 p-4">
        <ul className="space-y-1">
          {navItems.map((item) => {
            const isActive = pathname === item.href;
            return (
              <li key={item.href}>
                <Link
                  href={item.href}
                  onClick={onNavigate}
                  className={`flex items-center gap-3 px-3 py-2 rounded-lg transition-colors relative ${
                    isActive
                      ? 'text-primary'
                      : 'text-muted-foreground hover:text-foreground hover:bg-surface-elevated'
                  }`}
                >
                  {isActive && (
                    <motion.div
                      layoutId={`active-nav-${variant}`}
                      className="absolute inset-0 bg-surface-elevated rounded-lg"
                      initial={false}
                      transition={{ type: 'spring', stiffness: 500, damping: 30 }}
                    />
                  )}
                  <item.icon className="w-5 h-5 relative z-10" />
                  <span className="relative z-10">{item.label}</span>
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>

      <div className="p-4 border-t border-border">
        <div className="text-xs text-muted-foreground">
          <span>Version </span>
          <span className="font-mono">0.1.0</span>
        </div>
      </div>
    </>
  );
}

export function Sidebar() {
  const pathname = usePathname();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [hydrated, setHydrated] = useState(false);

  useEffect(() => {
    setHydrated(true);
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored === 'true') {
        setSidebarOpen(true);
      }
    } catch {
      // Ignore storage errors (private mode, disabled storage)
    }
  }, []);

  useEffect(() => {
    if (!hydrated) return;
    try {
      localStorage.setItem(STORAGE_KEY, String(sidebarOpen));
    } catch {
      // Ignore storage errors (private mode, disabled storage)
    }
  }, [sidebarOpen, hydrated]);

  return (
    <>
      <button
        type="button"
        data-testid="hamburger-menu"
        aria-label={sidebarOpen ? 'Close navigation' : 'Open navigation'}
        aria-expanded={sidebarOpen}
        aria-controls="mobile-sidebar"
        onClick={() => setSidebarOpen((open) => !open)}
        className="fixed top-4 left-4 z-[60] flex h-10 w-10 items-center justify-center rounded-lg border border-border bg-surface/95 text-foreground shadow-lg backdrop-blur md:hidden"
      >
        {sidebarOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
      </button>

      <aside className="hidden md:flex w-64 bg-surface border-r border-border h-screen flex-col">
        <SidebarContent pathname={pathname} variant="desktop" />
      </aside>

      <AnimatePresence>
        {sidebarOpen && (
          <>
            <motion.div
              data-testid="backdrop"
              className="fixed inset-0 z-40 bg-black/50 md:hidden"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setSidebarOpen(false)}
            />
            <motion.aside
              id="mobile-sidebar"
              data-testid="sidebar"
              className="fixed inset-y-0 left-0 z-50 w-64 bg-surface border-r border-border flex flex-col md:hidden"
              initial={{ x: '-100%' }}
              animate={{ x: 0 }}
              exit={{ x: '-100%' }}
              transition={{ type: 'spring', stiffness: 320, damping: 35 }}
            >
              <SidebarContent
                pathname={pathname}
                variant="mobile"
                onNavigate={() => setSidebarOpen(false)}
              />
            </motion.aside>
          </>
        )}
      </AnimatePresence>
    </>
  );
}
