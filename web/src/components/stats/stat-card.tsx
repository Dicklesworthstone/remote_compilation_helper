'use client';

import type { LucideIcon } from 'lucide-react';

interface StatCardProps {
  label: string;
  value: string | number;
  icon: LucideIcon;
  trend?: {
    value: number;
    isPositive: boolean;
  };
}

export function StatCard({ label, value, icon: Icon, trend }: StatCardProps) {
  return (
    <div
      className="bg-card border border-border rounded-lg p-4 transition-colors duration-200"
      data-testid="stat-card"
    >
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm text-muted-foreground">{label}</span>
        <Icon className="w-4 h-4 text-muted-foreground" />
      </div>
      <div className="flex items-end gap-2">
        <span className="text-2xl font-semibold text-foreground">{value}</span>
        {trend && (
          <span
            className={`text-xs ${trend.isPositive ? 'text-healthy' : 'text-error'}`}
          >
            {trend.isPositive ? '+' : ''}{trend.value}%
          </span>
        )}
      </div>
    </div>
  );
}
