'use client';

import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';

interface WorkerCardSkeletonProps {
  className?: string;
}

export function WorkerCardSkeleton({ className }: WorkerCardSkeletonProps) {
  return (
    <div
      className={cn('bg-card border border-border rounded-lg p-4', className)}
      data-testid="worker-card-skeleton"
    >
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-3">
          <Skeleton className="w-10 h-10 rounded-lg" />
          <div className="space-y-2">
            <Skeleton className="h-4 w-24" />
            <Skeleton className="h-3 w-32" />
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Skeleton className="h-5 w-10 rounded-full" />
          <Skeleton className="h-6 w-16 rounded-full" />
        </div>
      </div>

      <div className="mb-3 space-y-2">
        <div className="flex justify-between">
          <Skeleton className="h-3 w-16" />
          <Skeleton className="h-3 w-12" />
        </div>
        <div className="h-2 bg-surface-elevated rounded-full overflow-hidden">
          <Skeleton className="h-2 w-2/3 rounded-full" />
        </div>
      </div>

      <div className="flex items-center gap-4">
        <Skeleton className="h-3 w-24" />
        <Skeleton className="h-3 w-20" />
      </div>
    </div>
  );
}

interface WorkersGridSkeletonProps {
  count?: number;
}

export function WorkersGridSkeleton({ count = 6 }: WorkersGridSkeletonProps) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      {Array.from({ length: count }).map((_, index) => (
        <WorkerCardSkeleton key={`worker-skeleton-${index}`} />
      ))}
    </div>
  );
}
