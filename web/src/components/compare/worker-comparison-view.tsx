'use client';

import { useState, useCallback, useMemo, useEffect } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { Scale, Share2 } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { WorkerSelector } from './worker-selector';
import { ComparisonTable } from './comparison-table';
import { ComparisonRadar } from './comparison-radar';
import type { WorkerStatusInfo, SpeedScoreView } from '@/lib/types';

interface WorkerComparisonViewProps {
  /** All available workers */
  workers: WorkerStatusInfo[];
  /** Optional SpeedScore data for radar chart component scores */
  speedScores?: Map<string, SpeedScoreView>;
  /** Initial selected worker IDs (from URL or props) */
  initialSelection?: string[];
  /** Callback when clicking view details for a worker */
  onViewDetails?: (workerId: string) => void;
  /** Maximum workers that can be compared */
  maxWorkers?: number;
  /** Enable URL-based shareable selection */
  enableSharing?: boolean;
}

export function WorkerComparisonView({
  workers,
  speedScores,
  initialSelection = [],
  onViewDetails,
  maxWorkers = 4,
  enableSharing = true,
}: WorkerComparisonViewProps) {
  const router = useRouter();
  const searchParams = useSearchParams();

  // Initialize selection from URL params or props
  const [selectedIds, setSelectedIds] = useState<string[]>(() => {
    if (enableSharing && typeof window !== 'undefined') {
      const urlWorkers = searchParams.get('workers');
      if (urlWorkers) {
        const ids = urlWorkers.split(',').filter(Boolean);
        // Validate that all IDs exist in workers list
        return ids.filter((id) => workers.some((w) => w.id === id)).slice(0, maxWorkers);
      }
    }
    return initialSelection;
  });

  // Update URL when selection changes
  useEffect(() => {
    if (!enableSharing) return;

    const currentWorkers = searchParams.get('workers');
    const newWorkers = selectedIds.length > 0 ? selectedIds.join(',') : null;

    if (currentWorkers !== newWorkers) {
      const params = new URLSearchParams(searchParams.toString());
      if (newWorkers) {
        params.set('workers', newWorkers);
      } else {
        params.delete('workers');
      }
      const newUrl = params.toString() ? `?${params.toString()}` : window.location.pathname;
      router.replace(newUrl, { scroll: false });
    }
  }, [selectedIds, searchParams, router, enableSharing]);

  const handleSelectionChange = useCallback((ids: string[]) => {
    setSelectedIds(ids);
  }, []);

  const handleShare = useCallback(async () => {
    if (selectedIds.length === 0) {
      toast.error('Select workers to share comparison');
      return;
    }

    const url = new URL(window.location.href);
    url.searchParams.set('workers', selectedIds.join(','));

    try {
      await navigator.clipboard.writeText(url.toString());
      toast.success('Comparison URL copied to clipboard');
    } catch {
      toast.error('Failed to copy URL');
    }
  }, [selectedIds]);

  // Filter selected workers from the full list
  const selectedWorkers = useMemo(() => {
    const idSet = new Set(selectedIds);
    return workers.filter((w) => idSet.has(w.id));
  }, [workers, selectedIds]);

  return (
    <div className="space-y-6">
      {/* Header with selector and actions */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold flex items-center gap-2">
            <Scale className="w-5 h-5" />
            Worker Comparison
          </h2>
          <p className="text-sm text-muted-foreground mt-1">
            Compare up to {maxWorkers} workers side-by-side
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <WorkerSelector
            workers={workers}
            selectedIds={selectedIds}
            onSelectionChange={handleSelectionChange}
            maxSelection={maxWorkers}
          />
          {enableSharing && selectedIds.length > 0 && (
            <Button
              variant="outline"
              size="sm"
              onClick={handleShare}
              className="gap-1.5"
              title="Copy shareable URL"
            >
              <Share2 className="w-4 h-4" />
              <span className="hidden sm:inline">Share</span>
            </Button>
          )}
        </div>
      </div>

      {/* Comparison content */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Table comparison - full width on mobile, half on large screens */}
        <div className="lg:col-span-1">
          <ComparisonTable workers={selectedWorkers} onViewDetails={onViewDetails} />
        </div>

        {/* Radar chart - full width on mobile, half on large screens */}
        <div className="lg:col-span-1">
          <ComparisonRadar workers={selectedWorkers} speedScores={speedScores} />
        </div>
      </div>

      {/* Mobile: Stack vertically instead of grid */}
      <style jsx>{`
        @media (max-width: 1023px) {
          .grid {
            grid-template-columns: 1fr;
          }
        }
      `}</style>
    </div>
  );
}

export type { WorkerComparisonViewProps };
