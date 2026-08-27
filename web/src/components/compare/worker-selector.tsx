'use client';

import { useState, useRef, useEffect, useCallback } from 'react';
import { Check, ChevronDown, X, Users, Trophy } from 'lucide-react';
import { Button } from '@/components/ui/button';
import type { WorkerStatusInfo } from '@/lib/types';

interface WorkerSelectorProps {
  /** All available workers */
  workers: WorkerStatusInfo[];
  /** Currently selected worker IDs */
  selectedIds: string[];
  /** Callback when selection changes */
  onSelectionChange: (ids: string[]) => void;
  /** Maximum workers that can be selected (default: 4) */
  maxSelection?: number;
  /** Whether the selector is disabled */
  disabled?: boolean;
}

const statusColors: Record<string, string> = {
  healthy: 'text-healthy',
  degraded: 'text-warning',
  unreachable: 'text-error',
  draining: 'text-draining',
  disabled: 'text-muted-foreground',
};

export function WorkerSelector({
  workers,
  selectedIds,
  onSelectionChange,
  maxSelection = 4,
  disabled = false,
}: WorkerSelectorProps) {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Close dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const toggleWorker = useCallback(
    (workerId: string) => {
      if (selectedIds.includes(workerId)) {
        onSelectionChange(selectedIds.filter((id) => id !== workerId));
      } else if (selectedIds.length < maxSelection) {
        onSelectionChange([...selectedIds, workerId]);
      }
    },
    [selectedIds, onSelectionChange, maxSelection]
  );

  const clearAll = useCallback(() => {
    onSelectionChange([]);
  }, [onSelectionChange]);

  const selectTopN = useCallback(
    (n: number) => {
      const sortedByScore = [...workers]
        .filter((w) => w.status === 'healthy')
        .sort((a, b) => b.speed_score - a.speed_score)
        .slice(0, Math.min(n, maxSelection));
      onSelectionChange(sortedByScore.map((w) => w.id));
      setIsOpen(false);
    },
    [workers, onSelectionChange, maxSelection]
  );

  const isAtMax = selectedIds.length >= maxSelection;

  return (
    <div className="relative" ref={dropdownRef}>
      <div className="flex items-center gap-2">
        {/* Main dropdown trigger */}
        <Button
          variant="outline"
          onClick={() => setIsOpen(!isOpen)}
          disabled={disabled}
          className="min-w-[200px] justify-between"
          aria-expanded={isOpen}
          aria-haspopup="listbox"
        >
          <span className="flex items-center gap-2">
            <Users className="w-4 h-4" />
            {selectedIds.length === 0
              ? 'Select workers...'
              : `${selectedIds.length} worker${selectedIds.length === 1 ? '' : 's'} selected`}
          </span>
          <ChevronDown className={`w-4 h-4 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
        </Button>

        {/* Quick action: Compare top 3 */}
        <Button
          variant="ghost"
          size="sm"
          onClick={() => selectTopN(3)}
          disabled={disabled || workers.length === 0}
          title="Select top 3 by SpeedScore"
          className="gap-1.5"
        >
          <Trophy className="w-4 h-4" />
          <span className="hidden sm:inline">Top 3</span>
        </Button>

        {/* Clear all */}
        {selectedIds.length > 0 && (
          <Button
            variant="ghost"
            size="sm"
            onClick={clearAll}
            disabled={disabled}
            title="Clear selection"
          >
            <X className="w-4 h-4" />
          </Button>
        )}
      </div>

      {/* Dropdown menu */}
      {isOpen && (
        <div
          className="absolute z-50 mt-1 w-full min-w-[280px] bg-popover border border-border rounded-lg shadow-lg py-1 max-h-[300px] overflow-y-auto"
          role="listbox"
          aria-multiselectable="true"
        >
          {workers.length === 0 ? (
            <div className="px-3 py-2 text-sm text-muted-foreground">No workers available</div>
          ) : (() => {
            const selectedSet = new Set(selectedIds);
            return workers.map((worker) => {
              const isSelected = selectedSet.has(worker.id);
              const isDisabled = !isSelected && isAtMax;

              return (
                <button
                  key={worker.id}
                  type="button"
                  onClick={() => !isDisabled && toggleWorker(worker.id)}
                  disabled={isDisabled}
                  className={`w-full px-3 py-2 text-left flex items-center gap-3 hover:bg-muted/50 transition-colors ${
                    isDisabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'
                  } ${isSelected ? 'bg-muted/30' : ''}`}
                  role="option"
                  aria-selected={isSelected}
                >
                  <div
                    className={`w-5 h-5 rounded border flex items-center justify-center ${
                      isSelected
                        ? 'bg-primary border-primary text-primary-foreground'
                        : 'border-border'
                    }`}
                  >
                    {isSelected && <Check className="w-3.5 h-3.5" />}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="font-medium truncate">{worker.id}</div>
                    <div className="text-xs text-muted-foreground truncate">
                      {worker.user}@{worker.host}
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="font-mono text-sm">{worker.speed_score.toFixed(1)}</div>
                    <div className={`text-xs ${statusColors[worker.status]}`}>
                      {worker.status}
                    </div>
                  </div>
                </button>
              );
            });
          })()}

          {isAtMax && (
            <div className="px-3 py-2 text-xs text-muted-foreground border-t border-border mt-1">
              Maximum {maxSelection} workers can be selected
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export type { WorkerSelectorProps };
