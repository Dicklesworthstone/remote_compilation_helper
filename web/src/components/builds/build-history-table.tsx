'use client';

import { useMemo, useState } from 'react';
import { CheckCircle, XCircle, Clock, Search, ChevronLeft, ChevronRight } from 'lucide-react';
import { motion } from 'motion/react';
import { Button } from '@/components/ui/button';
import { SortableTableHead } from '@/components/ui/table';
import type { BuildRecord, ActiveBuild } from '@/lib/types';

interface BuildHistoryTableProps {
  activeBuilds: ActiveBuild[];
  recentBuilds: BuildRecord[];
}

type BuildStatus = 'running' | 'success' | 'failed';
type BuildStatusFilter = 'all' | BuildStatus;
type SortKey = 'status' | 'project' | 'worker' | 'command' | 'duration' | 'time';
type SortDirection = 'asc' | 'desc';

interface BuildRow {
  rowKey: string;
  kind: 'active' | 'completed';
  status: BuildStatus;
  project_id: string;
  worker_id: string;
  command: string;
  duration_ms: number | null;
  timestamp: string;
  exit_code?: number;
}

const PAGE_SIZE = 25;

const statusSortOrder: Record<BuildStatus, number> = {
  running: 0,
  success: 1,
  failed: 2,
};

const defaultSortDirection: Record<SortKey, SortDirection> = {
  status: 'asc',
  project: 'asc',
  worker: 'asc',
  command: 'asc',
  duration: 'desc',
  time: 'desc',
};

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  const mins = Math.floor(ms / 60000);
  const secs = Math.floor((ms % 60000) / 1000);
  return `${mins}m ${secs}s`;
}

function formatTime(isoString: string): string {
  const date = new Date(isoString);
  return date.toLocaleTimeString(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function truncateCommand(cmd: string, maxLen = 40): string {
  if (cmd.length <= maxLen) return cmd;
  return cmd.slice(0, maxLen - 3) + '...';
}

export function BuildHistoryTable({ activeBuilds, recentBuilds }: BuildHistoryTableProps) {
  const [statusFilter, setStatusFilter] = useState<BuildStatusFilter>('all');
  const [workerFilter, setWorkerFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [sortKey, setSortKey] = useState<SortKey>('time');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');
  const [page, setPage] = useState(1);

  const rows = useMemo<BuildRow[]>(() => {
    const activeRows = activeBuilds.map((build) => ({
      rowKey: `active-${build.id}`,
      kind: 'active' as const,
      status: 'running' as const,
      project_id: build.project_id,
      worker_id: build.worker_id,
      command: build.command,
      duration_ms: null,
      timestamp: build.started_at,
    }));

    const completedRows = recentBuilds.map((build) => ({
      rowKey: `completed-${build.id}`,
      kind: 'completed' as const,
      status: (build.exit_code === 0 ? 'success' : 'failed') as BuildStatus,
      project_id: build.project_id,
      worker_id: build.worker_id ?? (build.location === 'local' ? 'local' : 'unknown'),
      command: build.command,
      duration_ms: build.duration_ms,
      timestamp: build.completed_at,
      exit_code: build.exit_code,
    }));

    return [...activeRows, ...completedRows];
  }, [activeBuilds, recentBuilds]);

  const workerOptions = useMemo(() => {
    const unique = new Set(rows.map((row) => row.worker_id));
    return Array.from(unique).sort((a, b) => a.localeCompare(b));
  }, [rows]);

  const filteredRows = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    const start = startDate ? new Date(`${startDate}T00:00:00`) : null;
    const end = endDate ? new Date(`${endDate}T23:59:59.999`) : null;
    const hasStart = start && !Number.isNaN(start.getTime());
    const hasEnd = end && !Number.isNaN(end.getTime());

    return rows.filter((row) => {
      if (statusFilter !== 'all' && row.status !== statusFilter) {
        return false;
      }
      if (workerFilter !== 'all' && row.worker_id !== workerFilter) {
        return false;
      }
      if (query && !row.command.toLowerCase().includes(query)) {
        return false;
      }
      if (hasStart || hasEnd) {
        const timestamp = new Date(row.timestamp).getTime();
        if (Number.isNaN(timestamp)) {
          return false;
        }
        if (hasStart && timestamp < start!.getTime()) {
          return false;
        }
        if (hasEnd && timestamp > end!.getTime()) {
          return false;
        }
      }
      return true;
    });
  }, [rows, statusFilter, workerFilter, searchQuery, startDate, endDate]);

  const sortedRows = useMemo(() => {
    const sorted = [...filteredRows];
    sorted.sort((a, b) => {
      let aValue: number | string;
      let bValue: number | string;

      switch (sortKey) {
        case 'status':
          aValue = statusSortOrder[a.status];
          bValue = statusSortOrder[b.status];
          break;
        case 'project':
          aValue = a.project_id;
          bValue = b.project_id;
          break;
        case 'worker':
          aValue = a.worker_id;
          bValue = b.worker_id;
          break;
        case 'command':
          aValue = a.command;
          bValue = b.command;
          break;
        case 'duration':
          aValue = a.duration_ms ?? -1;
          bValue = b.duration_ms ?? -1;
          break;
        case 'time':
        default:
          aValue = new Date(a.timestamp).getTime();
          bValue = new Date(b.timestamp).getTime();
          break;
      }

      let comparison = 0;
      if (typeof aValue === 'string' && typeof bValue === 'string') {
        comparison = aValue.localeCompare(bValue);
      } else {
        comparison = (aValue as number) - (bValue as number);
      }

      if (comparison === 0) {
        comparison = a.rowKey.localeCompare(b.rowKey);
      }

      return sortDirection === 'asc' ? comparison : -comparison;
    });
    return sorted;
  }, [filteredRows, sortKey, sortDirection]);

  const totalPages = Math.ceil(sortedRows.length / PAGE_SIZE);
  const showPagination = sortedRows.length > 50;
  const currentPage = showPagination ? Math.min(page, totalPages || 1) : 1;
  const pagedRows = showPagination
    ? sortedRows.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE)
    : sortedRows;

  const hasBuilds = rows.length > 0;

  if (!hasBuilds) {
    return (
      <div className="text-center py-12 text-muted-foreground">
        <p>No builds yet</p>
        <p className="text-sm mt-1">Run a build command to see history</p>
      </div>
    );
  }

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
      return;
    }
    setSortKey(key);
    setSortDirection(defaultSortDirection[key]);
  };

  const rangeLabel = showPagination
    ? `${(currentPage - 1) * PAGE_SIZE + 1}-${Math.min(currentPage * PAGE_SIZE, sortedRows.length)} of ${sortedRows.length}`
    : `${sortedRows.length} build${sortedRows.length === 1 ? '' : 's'}`;

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div className="flex flex-wrap gap-3">
          <div className="flex flex-col gap-1">
            <label htmlFor="build-status-filter" className="text-xs font-medium text-muted-foreground">Status</label>
            <select
              id="build-status-filter"
              value={statusFilter}
              onChange={(event) => {
                setStatusFilter(event.target.value as BuildStatusFilter);
                setPage(1);
              }}
              className="h-9 rounded-md border border-border bg-background px-3 text-sm text-foreground shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/50"
            >
              <option value="all">All</option>
              <option value="running">Running</option>
              <option value="success">Success</option>
              <option value="failed">Failed</option>
            </select>
          </div>

          <div className="flex flex-col gap-1">
            <label htmlFor="build-worker-filter" className="text-xs font-medium text-muted-foreground">Worker</label>
            <select
              id="build-worker-filter"
              value={workerFilter}
              onChange={(event) => {
                setWorkerFilter(event.target.value);
                setPage(1);
              }}
              className="h-9 rounded-md border border-border bg-background px-3 text-sm text-foreground shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/50"
            >
              <option value="all">All workers</option>
              {workerOptions.map((worker) => (
                <option key={worker} value={worker}>
                  {worker}
                </option>
              ))}
            </select>
          </div>

          <div className="flex flex-col gap-1">
            <label className="text-xs font-medium text-muted-foreground">Date range</label>
            <div className="flex items-center gap-2">
              <input
                type="date"
                value={startDate}
                onChange={(event) => {
                  setStartDate(event.target.value);
                  setPage(1);
                }}
                className="h-9 rounded-md border border-border bg-background px-2 text-xs text-foreground shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/50"
                aria-label="Start date"
              />
              <span className="text-xs text-muted-foreground">to</span>
              <input
                type="date"
                value={endDate}
                onChange={(event) => {
                  setEndDate(event.target.value);
                  setPage(1);
                }}
                className="h-9 rounded-md border border-border bg-background px-2 text-xs text-foreground shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/50"
                aria-label="End date"
              />
            </div>
          </div>
        </div>

        <div className="flex flex-col gap-1 min-w-[220px]">
          <label className="text-xs font-medium text-muted-foreground">Command search</label>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <input
              value={searchQuery}
              onChange={(event) => {
                setSearchQuery(event.target.value);
                setPage(1);
              }}
              placeholder="Filter commands..."
              className="h-9 w-full rounded-md border border-border bg-background pl-9 pr-3 text-sm text-foreground shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/50"
              aria-label="Search build commands"
            />
          </div>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border text-left text-muted-foreground">
            <SortableTableHead
              className="pb-3 font-medium"
              sorted={sortKey === 'status'}
              direction={sortDirection}
              onSort={() => handleSort('status')}
            >
              Status
            </SortableTableHead>
            <SortableTableHead
              className="pb-3 font-medium"
              sorted={sortKey === 'project'}
              direction={sortDirection}
              onSort={() => handleSort('project')}
            >
              Project
            </SortableTableHead>
            <SortableTableHead
              className="pb-3 font-medium"
              sorted={sortKey === 'worker'}
              direction={sortDirection}
              onSort={() => handleSort('worker')}
            >
              Worker
            </SortableTableHead>
            <SortableTableHead
              className="pb-3 font-medium"
              sorted={sortKey === 'command'}
              direction={sortDirection}
              onSort={() => handleSort('command')}
            >
              Command
            </SortableTableHead>
            <SortableTableHead
              className="pb-3 font-medium"
              sorted={sortKey === 'duration'}
              direction={sortDirection}
              onSort={() => handleSort('duration')}
            >
              Duration
            </SortableTableHead>
            <SortableTableHead
              className="pb-3 font-medium"
              sorted={sortKey === 'time'}
              direction={sortDirection}
              onSort={() => handleSort('time')}
            >
              Time
            </SortableTableHead>
          </tr>
        </thead>
        <tbody>
          {pagedRows.length === 0 ? (
            <tr>
              <td colSpan={6} className="py-10 text-center text-muted-foreground">
                No builds match the current filters.
              </td>
            </tr>
          ) : (
            pagedRows.map((row) => (
              <motion.tr
                key={row.rowKey}
                initial={{ opacity: 0, x: row.kind === 'active' ? -10 : 0 }}
                animate={{ opacity: 1, x: 0 }}
                className="border-b border-border/50"
              >
                <td className="py-3">
                  {row.status === 'running' ? (
                    <span className="flex items-center gap-1.5 text-warning">
                      <Clock className="w-4 h-4 animate-pulse" />
                      Running
                    </span>
                  ) : row.exit_code === 0 ? (
                    <span className="flex items-center gap-1.5 text-healthy">
                      <CheckCircle className="w-4 h-4" />
                      Success
                    </span>
                  ) : (
                    <span className="flex items-center gap-1.5 text-error">
                      <XCircle className="w-4 h-4" />
                      Failed ({row.exit_code})
                    </span>
                  )}
                </td>
                <td className="py-3 font-mono text-xs">{row.project_id}</td>
                <td className="py-3">{row.worker_id}</td>
                <td className="py-3 font-mono text-xs text-muted-foreground" title={row.command}>
                  {truncateCommand(row.command)}
                </td>
                <td className="py-3 font-mono text-xs">
                  {row.duration_ms === null ? '-' : formatDuration(row.duration_ms)}
                </td>
                <td className="py-3 text-muted-foreground">{formatTime(row.timestamp)}</td>
              </motion.tr>
            ))
          )}
        </tbody>
      </table>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-muted-foreground">
        <span>{rangeLabel}</span>
        {showPagination && (
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="icon-sm"
              onClick={() => setPage(Math.max(1, currentPage - 1))}
              disabled={currentPage <= 1}
              aria-label="Previous page"
            >
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <span className="text-xs">
              Page {currentPage} of {totalPages || 1}
            </span>
            <Button
              variant="outline"
              size="icon-sm"
              onClick={() => setPage(Math.min(totalPages, currentPage + 1))}
              disabled={currentPage >= totalPages}
              aria-label="Next page"
            >
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}
