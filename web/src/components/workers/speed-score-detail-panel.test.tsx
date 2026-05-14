import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import {
  SpeedScoreDetailPanel,
  SpeedScoreDetailPanelSkeleton,
  SpeedScoreDetailPanelError,
  SpeedScoreDetailPanelEmpty,
  TotalScoreBadge,
} from './speed-score-detail-panel';
import { ComponentRow } from './component-row';
import { ComponentBreakdown } from './component-breakdown';
import type { SpeedScoreView, BenchmarkResults, PartialSpeedScore } from '@/lib/types';

// Mock framer-motion to avoid animation issues in tests
vi.mock('motion/react', () => ({
  motion: {
    div: ({ children, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
      <div {...props}>{children}</div>
    ),
  },
  AnimatePresence: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

const mockSpeedScore: SpeedScoreView = {
  total: 85.9,
  cpu_score: 90,
  memory_score: 78,
  disk_score: 83,
  network_score: 88,
  compilation_score: 87,
  measured_at: '2026-01-17T10:00:00Z',
  version: 1,
};

const mockRawResults: BenchmarkResults = {
  cpu: { gflops: 425.3 },
  memory: { bandwidth_gbps: 42.1 },
  disk: { sequential_read_mbps: 2450, random_read_iops: 125000 },
  network: { download_mbps: 850, upload_mbps: 420 },
  compilation: { units_per_sec: 45.2 },
};

const mockPartialSpeedScore: PartialSpeedScore = {
  is_partial: true,
  failed_phase: 'network',
  total: 65.2,
  cpu_score: 90,
  memory_score: 78,
  disk_score: 83,
  network_score: undefined,
  compilation_score: undefined,
  measured_at: '2026-01-17T10:00:00Z',
  version: 1,
};

describe('SpeedScoreDetailPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('loading state', () => {
    it('renders skeleton when loading', () => {
      console.log('[TEST] Rendering loading state');

      render(
        <SpeedScoreDetailPanel
          workerId="css"
          speedscore={null}
          isLoading={true}
        />
      );

      const skeleton = screen.getByTestId('speedscore-detail-panel-loading');
      expect(skeleton).toBeInTheDocument();
      expect(skeleton).toHaveAttribute('aria-busy', 'true');

      console.log('[TEST] PASSED: Loading state shows skeleton');
    });
  });

  describe('error state', () => {
    it('renders error with retry button', () => {
      console.log('[TEST] Rendering error state');
      const onRetry = vi.fn();

      render(
        <SpeedScoreDetailPanel
          workerId="css"
          speedscore={null}
          error={new Error('Connection timeout')}
          onRetry={onRetry}
        />
      );

      expect(screen.getByText(/Failed to load/)).toBeInTheDocument();
      expect(screen.getByText('Connection timeout')).toBeInTheDocument();

      fireEvent.click(screen.getByText('Try Again'));
      expect(onRetry).toHaveBeenCalledTimes(1);

      console.log('[TEST] PASSED: Error state with retry');
    });

    it('renders error without retry button when onRetry not provided', () => {
      render(
        <SpeedScoreDetailPanel
          workerId="css"
          speedscore={null}
          error={new Error('Server error')}
        />
      );

      expect(screen.queryByText('Try Again')).not.toBeInTheDocument();
    });
  });

  describe('empty state (not benchmarked)', () => {
    it('shows empty state for null speedscore', () => {
      console.log('[TEST] Rendering empty state');

      render(
        <SpeedScoreDetailPanel workerId="new_worker" speedscore={null} />
      );

      expect(screen.getByText('Not Yet Benchmarked')).toBeInTheDocument();
      expect(
        screen.getByText(/has not completed a benchmark/)
      ).toBeInTheDocument();

      console.log('[TEST] PASSED: Empty state shown');
    });

    it('shows benchmark button for admin', () => {
      const onTrigger = vi.fn();

      render(
        <SpeedScoreDetailPanel
          workerId="new_worker"
          speedscore={null}
          isAdmin={true}
          onTriggerBenchmark={onTrigger}
        />
      );

      const button = screen.getByText('Run Benchmark Now');
      fireEvent.click(button);
      expect(onTrigger).toHaveBeenCalled();
    });

    it('hides benchmark button for non-admin', () => {
      render(
        <SpeedScoreDetailPanel
          workerId="new_worker"
          speedscore={null}
          isAdmin={false}
          onTriggerBenchmark={vi.fn()}
        />
      );

      expect(screen.queryByText('Run Benchmark Now')).not.toBeInTheDocument();
    });
  });

  describe('partial results state', () => {
    it('shows partial results warning', () => {
      render(
        <SpeedScoreDetailPanel
          workerId="css"
          speedscore={mockPartialSpeedScore}
        />
      );

      expect(screen.getByText('Partial Results')).toBeInTheDocument();
      expect(screen.getByText(/failed during/)).toBeInTheDocument();
      expect(screen.getByText(/network/)).toBeInTheDocument();
    });

    it('shows retry button in partial state', () => {
      const onRetry = vi.fn();

      render(
        <SpeedScoreDetailPanel
          workerId="css"
          speedscore={mockPartialSpeedScore}
          onTriggerBenchmark={onRetry}
        />
      );

      const button = screen.getByText('Retry Benchmark');
      fireEvent.click(button);
      expect(onRetry).toHaveBeenCalled();
    });
  });

  describe('normal rendering', () => {
    it('displays all component scores', () => {
      console.log('[TEST] Rendering component breakdown');

      render(
        <SpeedScoreDetailPanel
          workerId="css"
          speedscore={mockSpeedScore}
          rawResults={mockRawResults}
        />
      );

      expect(screen.getByTestId('component-cpu')).toBeInTheDocument();
      expect(screen.getByTestId('component-memory')).toBeInTheDocument();
      expect(screen.getByTestId('component-disk')).toBeInTheDocument();
      expect(screen.getByTestId('component-network')).toBeInTheDocument();
      expect(screen.getByTestId('component-compilation')).toBeInTheDocument();

      console.log('[TEST] PASSED: All components displayed');
    });

    it('displays weights correctly', () => {
      render(
        <SpeedScoreDetailPanel
          workerId="css"
          speedscore={mockSpeedScore}
          rawResults={mockRawResults}
        />
      );

      // CPU weight: 0.30
      expect(screen.getByText('×0.30')).toBeInTheDocument();
      // Memory and Network both have weight 0.15, so use getAllByText
      const weight015Elements = screen.getAllByText('×0.15');
      expect(weight015Elements.length).toBe(2); // Memory and Network
      // Disk and Compilation both have weight 0.20, so use getAllByText
      const weight020Elements = screen.getAllByText('×0.20');
      expect(weight020Elements.length).toBe(2); // Disk and Compilation
    });

    it('displays total score', () => {
      render(
        <SpeedScoreDetailPanel
          workerId="css"
          speedscore={mockSpeedScore}
          rawResults={mockRawResults}
        />
      );

      expect(screen.getByText('86')).toBeInTheDocument(); // Rounded total
    });

    it('displays raw benchmark values', () => {
      render(
        <SpeedScoreDetailPanel
          workerId="css"
          speedscore={mockSpeedScore}
          rawResults={mockRawResults}
        />
      );

      expect(screen.getByText('425.3 GFLOPS')).toBeInTheDocument();
      expect(screen.getByText('42.1 GB/s')).toBeInTheDocument();
      expect(screen.getByText(/850↓\/420↑ Mbps/)).toBeInTheDocument();
    });

    it('handles missing raw results gracefully', () => {
      render(
        <SpeedScoreDetailPanel
          workerId="css"
          speedscore={mockSpeedScore}
          rawResults={null}
        />
      );

      // Should show scores but raw values as N/A
      expect(screen.getByText('90')).toBeInTheDocument(); // CPU score
      const naElements = screen.getAllByText('N/A');
      expect(naElements.length).toBeGreaterThan(0);
    });

    it('displays benchmark timestamp', () => {
      render(
        <SpeedScoreDetailPanel
          workerId="css"
          speedscore={mockSpeedScore}
          rawResults={mockRawResults}
        />
      );

      expect(screen.getByText(/Benchmarked:/)).toBeInTheDocument();
    });

    it('displays version', () => {
      render(
        <SpeedScoreDetailPanel
          workerId="css"
          speedscore={mockSpeedScore}
          rawResults={mockRawResults}
        />
      );

      expect(screen.getByText('Version: 1')).toBeInTheDocument();
    });
  });

  describe('expand/collapse', () => {
    it('toggles on header click', () => {
      const onToggle = vi.fn();

      render(
        <SpeedScoreDetailPanel
          workerId="css"
          speedscore={mockSpeedScore}
          rawResults={mockRawResults}
          isExpanded={true}
          onToggle={onToggle}
        />
      );

      fireEvent.click(screen.getByText(/SpeedScore Details: css/));
      expect(onToggle).toHaveBeenCalled();
    });

    it('toggles on Enter key', () => {
      const onToggle = vi.fn();

      render(
        <SpeedScoreDetailPanel
          workerId="css"
          speedscore={mockSpeedScore}
          rawResults={mockRawResults}
          onToggle={onToggle}
        />
      );

      const header = screen.getByRole('button', { name: /Toggle SpeedScore details/ });
      fireEvent.keyDown(header, { key: 'Enter' });
      expect(onToggle).toHaveBeenCalled();
    });

    it('toggles on Space key', () => {
      const onToggle = vi.fn();

      render(
        <SpeedScoreDetailPanel
          workerId="css"
          speedscore={mockSpeedScore}
          rawResults={mockRawResults}
          onToggle={onToggle}
        />
      );

      const header = screen.getByRole('button', { name: /Toggle SpeedScore details/ });
      fireEvent.keyDown(header, { key: ' ' });
      expect(onToggle).toHaveBeenCalled();
    });

    it('collapses on Escape when expanded', () => {
      const onToggle = vi.fn();

      render(
        <SpeedScoreDetailPanel
          workerId="css"
          speedscore={mockSpeedScore}
          rawResults={mockRawResults}
          isExpanded={true}
          onToggle={onToggle}
        />
      );

      const header = screen.getByRole('button', { name: /Toggle SpeedScore details/ });
      fireEvent.keyDown(header, { key: 'Escape' });
      expect(onToggle).toHaveBeenCalled();
    });
  });

  describe('re-benchmark button', () => {
    it('shows for admin users', () => {
      const onTrigger = vi.fn();

      render(
        <SpeedScoreDetailPanel
          workerId="css"
          speedscore={mockSpeedScore}
          rawResults={mockRawResults}
          isAdmin={true}
          onTriggerBenchmark={onTrigger}
        />
      );

      expect(screen.getByText('Re-benchmark')).toBeInTheDocument();
    });

    it('calls onTriggerBenchmark when clicked', () => {
      const onTrigger = vi.fn();

      render(
        <SpeedScoreDetailPanel
          workerId="css"
          speedscore={mockSpeedScore}
          rawResults={mockRawResults}
          isAdmin={true}
          onTriggerBenchmark={onTrigger}
        />
      );

      fireEvent.click(screen.getByText('Re-benchmark'));
      expect(onTrigger).toHaveBeenCalled();
    });

    it('hidden for non-admin users', () => {
      render(
        <SpeedScoreDetailPanel
          workerId="css"
          speedscore={mockSpeedScore}
          rawResults={mockRawResults}
          isAdmin={false}
          onTriggerBenchmark={vi.fn()}
        />
      );

      expect(screen.queryByText('Re-benchmark')).not.toBeInTheDocument();
    });
  });

  describe('accessibility', () => {
    it('has correct ARIA attributes', () => {
      render(
        <SpeedScoreDetailPanel
          workerId="css"
          speedscore={mockSpeedScore}
          rawResults={mockRawResults}
          isExpanded={true}
        />
      );

      const panel = screen.getByRole('region');
      expect(panel).toHaveAttribute('data-expanded', 'true');
      expect(panel).toHaveAttribute('aria-labelledby', 'panel-title-css');
    });

    it('header is keyboard navigable when onToggle provided', () => {
      render(
        <SpeedScoreDetailPanel
          workerId="css"
          speedscore={mockSpeedScore}
          rawResults={mockRawResults}
          onToggle={vi.fn()}
        />
      );

      // The header should have tabIndex=0, find it by its specific role and name
      const header = screen.getByRole('button', { name: /Toggle SpeedScore details/ });
      expect(header).toHaveAttribute('tabIndex', '0');
    });

    it('total score has aria-label', () => {
      render(
        <SpeedScoreDetailPanel
          workerId="css"
          speedscore={mockSpeedScore}
          rawResults={mockRawResults}
        />
      );

      const badge = screen.getByRole('status', { name: /Total SpeedScore: 86/ });
      expect(badge).toBeInTheDocument();
    });
  });
});

describe('ComponentRow', () => {
  it('displays component name', () => {
    render(
      <ComponentRow
        name="CPU"
        score={90}
        weight={0.3}
        rawValue="425 GFLOPS"
        description="Test description"
      />
    );

    expect(screen.getByText('CPU')).toBeInTheDocument();
  });

  it('calculates contribution correctly', () => {
    render(
      <ComponentRow
        name="CPU"
        score={90}
        weight={0.3}
        rawValue="425 GFLOPS"
        description="Test"
      />
    );

    // 90 × 0.30 = 27.0
    expect(screen.getByText('=27.0')).toBeInTheDocument();
  });

  it('handles null score (partial results)', () => {
    render(
      <ComponentRow
        name="Network"
        score={null}
        weight={0.15}
        rawValue="Not measured"
        description="Test"
        isPartial={true}
      />
    );

    // There are two '—' characters (score and contribution)
    const dashElements = screen.getAllByText('—');
    expect(dashElements.length).toBeGreaterThanOrEqual(1);
    // 'Not measured' appears twice (in bar and raw value column)
    const notMeasuredElements = screen.getAllByText('Not measured');
    expect(notMeasuredElements.length).toBeGreaterThanOrEqual(1);
  });

  it('shows info tooltip button', () => {
    render(
      <ComponentRow
        name="CPU"
        score={90}
        weight={0.3}
        rawValue="425 GFLOPS"
        description="CPU performance"
      />
    );

    const infoButton = screen.getByRole('button', { name: /Info about CPU/ });
    expect(infoButton).toBeInTheDocument();
  });

  it('applies partial styling when isPartial is true', () => {
    const { container } = render(
      <ComponentRow
        name="Network"
        score={null}
        weight={0.15}
        rawValue="Not measured"
        description="Test"
        isPartial={true}
      />
    );

    const row = container.firstChild;
    expect(row).toHaveClass('opacity-50');
  });
});

describe('ComponentBreakdown', () => {
  it('renders all five components', () => {
    render(
      <ComponentBreakdown speedscore={mockSpeedScore} rawResults={mockRawResults} />
    );

    expect(screen.getByTestId('component-cpu')).toBeInTheDocument();
    expect(screen.getByTestId('component-memory')).toBeInTheDocument();
    expect(screen.getByTestId('component-disk')).toBeInTheDocument();
    expect(screen.getByTestId('component-network')).toBeInTheDocument();
    expect(screen.getByTestId('component-compilation')).toBeInTheDocument();
  });

  it('displays total formula', () => {
    render(
      <ComponentBreakdown speedscore={mockSpeedScore} rawResults={mockRawResults} />
    );

    expect(screen.getByText(/Total = Σ\(score × weight\)/)).toBeInTheDocument();
    expect(screen.getByText('85.9')).toBeInTheDocument();
  });

  it('handles partial results correctly', () => {
    render(
      <ComponentBreakdown
        speedscore={mockPartialSpeedScore}
        partialUpTo="network"
      />
    );

    // CPU, Memory, Disk should have scores
    expect(screen.getByText('90')).toBeInTheDocument(); // CPU score

    // Network and Compilation should show "Not measured"
    const notMeasuredElements = screen.getAllByText('Not measured');
    expect(notMeasuredElements.length).toBeGreaterThanOrEqual(2);
  });
});

describe('TotalScoreBadge', () => {
  it('displays rounded score', () => {
    render(<TotalScoreBadge score={85.9} />);
    expect(screen.getByText('86')).toBeInTheDocument();
  });

  it('has correct aria-label', () => {
    render(<TotalScoreBadge score={85.9} />);
    expect(screen.getByRole('status')).toHaveAttribute(
      'aria-label',
      'Total SpeedScore: 86'
    );
  });

  it('applies excellent style for score >= 90', () => {
    const { container } = render(<TotalScoreBadge score={95} />);
    expect(container.firstChild).toHaveClass('text-emerald-700');
  });

  it('applies good style for score >= 70', () => {
    const { container } = render(<TotalScoreBadge score={75} />);
    expect(container.firstChild).toHaveClass('text-sky-700');
  });

  it('applies average style for score >= 50', () => {
    const { container } = render(<TotalScoreBadge score={55} />);
    expect(container.firstChild).toHaveClass('text-amber-700');
  });
});

describe('SpeedScoreDetailPanelSkeleton', () => {
  it('renders with aria-busy', () => {
    render(<SpeedScoreDetailPanelSkeleton />);
    const skeleton = screen.getByTestId('speedscore-detail-panel-loading');
    expect(skeleton).toHaveAttribute('aria-busy', 'true');
  });
});

describe('SpeedScoreDetailPanelError', () => {
  it('displays error message', () => {
    render(
      <SpeedScoreDetailPanelError
        workerId="test"
        error={new Error('Test error')}
      />
    );
    expect(screen.getByText('Test error')).toBeInTheDocument();
  });

  it('shows worker id in title', () => {
    render(
      <SpeedScoreDetailPanelError
        workerId="test-worker"
        error={new Error('Error')}
      />
    );
    expect(screen.getByText(/test-worker/)).toBeInTheDocument();
  });
});

describe('SpeedScoreDetailPanelEmpty', () => {
  it('displays worker id', () => {
    render(<SpeedScoreDetailPanelEmpty workerId="empty-worker" />);
    expect(screen.getByText(/empty-worker/)).toBeInTheDocument();
  });

  it('shows explanatory text', () => {
    render(<SpeedScoreDetailPanelEmpty workerId="test" />);
    expect(
      screen.getByText(/has not completed a benchmark/)
    ).toBeInTheDocument();
  });
});
