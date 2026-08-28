/** Types for `./problems.js` — see that file for the semantics. */

import type { ActiveBuild, Alert, Dispatcher, Issue, RemediationHint, Worker } from "./types";

export type ProblemSeverity = "critical" | "warn" | "info";

export interface Problem {
  severity: ProblemSeverity;
  kind: string;
  target: string;
  detail: string;
  /** ISO time the daemon first raised it, or "". */
  since: string;
  /** Command to run, or "". */
  action: string;
  /** Where to run it: a dev machine id, "collector", or "". */
  on: string;
}

export interface NextAction {
  severity: ProblemSeverity;
  on: string;
  run: string;
  /** `|`-joined targets this command addresses. */
  fixes: string;
}

export interface FleetVersion {
  version: string | null;
  machines: number;
  off_version: string[];
}

export interface ProblemKindInfo {
  severity: ProblemSeverity;
  meaning: string;
  fix: string;
}

export const SEVERITY_RANK: Record<ProblemSeverity, number>;
export const PROBLEM_KINDS: Record<string, ProblemKindInfo>;

export type ProblemWorker = Worker & { health: string; reason?: string; healthReason?: string };
export type ProblemDev = Dispatcher & {
  level: string;
  reason?: string;
  levelReason?: string;
  remediation_hints?: RemediationHint[];
  alert_records?: Alert[];
  issue_records?: Issue[];
  active_records?: ActiveBuild[];
};

export function fleetVersion(devs: readonly Pick<Dispatcher, "id" | "reachable" | "daemon">[]): FleetVersion;

export function buildProblems(input: {
  workers: readonly ProblemWorker[];
  devs: readonly ProblemDev[];
  snapshotValid?: boolean;
  ageSeconds?: number;
  staleAfter?: number;
}): { problems: Problem[]; next_actions: NextAction[]; fleet_version: FleetVersion };
