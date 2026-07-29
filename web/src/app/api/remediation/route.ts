import { NextResponse } from 'next/server';
import { requestRchd } from '@/lib/rchd-client';
import type { RemediationView, StatusResponse } from '@/lib/types';

export const runtime = 'nodejs';

// Stable JSON endpoint for the operator-facing remediation view
// (bd-session-history-remediation-ocv9i.14.4). Proxies the daemon `/status`
// socket and returns only the `remediation` field, which the daemon assembles
// redacted-by-construction (no hostnames, SSH users, paths, or secrets).

function jsonResponse(data: unknown, status: number, requestId: string) {
  return NextResponse.json(data, {
    status,
    headers: { 'X-Request-ID': requestId },
  });
}

function parseStatusCode(statusLine: string): number {
  const match = statusLine.match(/\s(\d{3})\s/);
  if (!match) return 200;
  const code = Number(match[1]);
  return Number.isFinite(code) ? code : 200;
}

export async function GET() {
  const requestId = crypto.randomUUID();

  try {
    const response = await requestRchd('/status');
    const status = parseStatusCode(response.statusLine);
    if (status >= 400) {
      return jsonResponse(
        { error: 'rchd_error', message: response.statusLine },
        status,
        requestId
      );
    }
    const body = response.body ? (JSON.parse(response.body) as StatusResponse) : null;
    const remediation: RemediationView | null = body?.remediation ?? null;
    if (!remediation) {
      return jsonResponse(
        {
          error: 'remediation_unavailable',
          message:
            'Daemon did not report a remediation view (it may be starting up or predate this feature).',
        },
        503,
        requestId
      );
    }
    return jsonResponse(remediation, 200, requestId);
  } catch (error) {
    return jsonResponse(
      {
        error: 'rchd_unavailable',
        message: error instanceof Error ? error.message : 'Failed to connect to rchd',
      },
      503,
      requestId
    );
  }
}
