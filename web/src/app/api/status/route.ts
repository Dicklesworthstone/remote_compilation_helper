import { NextResponse } from 'next/server';
import { requestRchd } from '@/lib/rchd-client';

export const runtime = 'nodejs';

function jsonResponse(
  data: unknown,
  status: number,
  requestId: string,
  extraHeaders?: Record<string, string>
) {
  return NextResponse.json(data, {
    status,
    headers: {
      'X-Request-ID': requestId,
      ...extraHeaders,
    },
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
    const data = response.body ? JSON.parse(response.body) : {};
    return jsonResponse(data, status, requestId);
  } catch (error) {
    return jsonResponse(
      {
        error: 'rchd_unavailable',
        message: error instanceof Error ? error.message : 'Failed to connect to rchd',
        request_id: requestId,
      },
      503,
      requestId
    );
  }
}

