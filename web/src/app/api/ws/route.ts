import net from 'node:net';
import { type NextRequest } from 'next/server';
import { getSocketPath } from '@/lib/rchd-client';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// Heartbeat interval in milliseconds (30 seconds)
const HEARTBEAT_INTERVAL_MS = 30_000;

interface RchdEvent {
  event?: string;
  data?: {
    worker_id?: string;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

/**
 * Check if an event matches the subscription filter.
 * If no filter is set, all events pass through.
 */
function matchesSubscription(event: RchdEvent, subscribedWorkers: Set<string> | null): boolean {
  // No filter - pass all events
  if (!subscribedWorkers || subscribedWorkers.size === 0) {
    return true;
  }

  // System events (heartbeat, connection status) always pass
  const eventType = event.event || '';
  if (eventType === 'heartbeat' || eventType === 'connected' || eventType === 'error') {
    return true;
  }

  // Check if event has a worker_id that matches subscription
  const workerId = event.data?.worker_id;
  if (workerId && subscribedWorkers.has(workerId)) {
    return true;
  }

  // No worker_id in event - pass it through (global events)
  if (!workerId) {
    return true;
  }

  return false;
}

/**
 * SSE endpoint that proxies events from rchd daemon.
 *
 * Query parameters:
 * - subscribe: Comma-separated list of worker IDs to filter events for.
 *              If not provided, all events are streamed.
 *
 * Features:
 * - Automatic heartbeat every 30 seconds to keep connection alive
 * - Worker subscription filtering
 * - Graceful error handling with error events
 *
 * Note: This uses Server-Sent Events (SSE) instead of WebSocket because
 * Next.js App Router doesn't support WebSocket upgrades natively.
 * SSE provides sufficient functionality for server→client event streaming.
 * For client→server communication, use the REST API endpoints.
 */
export async function GET(request: NextRequest) {
  const requestId = crypto.randomUUID();
  const encoder = new TextEncoder();
  let socket: net.Socket | null = null;
  let heartbeatInterval: ReturnType<typeof setInterval> | null = null;
  let isClosed = false;

  // Parse subscription filter from query params
  const subscribeParam = request.nextUrl.searchParams.get('subscribe');
  const subscribedWorkers: Set<string> | null = subscribeParam
    ? new Set(subscribeParam.split(',').map(s => s.trim()).filter(Boolean))
    : null;

  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      const socketPath = getSocketPath();

      // Helper to send SSE event
      const sendEvent = (eventType: string, data: unknown) => {
        if (isClosed) return;
        try {
          const payload = JSON.stringify(data);
          controller.enqueue(encoder.encode(`event: ${eventType}\ndata: ${payload}\n\n`));
        } catch {
          // Ignore encoding errors
        }
      };

      // Send initial connection event
      sendEvent('connected', {
        request_id: requestId,
        subscribed_workers: subscribedWorkers ? Array.from(subscribedWorkers) : null,
        timestamp: new Date().toISOString(),
      });

      // Start heartbeat
      heartbeatInterval = setInterval(() => {
        if (isClosed) return;
        sendEvent('heartbeat', {
          timestamp: new Date().toISOString(),
          request_id: requestId,
        });
      }, HEARTBEAT_INTERVAL_MS);

      // Connect to rchd
      socket = net.createConnection({ path: socketPath }, () => {
        socket!.write('GET /events HTTP/1.0\r\n\r\n');
      });

      let buffer = '';
      let headersDone = false;

      socket.setEncoding('utf8');

      socket.on('data', (chunk) => {
        if (isClosed) return;

        buffer += chunk;
        if (!headersDone) {
          const headerIndex = buffer.indexOf('\r\n\r\n');
          if (headerIndex === -1) {
            return;
          }
          buffer = buffer.slice(headerIndex + 4);
          headersDone = true;
        }

        const lines = buffer.split('\n');
        buffer = lines.pop() || '';
        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed) continue;

          // Parse event to check subscription filter
          try {
            const event: RchdEvent = JSON.parse(trimmed);
            if (matchesSubscription(event, subscribedWorkers)) {
              controller.enqueue(encoder.encode(`data: ${trimmed}\n\n`));
            }
          } catch {
            // If parsing fails, pass through raw (shouldn't happen normally)
            controller.enqueue(encoder.encode(`data: ${trimmed}\n\n`));
          }
        }
      });

      socket.on('end', () => {
        if (!isClosed) {
          isClosed = true;
          if (heartbeatInterval) clearInterval(heartbeatInterval);
          controller.close();
        }
      });

      socket.on('error', (err) => {
        if (!isClosed) {
          // Send error event before closing
          sendEvent('error', {
            message: err.message,
            code: (err as NodeJS.ErrnoException).code,
            timestamp: new Date().toISOString(),
          });
          isClosed = true;
          if (heartbeatInterval) clearInterval(heartbeatInterval);
          controller.error(err);
        }
      });
    },
    cancel() {
      isClosed = true;
      if (heartbeatInterval) {
        clearInterval(heartbeatInterval);
        heartbeatInterval = null;
      }
      if (socket) {
        socket.end();
        socket.destroy();
        socket = null;
      }
    },
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      Connection: 'keep-alive',
      'X-Request-ID': requestId,
      'X-Accel-Buffering': 'no', // Disable nginx buffering
    },
  });
}
