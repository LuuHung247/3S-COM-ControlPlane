import { NextRequest } from "next/server";

const AGENT_BASE = process.env.AGENT_URL ?? "http://localhost:8766";

export async function GET(req: NextRequest) {
  const stream = new ReadableStream({
    async start(controller) {
      const upstream = await fetch(`${AGENT_BASE}/events`, {
        headers: { Accept: "text/event-stream" },
        signal: req.signal,
      }).catch(() => null);

      if (!upstream?.ok || !upstream.body) {
        controller.enqueue(new TextEncoder().encode("data: {\"type\":\"error\"}\n\n"));
        controller.close();
        return;
      }

      const reader = upstream.body.getReader();
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          controller.enqueue(value);
        }
      } catch {
        // client disconnected
      } finally {
        reader.cancel();
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}
