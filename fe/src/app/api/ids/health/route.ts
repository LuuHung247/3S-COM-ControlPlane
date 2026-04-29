import { NextResponse } from "next/server";

const AGENT_BASE = process.env.AGENT_URL ?? "http://localhost:8766";

export async function GET() {
  try {
    const res = await fetch(`${AGENT_BASE}/health`, {
      next: { revalidate: 0 },
      signal: AbortSignal.timeout(5000),
    });
    const data = await res.json();
    return NextResponse.json(data, {
      headers: { "Cache-Control": "no-store" },
    });
  } catch {
    return NextResponse.json(
      { status: "offline", suricata: "unreachable", alerts_total: 0 },
      { status: 503 }
    );
  }
}
