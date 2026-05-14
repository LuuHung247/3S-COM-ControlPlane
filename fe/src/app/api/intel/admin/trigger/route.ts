import { NextResponse } from "next/server";

const INTEL_BASE = process.env.INTEL_URL ?? "http://localhost:8767";

export async function GET() {
  try {
    const res = await fetch(`${INTEL_BASE}/admin/agent/trigger`, {
      next: { revalidate: 0 },
      signal: AbortSignal.timeout(5000),
    });
    const data = await res.json();
    return NextResponse.json(data, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return NextResponse.json({ enabled: null, error: "offline" }, { status: 503 });
  }
}

export async function POST(req: Request) {
  try {
    const body = await req.json().catch(() => ({}));
    const res = await fetch(`${INTEL_BASE}/admin/agent/trigger`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: !!body.enabled }),
      signal: AbortSignal.timeout(5000),
    });
    const data = await res.json();
    return NextResponse.json(data, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return NextResponse.json({ enabled: null, error: "offline" }, { status: 503 });
  }
}
