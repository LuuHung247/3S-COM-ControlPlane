import { NextRequest, NextResponse } from "next/server";

const AGENT_BASE = process.env.AGENT_URL ?? "http://localhost:8766";

export async function GET() {
  try {
    const res = await fetch(`${AGENT_BASE}/rules`, {
      next: { revalidate: 0 },
      signal: AbortSignal.timeout(10000),
    });
    const data = await res.json();
    return NextResponse.json(data, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return NextResponse.json({ success: false, error: "IDS Agent offline" }, { status: 503 });
  }
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const res = await fetch(`${AGENT_BASE}/autoblock`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(10000),
    });
    const data = await res.json();
    return NextResponse.json(data, { status: res.status });
  } catch (e) {
    return NextResponse.json({ success: false, error: String(e) }, { status: 500 });
  }
}
