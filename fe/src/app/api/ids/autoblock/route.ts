import { NextRequest, NextResponse } from "next/server";

const AGENT_BASE = process.env.AGENT_URL ?? "http://localhost:8766";

export async function GET() {
  try {
    const res = await fetch(`${AGENT_BASE}/autoblock`, {
      next: { revalidate: 0 },
      signal: AbortSignal.timeout(5000),
    });
    const data = await res.json();
    return NextResponse.json(data);
  } catch {
    return NextResponse.json({ enabled: false, error: "offline" }, { status: 503 });
  }
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const action = body.enable ? "enable" : "disable";
    const res = await fetch(`${AGENT_BASE}/autoblock/${action}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
      signal: AbortSignal.timeout(5000),
    });
    const data = await res.json();
    return NextResponse.json(data, { status: res.status });
  } catch (e) {
    return NextResponse.json({ success: false, error: String(e) }, { status: 500 });
  }
}
