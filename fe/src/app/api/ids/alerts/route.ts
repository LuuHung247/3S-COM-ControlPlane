import { NextRequest, NextResponse } from "next/server";

const AGENT_BASE = process.env.AGENT_URL ?? "http://localhost:8766";
const IDS_BASE   = process.env.IDS_API_URL ?? "http://10.10.6.238:8765";

export async function GET(req: NextRequest) {
  const last  = req.nextUrl.searchParams.get("last");
  const since = req.nextUrl.searchParams.get("since");

  // ?since= goes directly to IDS API (ids-agent doesn't support it yet)
  if (since) {
    try {
      const res = await fetch(`${IDS_BASE}/alerts?since=${encodeURIComponent(since)}`, {
        next: { revalidate: 0 }, signal: AbortSignal.timeout(10000),
      });
      const data = await res.json();
      return NextResponse.json(data, { headers: { "Cache-Control": "no-store" } });
    } catch {
      return NextResponse.json([], { status: 503 });
    }
  }

  const url = last ? `${AGENT_BASE}/alerts?last=${last}` : `${AGENT_BASE}/alerts`;

  try {
    const res = await fetch(url, {
      next: { revalidate: 0 },
      signal: AbortSignal.timeout(10000),
    });
    const data = await res.json();
    return NextResponse.json(data, {
      headers: { "Cache-Control": "no-store" },
    });
  } catch {
    return NextResponse.json([], { status: 503 });
  }
}
