import { NextRequest, NextResponse } from "next/server";

const AGENT_BASE = process.env.AGENT_URL ?? "http://localhost:8766";

export async function GET(req: NextRequest) {
  const last  = req.nextUrl.searchParams.get("last") ?? "100";
  const since = req.nextUrl.searchParams.get("since");
  let url = `${AGENT_BASE}/flows?last=${last}`;
  if (since) url += `&since=${encodeURIComponent(since)}`;
  try {
    const res = await fetch(url, { next: { revalidate: 0 }, signal: AbortSignal.timeout(10000) });
    const data = await res.json();
    return NextResponse.json(data, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return NextResponse.json([], { status: 503 });
  }
}
