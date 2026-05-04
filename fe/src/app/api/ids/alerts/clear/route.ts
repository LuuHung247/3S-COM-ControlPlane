import { NextResponse } from "next/server";

const IDS_BASE = process.env.IDS_API_URL ?? "http://10.10.6.238:8765";

export async function GET() {
  try {
    const res = await fetch(`${IDS_BASE}/alerts/clear`, {
      cache: "no-store",
      signal: AbortSignal.timeout(5000),
    });
    const data = await res.json();
    return NextResponse.json(data, { headers: { "Cache-Control": "no-store" } });
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 503 });
  }
}
