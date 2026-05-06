import { NextResponse } from "next/server";

const INTEL_BASE = process.env.INTEL_URL ?? "http://localhost:8767";

export async function GET() {
  try {
    const res = await fetch(`${INTEL_BASE}/kg/json`, {
      next: { revalidate: 0 },
      signal: AbortSignal.timeout(8000),
    });
    const data = await res.json();
    return NextResponse.json(data, { headers: { "Cache-Control": "no-store" } });
  } catch (e) {
    return NextResponse.json(
      { nodes: [], edges: [], error: String(e) },
      { status: 200 },
    );
  }
}
