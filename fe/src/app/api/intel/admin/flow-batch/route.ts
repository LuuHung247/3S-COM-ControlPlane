import { NextResponse } from "next/server";

const INTEL_BASE = process.env.INTEL_URL ?? "http://localhost:8767";

export async function GET() {
  try {
    const res = await fetch(`${INTEL_BASE}/admin/flow-batch/status`, {
      next: { revalidate: 0 },
      signal: AbortSignal.timeout(5000),
    });
    const data = await res.json();
    return NextResponse.json(data, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return NextResponse.json({ enabled: false, error: "offline" }, { status: 503 });
  }
}
