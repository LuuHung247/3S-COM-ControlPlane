import { NextResponse } from "next/server";

const INTEL_BASE = process.env.INTEL_URL ?? "http://localhost:8767";

export async function GET() {
  try {
    const res = await fetch(`${INTEL_BASE}/kg/export/graphml`, {
      next: { revalidate: 0 },
      signal: AbortSignal.timeout(8000),
    });
    const buf = await res.arrayBuffer();
    return new NextResponse(buf, {
      status: res.status,
      headers: {
        "Content-Type": "application/xml",
        "Content-Disposition": "attachment; filename=zerotrust-kg.graphml",
        "Cache-Control": "no-store",
      },
    });
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 502 });
  }
}
