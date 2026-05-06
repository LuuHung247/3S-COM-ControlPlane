import { NextRequest, NextResponse } from "next/server";

const INTEL_BASE = process.env.INTEL_URL ?? "http://localhost:8767";

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const params = new URLSearchParams();
  for (const k of ["since", "limit", "kind"]) {
    const v = searchParams.get(k);
    if (v) params.set(k, v);
  }
  try {
    const url = `${INTEL_BASE}/events${params.toString() ? `?${params.toString()}` : ""}`;
    const res = await fetch(url, {
      next: { revalidate: 0 },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) {
      return NextResponse.json([], { status: res.status });
    }
    const data = await res.json();
    return NextResponse.json(data, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return NextResponse.json([], { status: 200 });
  }
}
