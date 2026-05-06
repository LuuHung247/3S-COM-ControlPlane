import { NextResponse } from "next/server";

const INTEL_BASE = process.env.INTEL_URL ?? "http://localhost:8767";

export async function GET(
  _req: Request,
  context: { params: Promise<{ id: string }> },
) {
  const { id } = await context.params;
  try {
    const res = await fetch(`${INTEL_BASE}/decisions/${encodeURIComponent(id)}`, {
      next: { revalidate: 0 },
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) {
      return NextResponse.json({ error: "not found" }, { status: res.status });
    }
    const data = await res.json();
    return NextResponse.json(data, { headers: { "Cache-Control": "no-store" } });
  } catch (err) {
    return NextResponse.json(
      { error: String(err) },
      { status: 502 },
    );
  }
}
