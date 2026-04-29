import { NextRequest, NextResponse } from "next/server";

const AGENT_BASE = process.env.AGENT_URL ?? "http://localhost:8766";

export async function DELETE(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  try {
    const res = await fetch(`${AGENT_BASE}/autoblock/unblock/${id}`, {
      method: "DELETE",
      signal: AbortSignal.timeout(10000),
    });
    const data = await res.json();
    return NextResponse.json(data, { status: res.status });
  } catch (e) {
    return NextResponse.json({ success: false, error: String(e) }, { status: 500 });
  }
}
