export async function register() {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;

  const AGENT = process.env.AGENT_URL ?? "http://localhost:8766";

  try {
    const [health, alerts] = await Promise.all([
      fetch(`${AGENT}/health`, { signal: AbortSignal.timeout(3000) }).then((r) => r.json()),
      fetch(`${AGENT}/alerts`, { signal: AbortSignal.timeout(3000) }).then((r) => r.json()),
    ]);

    console.log(`[3S-NOS] ✓ Go IDS Agent — ${AGENT}`);
    console.log(`[3S-NOS] ✓ Suricata status: ${health.status} | ts: ${health.ts}`);
    console.log(`[3S-NOS] ✓ Alerts in store: ${alerts.count} total`);
  } catch {
    console.error(`[3S-NOS] ✗ Go IDS Agent unreachable at ${AGENT} — start ids-agent first`);
  }
}
