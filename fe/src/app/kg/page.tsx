"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import dynamic from "next/dynamic";
import type cytoscape from "cytoscape";

const CytoscapeComponent = dynamic(
  async () => {
    const [
      cytoscapeMod,
      fcoseMod,
      dagreMod,
      compMod,
    ] = await Promise.all([
      import("cytoscape"),
      import("cytoscape-fcose"),
      import("cytoscape-dagre"),
      import("react-cytoscapejs"),
    ]);
    const cy = cytoscapeMod.default as unknown as {
      use: (ext: unknown) => void;
    };
    try {
      cy.use(fcoseMod.default);
    } catch {}
    try {
      cy.use(dagreMod.default);
    } catch {}
    return compMod.default ?? compMod;
  },
  { ssr: false },
);

type KgNodeData = {
  id: string;
  type: string;
  label: string;
  title: string;
  shape?: string;
  color?: string;
};
type KgNode = { data: KgNodeData };
type KgEdge = {
  data: {
    id: string;
    source: string;
    target: string;
    label: string;
    kind: string;
    color?: string;
    dashes?: boolean;
  };
};
type KgPayload = { nodes: KgNode[]; edges: KgEdge[]; error?: string };

const NODE_TYPES = [
  { key: "zone", label: "Zone", color: "#3498db" },
  { key: "asset", label: "Asset", color: "#2ecc71" },
  { key: "leaf", label: "LEAF", color: "#f39c12" },
  { key: "sid", label: "SID", color: "#e74c3c" },
  { key: "kill_chain", label: "Kill chain", color: "#9b59b6" },
  { key: "baseline", label: "Baseline flow", color: "#1abc9c" },
] as const;

const EDGE_KINDS = [
  { key: "policy", label: "ALLOW/DENY", color: "#c0392b" },
  { key: "membership", label: "membership/enforces", color: "#8b949e" },
  { key: "stage", label: "kill-chain stage", color: "#9b59b6" },
  { key: "flow", label: "production flow", color: "#1abc9c" },
] as const;

const LAYOUTS = [
  { key: "fcose", label: "Force (fCoSE)" },
  { key: "concentric", label: "Concentric" },
  { key: "dagre", label: "Hierarchical (dagre)" },
  { key: "breadthfirst", label: "Breadth-first" },
  { key: "circle", label: "Circle" },
  { key: "grid", label: "Grid" },
] as const;

type LayoutKey = (typeof LAYOUTS)[number]["key"];

export default function KnowledgeGraphPage() {
  const [data, setData] = useState<KgPayload>({ nodes: [], edges: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [layoutKey, setLayoutKey] = useState<LayoutKey>("fcose");
  const [enabledTypes, setEnabledTypes] = useState<Record<string, boolean>>({
    zone: true,
    asset: true,
    leaf: true,
    sid: true,
    kill_chain: true,
    baseline: true,
  });
  const [selected, setSelected] = useState<KgNodeData | null>(null);
  const [search, setSearch] = useState("");
  const cyRef = useRef<cytoscape.Core | null>(null);

  // Fetch KG data
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        setLoading(true);
        const res = await fetch("/api/intel/kg/json", { cache: "no-store" });
        const payload: KgPayload = await res.json();
        if (cancelled) return;
        if (payload.error) {
          setError(payload.error);
        }
        setData(payload);
      } catch (e) {
        if (!cancelled) setError(String(e));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // Filter elements based on enabled types and search
  const elements = useMemo(() => {
    const visibleNodeIds = new Set(
      data.nodes
        .filter((n) => enabledTypes[n.data.type] !== false)
        .filter((n) =>
          search.trim() === ""
            ? true
            : n.data.label.toLowerCase().includes(search.toLowerCase()) ||
              n.data.id.toLowerCase().includes(search.toLowerCase()),
        )
        .map((n) => n.data.id),
    );
    const filteredNodes = data.nodes.filter((n) => visibleNodeIds.has(n.data.id));
    const filteredEdges = data.edges.filter(
      (e) => visibleNodeIds.has(e.data.source) && visibleNodeIds.has(e.data.target),
    );
    return [...filteredNodes, ...filteredEdges];
  }, [data, enabledTypes, search]);

  // Cytoscape stylesheet — typed as unknown[] to bypass v3 type complexity
  const stylesheet = useMemo<unknown[]>(
    () => [
      {
        selector: "node",
        style: {
          "background-color": "data(color)",
          label: "data(label)",
          color: "#d4dae0",
          "font-family": "JetBrains Mono, monospace",
          "font-size": 10,
          "text-wrap": "wrap",
          "text-max-width": 100,
          "text-valign": "bottom",
          "text-halign": "center",
          "text-margin-y": 4,
          "border-width": 2,
          "border-color": "#1f2a36",
          width: 36,
          height: 36,
        },
      },
      ...NODE_TYPES.map((t) => ({
        selector: `node[type = "${t.key}"]`,
        style: {
          "background-color": t.color,
          shape:
            t.key === "zone"
              ? "round-rectangle"
              : t.key === "leaf"
                ? "diamond"
                : t.key === "sid"
                  ? "triangle"
                  : t.key === "kill_chain"
                    ? "star"
                    : t.key === "baseline"
                      ? "hexagon"
                      : "ellipse",
          width: t.key === "zone" ? 60 : t.key === "kill_chain" ? 50 : 36,
          height: t.key === "zone" ? 40 : t.key === "kill_chain" ? 50 : 36,
        },
      })),
      {
        selector: "node:selected",
        style: {
          "border-color": "#4ade80",
          "border-width": 4,
        },
      },
      {
        selector: "edge",
        style: {
          width: 1.5,
          "line-color": "#3a4452",
          "target-arrow-color": "#3a4452",
          "target-arrow-shape": "triangle",
          "curve-style": "bezier",
          label: "data(label)",
          "font-size": 8,
          "font-family": "JetBrains Mono, monospace",
          color: "#8b949e",
          "text-background-color": "#0a0e13",
          "text-background-opacity": 0.7,
          "text-background-padding": 2,
          "text-rotation": "autorotate",
        },
      },
      {
        selector: 'edge[kind = "policy"][label = "ALLOW"]',
        style: {
          "line-color": "#27ae60",
          "target-arrow-color": "#27ae60",
          width: 2,
        },
      },
      {
        selector: 'edge[kind = "policy"][label = "DENY"]',
        style: {
          "line-color": "#c0392b",
          "target-arrow-color": "#c0392b",
          "line-style": "dashed",
          width: 2,
        },
      },
      {
        selector: 'edge[kind = "stage"]',
        style: {
          "line-color": "#9b59b6",
          "target-arrow-color": "#9b59b6",
        },
      },
      {
        selector: 'edge[kind = "flow"]',
        style: {
          "line-color": "#1abc9c",
          "target-arrow-color": "#1abc9c",
        },
      },
      {
        selector: 'edge[kind = "membership"]',
        style: {
          "line-color": "#7f8c8d",
          "target-arrow-color": "#7f8c8d",
          "line-style": "dotted",
        },
      },
    ],
    [],
  );

  // Inject color into node data based on type
  const elementsWithColor = useMemo(() => {
    return elements.map((el) => {
      if ("source" in el.data) return el;
      const node = el as KgNode;
      const t = NODE_TYPES.find((x) => x.key === node.data.type);
      return {
        ...node,
        data: { ...node.data, color: t?.color ?? "#95a5a6" },
      };
    });
  }, [elements]);

  // Layout config
  const layoutConfig = useMemo<unknown>(() => {
    const base = { name: layoutKey, animate: true, animationDuration: 600 };
    if (layoutKey === "fcose") {
      return {
        ...base,
        quality: "default",
        randomize: false,
        nodeRepulsion: 6000,
        idealEdgeLength: 110,
        edgeElasticity: 0.45,
        gravity: 0.25,
        gravityRange: 3.8,
        numIter: 2500,
        tile: true,
      };
    }
    if (layoutKey === "concentric") {
      return {
        ...base,
        concentric: (n: cytoscape.NodeSingular) => {
          const t = n.data("type");
          if (t === "leaf") return 4;
          if (t === "zone") return 3;
          if (t === "asset") return 2;
          if (t === "baseline") return 1;
          return 0;
        },
        levelWidth: () => 1,
        spacingFactor: 1.2,
      };
    }
    if (layoutKey === "dagre") {
      return {
        ...base,
        rankDir: "TB",
        nodeSep: 50,
        rankSep: 80,
      };
    }
    if (layoutKey === "breadthfirst") {
      return { ...base, directed: true, padding: 20, spacingFactor: 1.2 };
    }
    return base;
  }, [layoutKey]);

  const stats = useMemo(() => {
    const counts: Record<string, number> = {};
    data.nodes.forEach((n) => {
      counts[n.data.type] = (counts[n.data.type] ?? 0) + 1;
    });
    return counts;
  }, [data]);

  const onCyInit = (cy: cytoscape.Core) => {
    cyRef.current = cy;
    cy.on("tap", "node", (evt: cytoscape.EventObject) => {
      setSelected(evt.target.data() as KgNodeData);
    });
    cy.on("tap", (evt: cytoscape.EventObject) => {
      if (evt.target === cy) setSelected(null);
    });
  };

  const fitGraph = () => {
    if (!cyRef.current) return;
    cyRef.current.fit(undefined, 30);
  };

  const replayLayout = () => {
    if (!cyRef.current) return;
    cyRef.current
      .layout(layoutConfig as cytoscape.LayoutOptions)
      .run();
  };

  return (
    <main className="min-h-screen bg-tc-darker text-tc-text pt-16">
      <div className="mx-auto max-w-7xl px-4 py-6 sm:px-6">
        <header className="mb-4">
          <h1 className="text-2xl font-bold text-tc-green font-mono">
            🧠 Agent Knowledge Graph
          </h1>
          <p className="text-sm text-tc-text-dim mt-1">
            Heterogeneous KG agent đang dùng để reason: zones, assets, LEAFs, SIDs,
            kill chains, production traffic baselines.
          </p>
        </header>

        {/* Toolbar */}
        <div className="mb-3 flex flex-wrap items-center gap-3 rounded-lg border border-tc-border bg-tc-card p-3">
          <div className="flex items-center gap-2">
            <span className="text-xs text-tc-text-dim font-mono">Layout:</span>
            <select
              value={layoutKey}
              onChange={(e) => setLayoutKey(e.target.value as LayoutKey)}
              className="rounded border border-tc-border bg-tc-darker px-2 py-1 text-xs font-mono text-tc-text"
            >
              {LAYOUTS.map((l) => (
                <option key={l.key} value={l.key}>
                  {l.label}
                </option>
              ))}
            </select>
          </div>

          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search node..."
            className="rounded border border-tc-border bg-tc-darker px-2 py-1 text-xs font-mono text-tc-text placeholder:text-tc-text-dim"
          />

          <div className="flex-1" />

          <button
            type="button"
            onClick={replayLayout}
            className="rounded border border-tc-border px-2 py-1 text-xs font-mono text-tc-text-dim hover:border-tc-green hover:text-tc-green"
          >
            ↻ Replay layout
          </button>
          <button
            type="button"
            onClick={fitGraph}
            className="rounded border border-tc-border px-2 py-1 text-xs font-mono text-tc-text-dim hover:border-tc-green hover:text-tc-green"
          >
            ⤢ Fit
          </button>
          <a
            href="/api/intel/kg/graphml"
            download="zerotrust-kg.graphml"
            className="rounded border border-tc-green/40 bg-tc-green/10 px-2 py-1 text-xs font-mono text-tc-green hover:bg-tc-green/20"
          >
            ⬇ Export GraphML
          </a>
        </div>

        {/* Type filters */}
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <span className="text-xs text-tc-text-dim font-mono">Show:</span>
          {NODE_TYPES.map((t) => {
            const enabled = enabledTypes[t.key];
            return (
              <button
                key={t.key}
                type="button"
                onClick={() =>
                  setEnabledTypes((s) => ({ ...s, [t.key]: !s[t.key] }))
                }
                className={`flex items-center gap-1.5 rounded border px-2 py-1 text-xs font-mono transition-colors ${
                  enabled
                    ? "border-tc-border text-tc-text hover:border-tc-green/40"
                    : "border-tc-border/50 text-tc-text-dim/60 line-through"
                }`}
              >
                <span
                  className="inline-block h-2.5 w-2.5 rounded-full"
                  style={{ backgroundColor: t.color }}
                />
                {t.label} ({stats[t.key] ?? 0})
              </button>
            );
          })}
        </div>

        {/* Main grid */}
        <div className="grid grid-cols-1 lg:grid-cols-[1fr_320px] gap-4">
          <div className="relative rounded-lg border border-tc-border bg-tc-card overflow-hidden">
            {loading && (
              <div className="absolute inset-0 z-10 flex items-center justify-center bg-tc-darker/80">
                <div className="text-tc-text-dim font-mono text-sm">
                  Loading KG...
                </div>
              </div>
            )}
            {error && !loading && (
              <div className="absolute inset-0 z-10 flex items-center justify-center bg-tc-darker/80">
                <div className="text-red-400 font-mono text-sm max-w-md text-center px-4">
                  Failed to load KG: {error}
                </div>
              </div>
            )}
            <CytoscapeComponent
              elements={elementsWithColor}
              stylesheet={stylesheet as never}
              layout={layoutConfig as cytoscape.LayoutOptions}
              cy={onCyInit}
              style={{ width: "100%", height: "78vh" }}
              minZoom={0.2}
              maxZoom={3}
            />
          </div>

          <aside className="space-y-3">
            <div className="rounded-lg border border-tc-border bg-tc-card p-3">
              <div className="text-xs text-tc-text-dim font-mono mb-2">
                KG STATS
              </div>
              <div className="text-sm font-mono">
                <div>
                  Nodes:{" "}
                  <span className="text-tc-green">{data.nodes.length}</span>
                </div>
                <div>
                  Edges:{" "}
                  <span className="text-tc-green">{data.edges.length}</span>
                </div>
              </div>
            </div>

            <div className="rounded-lg border border-tc-border bg-tc-card p-3">
              <div className="text-xs text-tc-text-dim font-mono mb-2">
                EDGE LEGEND
              </div>
              <div className="space-y-1.5 text-xs font-mono">
                {EDGE_KINDS.map((k) => (
                  <div key={k.key} className="flex items-center gap-2">
                    <span
                      className="inline-block h-0.5 w-6"
                      style={{ backgroundColor: k.color }}
                    />
                    <span className="text-tc-text-dim">{k.label}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="rounded-lg border border-tc-border bg-tc-card p-3">
              <div className="text-xs text-tc-text-dim font-mono mb-2">
                SELECTED NODE
              </div>
              {selected ? (
                <div className="space-y-1.5 text-xs font-mono">
                  <div>
                    <span className="text-tc-text-dim">id:</span>{" "}
                    <span className="text-tc-green break-all">
                      {selected.id}
                    </span>
                  </div>
                  <div>
                    <span className="text-tc-text-dim">type:</span>{" "}
                    <span>{selected.type}</span>
                  </div>
                  {selected.title && (
                    <pre className="mt-2 whitespace-pre-wrap rounded bg-tc-darker p-2 text-[11px] leading-relaxed text-tc-text">
                      {selected.title}
                    </pre>
                  )}
                </div>
              ) : (
                <div className="text-xs text-tc-text-dim italic">
                  Click any node...
                </div>
              )}
            </div>

            <div className="rounded-lg border border-tc-border bg-tc-card p-3">
              <div className="text-xs text-tc-text-dim font-mono mb-2">
                EXPORT
              </div>
              <div className="text-xs text-tc-text-dim leading-relaxed">
                <p className="mb-2">
                  <code className="text-tc-green">.graphml</code> mở được trong:
                </p>
                <ul className="ml-4 list-disc space-y-0.5">
                  <li>
                    <span className="text-tc-text">yEd</span> — auto-layout
                    chuyên nghiệp, export PDF/SVG
                  </li>
                  <li>
                    <span className="text-tc-text">Gephi</span> — clustering,
                    centrality
                  </li>
                  <li>
                    <span className="text-tc-text">Cytoscape Desktop</span> —
                    publication-grade figure
                  </li>
                </ul>
              </div>
            </div>
          </aside>
        </div>
      </div>
    </main>
  );
}
