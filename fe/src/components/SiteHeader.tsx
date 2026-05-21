"use client";

import { useState } from "react";
import ThemeToggle from "./ThemeToggle";

export default function SiteHeader() {
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  // Knowledge link opens the Neo4j Browser in a new tab. The browser auto-fills
  // connection params via URL query string so the user only needs to enter the
  // password (`zerotrust2026`). Bolt port 7687 must be reachable from the
  // user's machine — same forward as port 7474. Set per-machine in VSCode
  // Ports panel or via SSH `-L 7687:localhost:7687`.
  const NEO4J_BROWSER_URL =
    "http://localhost:7474/browser/?dbms=bolt%3A%2F%2Flocalhost%3A7687&db=neo4j&username=neo4j";

  const navLinks = [
    { href: "/", label: "Dashboard" },
    { href: "/monitor", label: "Monitor" },
    { href: NEO4J_BROWSER_URL, label: "Knowledge", external: true },
    { href: "/policy", label: "Policy" },
  ];

  return (
    <nav className="fixed top-0 left-0 right-0 z-40 border-b border-tc-border/50 bg-tc-darker/80 backdrop-blur-md">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-2 sm:px-6">
        <a href="/" className="flex items-center gap-2">
          <span className="text-xl font-bold text-tc-green glow-green font-mono">
            ⚡ 3s-COM
          </span>
          <span className="hidden sm:inline text-xs font-mono text-tc-text-dim border border-tc-border/50 rounded px-2 py-0.5">
            Spine-Leaf DC Fabric
          </span>
        </a>

        {/* Desktop nav */}
        <div className="hidden lg:flex items-center gap-6 text-sm text-tc-text-dim">
          {navLinks.map((link) => (
            <a
              key={link.href}
              href={link.href}
              className="hover:text-tc-green transition-colors"
              {...(link.external ? { target: "_blank", rel: "noopener noreferrer" } : {})}
            >
              {link.label}{link.external ? " ↗" : ""}
            </a>
          ))}
          <ThemeToggle />
        </div>

        {/* Mobile hamburger */}
        <button
          type="button"
          onClick={() => setMobileNavOpen((open) => !open)}
          className="inline-flex h-10 w-10 items-center justify-center rounded-lg border border-tc-border text-tc-text-dim transition-all hover:border-tc-green/30 hover:text-tc-green lg:hidden"
          aria-label="Toggle navigation menu"
          aria-expanded={mobileNavOpen}
        >
          <span className="text-lg">{mobileNavOpen ? "✕" : "☰"}</span>
        </button>
      </div>

      {/* Mobile menu */}
      {mobileNavOpen && (
        <div className="border-t border-tc-border/50 bg-tc-darker/95 px-4 py-4 lg:hidden">
          <div className="flex flex-col gap-3 text-sm text-tc-text-dim">
            {navLinks.map((link) => (
              <a
                key={link.href}
                href={link.href}
                className="hover:text-tc-green transition-colors"
                onClick={() => setMobileNavOpen(false)}
                {...(link.external ? { target: "_blank", rel: "noopener noreferrer" } : {})}
              >
                {link.label}{link.external ? " ↗" : ""}
              </a>
            ))}
            <div className="pt-2 border-t border-tc-border/30">
              <ThemeToggle />
            </div>
          </div>
        </div>
      )}
    </nav>
  );
}
