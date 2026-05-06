"use client";

import { useState } from "react";
import ThemeToggle from "./ThemeToggle";

export default function SiteHeader() {
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  const navLinks = [
    { href: "/", label: "Dashboard" },
    { href: "/monitor", label: "Monitor" },
    { href: "/topology", label: "Topology" },
    { href: "/rules", label: "Rules" },
    { href: "/policy", label: "Policy" },
  ];

  return (
    <nav className="fixed top-0 left-0 right-0 z-40 border-b border-tc-border/50 bg-tc-darker/80 backdrop-blur-md">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-2 sm:px-6">
        <a href="/" className="flex items-center gap-2">
          <span className="text-xl font-bold text-tc-green glow-green font-mono">
            ⚡ 3S-NOS
          </span>
          <span className="hidden sm:inline text-xs font-mono text-tc-text-dim border border-tc-border/50 rounded px-2 py-0.5">
            Spine-Leaf DC Fabric
          </span>
        </a>

        {/* Desktop nav */}
        <div className="hidden lg:flex items-center gap-6 text-sm text-tc-text-dim">
          {navLinks.map((link) => (
            <a key={link.href} href={link.href} className="hover:text-tc-green transition-colors">
              {link.label}
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
              >
                {link.label}
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
