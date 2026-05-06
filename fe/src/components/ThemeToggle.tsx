"use client";

import { useEffect, useState } from "react";

type Theme = "dark" | "light";

const STORAGE_KEY = "zt-theme";

export default function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>("dark");
  const [mounted, setMounted] = useState(false);

  // On mount: read persisted theme + apply to <html>
  useEffect(() => {
    const saved = (typeof window !== "undefined" && localStorage.getItem(STORAGE_KEY)) as Theme | null;
    const initial: Theme = saved === "light" ? "light" : "dark";
    setTheme(initial);
    document.documentElement.setAttribute("data-theme", initial);
    setMounted(true);
  }, []);

  const toggle = () => {
    const next: Theme = theme === "dark" ? "light" : "dark";
    setTheme(next);
    document.documentElement.setAttribute("data-theme", next);
    try {
      localStorage.setItem(STORAGE_KEY, next);
    } catch {}
  };

  if (!mounted) return null;

  return (
    <button
      onClick={toggle}
      title={theme === "dark" ? "Switch to light mode (for screenshots)" : "Switch to dark mode"}
      className="px-2.5 py-1 rounded text-xs font-mono border border-tc-border text-tc-text-dim hover:text-tc-green hover:border-tc-green/40 transition-colors"
      aria-label="Toggle theme"
    >
      {theme === "dark" ? "☀ Light" : "🌙 Dark"}
    </button>
  );
}
