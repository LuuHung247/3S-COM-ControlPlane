export default function SiteFooter() {
  return (
    <footer className="border-t border-tc-border py-8">
      <div className="mx-auto max-w-6xl px-6">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="font-mono text-tc-green font-bold">⚡ 3S-NOS</div>
          <div className="flex flex-wrap items-center justify-center gap-x-6 gap-y-2 text-sm text-tc-text-dim">
            <a href="/" className="hover:text-tc-green transition-colors">Dashboard</a>
            <a href="/monitor" className="hover:text-tc-green transition-colors">Monitor</a>
            <a href="/topology" className="hover:text-tc-green transition-colors">Topology</a>
            <a href="/rules" className="hover:text-tc-green transition-colors">Rules</a>
            <a
              href="https://github.com/profullstack/threatcrush"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-tc-green transition-colors"
            >
              GitHub
            </a>
          </div>
          <p className="text-xs text-tc-text-dim font-mono">
            Zero Trust Microsegmentation Lab · {new Date().getFullYear()}
          </p>
        </div>
      </div>
    </footer>
  );
}
