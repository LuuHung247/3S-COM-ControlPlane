import type { Metadata } from "next";
import "./globals.css";
import SiteHeader from "@/components/SiteHeader";
import SiteFooter from "@/components/SiteFooter";

export const metadata: Metadata = {
  title: "3S-NOS — Zero Trust Microsegmentation Dashboard",
  description:
    "GNS3 Spine-Leaf datacenter fabric với SONiC, microsegmentation iptables, và Suricata IDS real-time monitoring. NIST 800-207 Zero Trust Architecture.",
  keywords: [
    "zero trust",
    "microsegmentation",
    "suricata",
    "IDS",
    "spine-leaf",
    "SONiC",
    "datacenter",
    "network security",
  ],
  manifest: "/manifest.json",
  icons: {
    icon: [
      { url: "/favicon.svg", type: "image/svg+xml" },
      { url: "/icons/favicon-32.png", sizes: "32x32", type: "image/png" },
      { url: "/icons/favicon-16.png", sizes: "16x16", type: "image/png" },
    ],
    shortcut: "/favicon.ico",
    apple: [
      { url: "/icons/apple-touch-icon-180x180.png", sizes: "180x180" },
      { url: "/icons/apple-touch-icon-152x152.png", sizes: "152x152" },
      { url: "/icons/apple-touch-icon-144x144.png", sizes: "144x144" },
      { url: "/icons/apple-touch-icon-120x120.png", sizes: "120x120" },
      { url: "/icons/apple-touch-icon-114x114.png", sizes: "114x114" },
      { url: "/icons/apple-touch-icon-76x76.png", sizes: "76x76" },
      { url: "/icons/apple-touch-icon-72x72.png", sizes: "72x72" },
      { url: "/icons/apple-touch-icon-60x60.png", sizes: "60x60" },
      { url: "/icons/apple-touch-icon-57x57.png", sizes: "57x57" },
    ],
  },
  appleWebApp: {
    capable: true,
    title: "ThreatCrush",
    statusBarStyle: "black-translucent",
  },
  other: {
    "mobile-web-app-capable": "yes",
    "msapplication-TileColor": "#0a0a0a",
    "msapplication-config": "/browserconfig.xml",
    "msapplication-TileImage": "/icons/apple-touch-icon-144x144.png",
  },
  openGraph: {
    title: "ThreatCrush — Real-Time Threat Intelligence Platform",
    description:
      "Crush every threat before it crushes you. Lifetime access to real-time threat intelligence.",
    type: "website",
    images: ["/banner.png"],
  },
  twitter: {
    card: "summary_large_image",
    title: "ThreatCrush — Real-Time Threat Intelligence Platform",
    description:
      "Crush every threat before it crushes you. Lifetime access to real-time threat intelligence.",
    images: ["/banner.png"],
  },
};

export const viewport = {
  themeColor: "#0a0a0a",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <head>
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="antialiased">
        <SiteHeader />
        {children}
        <SiteFooter />
      </body>
    </html>
  );
}
