import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Sidebar } from "@/components/layout";
import { QueryProvider } from "@/components/providers/query-provider";
import { ThemeProvider } from "@/components/providers/theme-provider";
import { ToastProvider } from "@/components/providers/toast-provider";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "RCH Dashboard — Remote Compilation Helper",
  description: "Transparent remote compilation offloading fleet dashboard for AI coding agents.",
  icons: {
    icon: "/favicon.svg",
  },
  openGraph: {
    title: "RCH Fleet Dashboard — Remote Compilation Helper",
    description: "Transparent remote compilation offloading fleet dashboard. Real-time compute slots, capacity matrix, and pipeline telemetry for AI coding agents.",
    url: "https://github.com/Dicklesworthstone/remote_compilation_helper",
    siteName: "RCH Fleet Dashboard",
    images: [
      {
        url: "/og-image.jpg",
        width: 1280,
        height: 720,
        alt: "RCH Fleet Dashboard Preview",
      },
    ],
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "RCH Fleet Dashboard — Remote Compilation Helper",
    description: "Transparent remote compilation offloading fleet dashboard for AI coding agents.",
    images: ["/og-image.jpg"],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        <ThemeProvider>
          <ToastProvider />
          <QueryProvider>
            <a
              href="#main-content"
              className="sr-only focus:not-sr-only focus:fixed focus:top-4 focus:left-4 focus:z-[70] focus:rounded-md focus:bg-surface focus:px-3 focus:py-2 focus:text-sm focus:font-medium focus:text-foreground focus:shadow-lg"
            >
              Skip to main content
            </a>
            <div className="flex h-screen">
              <Sidebar />
              <main id="main-content" className="flex-1 overflow-auto p-6">
                {children}
              </main>
            </div>
          </QueryProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
