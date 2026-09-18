import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ScamShield AI — Explainable Threat Defense",
  description:
    "AI-powered scam and social engineering threat detector. Detect the scam. Understand the attack. Know what to do next.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
      </head>
      <body>
        {children}
      </body>
    </html>
  );
}
