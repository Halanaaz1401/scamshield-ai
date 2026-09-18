"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { Shield, ShieldAlert } from "lucide-react";

export default function Navbar() {
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  const scrollToSection = (id: string) => (e: React.MouseEvent) => {
    e.preventDefault();
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView({ behavior: "smooth" });
    }
  };

  return (
    <header
      role="banner"
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        scrolled
          ? "bg-[#07080d]/85 backdrop-blur-md border-b border-white/[0.08] py-3 shadow-[0_4px_30px_rgba(0,0,0,0.7)]"
          : "bg-[#07080d]/40 backdrop-blur-sm border-b border-white/[0.04] py-4"
      }`}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex items-center justify-between">
        {/* Left: Brand Logo & Wordmark */}
        <Link
          href="/"
          className="flex items-center gap-2.5 group focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 rounded-lg p-1 -m-1"
          aria-label="ScamShield AI Home"
        >
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 transition-all duration-200 group-hover:border-cyan-400/60 group-hover:bg-cyan-500/20 group-hover:shadow-[0_0_12px_rgba(34,211,238,0.3)]">
            <Shield className="h-4 w-4" />
          </div>
          <div className="flex items-baseline gap-1.5">
            <span
              className="font-extrabold tracking-tight text-white text-base font-heading"
            >
              ScamShield
            </span>
            <span className="text-[10px] font-mono font-bold tracking-widest text-cyan-400">
              AI
            </span>
          </div>
        </Link>

        {/* Center / Left Navigation Links */}
        <nav
          aria-label="Main Navigation"
          className="hidden md:flex items-center gap-8 text-xs font-medium text-zinc-400"
        >
          <Link
            href="/"
            className="hover:text-white transition-colors duration-150 relative py-1 focus:outline-none focus-visible:text-cyan-400"
          >
            Message Analyzer
          </Link>
          <Link
            href="/safe-link"
            id="nav-safelink-link"
            className="hover:text-cyan-300 transition-colors duration-150 relative py-1 focus:outline-none focus-visible:text-cyan-400 flex items-center gap-1.5"
          >
            <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-pulse" aria-hidden="true" />
            <span>Safe Link Gateway</span>
          </Link>
          <Link
            href="/#how-it-works"
            className="hover:text-white transition-colors duration-150 relative py-1 focus:outline-none focus-visible:text-cyan-400"
          >
            How It Works
          </Link>
        </nav>

        {/* Right Navigation & CTAs */}
        <div className="flex items-center gap-3.5">
          <button
            type="button"
            onClick={scrollToSection("analyzer")}
            className="hidden sm:inline-flex text-xs text-zinc-400 hover:text-zinc-200 transition-colors duration-150 font-medium px-2 py-1"
          >
            Sign In
          </button>

          <a
            href="#analyzer"
            id="navbar-analyze-cta"
            onClick={scrollToSection("analyzer")}
            className="inline-flex items-center gap-2 rounded-lg bg-gradient-to-r from-cyan-500/20 to-violet-500/20 px-3.5 py-2 text-xs font-mono font-semibold tracking-wide text-cyan-300 border border-cyan-500/40 hover:border-cyan-400 hover:text-white hover:bg-cyan-500/30 hover:shadow-[0_0_20px_rgba(34,211,238,0.25)] active:scale-[0.97] transition-all duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400"
          >
            <ShieldAlert className="h-3.5 w-3.5 text-cyan-400" aria-hidden="true" />
            <span>Analyze Message</span>
          </a>
        </div>
      </div>
    </header>
  );
}
