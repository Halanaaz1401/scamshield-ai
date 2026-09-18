"use client";

import React from "react";
import {
  ArrowRight,
  ShieldCheck,
  Search,
  Cpu,
  Sparkles,
  Terminal,
  Lock,
  Shield,
  Activity,
} from "lucide-react";
import ThreatSignalCore from "./ThreatSignalCore";
import { PRESET_SAMPLES } from "@/lib/mockData";

interface HeroProps {
  onSelectPreset: (message: string) => void;
}

export default function Hero({ onSelectPreset }: HeroProps) {
  const scrollToAnalyzer = () => {
    const el = document.getElementById("analyzer");
    if (el) {
      el.scrollIntoView({ behavior: "smooth" });
    }
  };

  const scrollToHowItWorks = () => {
    const el = document.getElementById("how-it-works");
    if (el) {
      el.scrollIntoView({ behavior: "smooth" });
    }
  };

  return (
    <div className="relative overflow-hidden pt-20 sm:pt-24 pb-12 lg:pb-16" aria-label="Hero">
      {/* Multi-layered Tech-Noir ambient gradients */}
      <div
        className="absolute top-0 left-1/4 -translate-x-1/2 w-[600px] h-[350px] rounded-full pointer-events-none opacity-40 blur-[130px]"
        style={{ background: "radial-gradient(circle, rgba(34, 211, 238, 0.15) 0%, transparent 70%)" }}
        aria-hidden="true"
      />
      <div
        className="absolute top-20 right-10 w-[500px] h-[400px] rounded-full pointer-events-none opacity-30 blur-[140px]"
        style={{ background: "radial-gradient(circle, rgba(139, 92, 246, 0.18) 0%, transparent 70%)" }}
        aria-hidden="true"
      />

      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 relative">
        {/* ============================================================
            TRUE 50/50 SPLIT HERO SECTION
            ============================================================ */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 lg:gap-12 items-center min-h-[520px]">
          
          {/* ---- LEFT COLUMN: Content (~50%) ---- */}
          <div className="lg:col-span-6 xl:col-span-6 space-y-6 text-left">
            
            {/* Eyebrow / Engine Status Bar */}
            <div className="flex flex-wrap items-center gap-2.5">
              <div className="inline-flex items-center gap-2 rounded-full border border-cyan-500/25 bg-cyan-500/10 px-3.5 py-1 text-[11px] font-mono text-cyan-300 backdrop-blur-sm tracking-wider uppercase">
                <Terminal className="h-3 w-3 text-cyan-400" aria-hidden="true" />
                <span>EXPLAINABLE THREAT DEFENSE // AWS BEDROCK</span>
              </div>

              <div className="inline-flex items-center gap-1.5 rounded-full border border-white/[0.08] bg-zinc-950/60 px-3 py-1 text-[11px] font-mono text-zinc-400 backdrop-blur-sm">
                <span className="relative flex h-1.5 w-1.5">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
                  <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald-400" />
                </span>
                <span>Threat Detection Engine • Online</span>
              </div>
            </div>

            {/* Approved Main Headline */}
            <h1
              className="font-extrabold tracking-tight text-white leading-[1.08]"
              style={{
                fontFamily: "'Space Grotesk', system-ui, sans-serif",
                fontSize: "clamp(2.35rem, 5vw, 4rem)",
              }}
            >
              Detect the scam. <br />
              <span className="bg-gradient-to-r from-cyan-400 via-violet-300 to-white bg-clip-text text-transparent">
                Understand the attack.
              </span>{" "}
              <br />
              Know what to do next.
            </h1>

            {/* Core Experience Pipeline Pill */}
            <div className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.07] bg-zinc-950/60 px-3 py-1 text-[10px] font-mono text-zinc-400">
              <span className="text-cyan-400 font-bold">DETECT</span>
              <span className="text-zinc-600">→</span>
              <span className="text-zinc-300">EXPLAIN</span>
              <span className="text-zinc-600">→</span>
              <span className="text-violet-400 font-bold">UNDERSTAND</span>
              <span className="text-zinc-600">→</span>
              <span className="text-zinc-300">DECIDE</span>
              <span className="text-zinc-600">→</span>
              <span className="text-emerald-400 font-bold">RESPOND</span>
            </div>

            {/* Supporting Copy */}
            <p className="text-base sm:text-lg text-zinc-400 max-w-xl leading-relaxed">
              ScamShield AI combines deterministic cybersecurity heuristics with Amazon Bedrock contextual intelligence to decode deceptive communications, reconstruct the attacker&apos;s kill chain, and deliver immediate, protective guidance.
            </p>

            {/* CTA Buttons */}
            <div className="pt-1 flex flex-wrap items-center gap-4">
              <button
                type="button"
                id="hero-analyze-cta"
                onClick={scrollToAnalyzer}
                className="inline-flex items-center gap-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 px-6 py-3.5 text-xs sm:text-sm font-bold uppercase tracking-wider text-white shadow-[0_0_25px_rgba(34,211,238,0.25)] hover:shadow-[0_0_35px_rgba(34,211,238,0.4)] hover:brightness-110 active:scale-[0.98] transition-all duration-150 border border-cyan-400/40 cursor-pointer"
              >
                <span>Analyze a Message</span>
                <ArrowRight className="h-4 w-4" aria-hidden="true" />
              </button>

              <button
                type="button"
                id="hero-how-it-works-cta"
                onClick={scrollToHowItWorks}
                className="inline-flex items-center gap-2 rounded-xl border border-white/[0.1] bg-white/[0.04] px-5 py-3.5 text-xs sm:text-sm font-semibold text-zinc-300 hover:text-white hover:bg-white/[0.08] hover:border-white/[0.2] active:scale-[0.98] transition-all duration-150 backdrop-blur-sm cursor-pointer"
              >
                <span>See How It Works</span>
              </button>
            </div>

            {/* Preset Attack Vectors */}
            <div className="pt-3 border-t border-white/[0.06] flex flex-wrap items-center gap-2">
              <span className="text-[11px] font-mono text-zinc-500 flex items-center gap-1.5 mr-1">
                <Sparkles className="h-3 w-3 text-cyan-400" aria-hidden="true" />
                Quick Test:
              </span>
              {PRESET_SAMPLES.map((preset) => (
                <button
                  key={preset.id}
                  type="button"
                  id={`hero-preset-${preset.id}`}
                  onClick={() => onSelectPreset(preset.message)}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.07] bg-zinc-900/50 px-2.5 py-1 text-[11px] font-mono text-zinc-400 hover:border-cyan-500/40 hover:text-cyan-300 hover:bg-zinc-800/80 transition-all duration-150 cursor-pointer"
                >
                  <span className="h-1 w-1 rounded-full bg-cyan-400/70" aria-hidden="true" />
                  {preset.title}
                </button>
              ))}
            </div>

          </div>

          {/* ---- RIGHT COLUMN: Interactive Threat Signal Core (~50%) ---- */}
          <div className="lg:col-span-6 xl:col-span-6 flex justify-center w-full">
            <ThreatSignalCore />
          </div>

        </div>

        {/* Technical Telemetry Specs Bar */}
        <div className="mt-14 grid grid-cols-2 sm:grid-cols-4 gap-0 w-full border border-white/[0.08] rounded-xl overflow-hidden text-left sm:text-center bg-[#0a0b12]/60 backdrop-blur-sm">
          {[
            { icon: Cpu,      color: "text-cyan-400",    label: "Architecture", value: "Dual-Layer",   sub: "Rules + Bedrock" },
            { icon: Shield,   color: "text-cyan-400",    label: "Payload",      value: "≤ 4,000",      sub: "Character Bound" },
            { icon: Lock,     color: "text-emerald-400", label: "Privacy",      value: "Zero-PII",     sub: "Stateless In-Memory" },
            { icon: Activity, color: "text-violet-400",  label: "Signature",    value: "Scam DNA™",    sub: "Kill Chain Graph" },
          ].map((item, i) => (
            <div
              key={item.label}
              className={`px-4 py-4 ${i > 0 ? "border-l border-white/[0.07]" : ""}`}
            >
              <div className={`flex items-center justify-start sm:justify-center gap-1.5 ${item.color} mb-1.5`}>
                <item.icon className="h-3 w-3" aria-hidden="true" />
                <span className="tech-label">{item.label}</span>
              </div>
              <div className="text-base font-bold font-mono text-white">{item.value}</div>
              <div className="text-[11px] text-zinc-500 font-mono mt-0.5">{item.sub}</div>
            </div>
          ))}
        </div>

        {/* ============================================================
            BELOW-THE-FOLD COMPACT SECTION: "How ScamShield thinks"
            ============================================================ */}
        <div id="how-it-works" className="mt-16 lg:mt-20 pt-12 border-t border-white/[0.07] scroll-mt-20">
          
          <div className="text-center max-w-2xl mx-auto mb-10">
            <div className="inline-flex items-center gap-1.5 rounded-full border border-violet-500/20 bg-violet-500/10 px-3 py-1 text-[10px] font-mono text-violet-300 uppercase tracking-widest mb-3">
              <span>Security Architecture</span>
            </div>
            <h2 className="text-2xl sm:text-3xl font-extrabold text-white font-heading">
              How ScamShield thinks
            </h2>
            <p className="text-sm text-zinc-400 mt-2">
              Autonomous 3-stage defense pipeline combining deterministic detection with Bedrock cognitive intelligence.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* Stage 1: DETECT */}
            <div className="rounded-2xl border border-white/[0.08] bg-[#0c0d15]/80 p-6 backdrop-blur-sm relative overflow-hidden group hover:border-cyan-500/30 transition-colors duration-300">
              <div className="text-3xl font-black font-mono text-cyan-400/25 mb-3 group-hover:text-cyan-400/40 transition-colors">
                01
              </div>
              <div className="flex items-center gap-2 mb-2">
                <Search className="h-4 w-4 text-cyan-400" />
                <h3 className="text-base font-bold text-white font-heading tracking-wide">
                  DETECT
                </h3>
              </div>
              <p className="text-xs text-zinc-400 leading-relaxed">
                Ingests communication across SMS, WhatsApp, Email, or Telegram. Heuristically parses deceptive urgency, domain mimicry, credential traps, and coercion signatures.
              </p>
            </div>

            {/* Stage 2: ANALYZE */}
            <div className="rounded-2xl border border-white/[0.08] bg-[#0c0d15]/80 p-6 backdrop-blur-sm relative overflow-hidden group hover:border-violet-500/30 transition-colors duration-300">
              <div className="text-3xl font-black font-mono text-violet-400/25 mb-3 group-hover:text-violet-400/40 transition-colors">
                02
              </div>
              <div className="flex items-center gap-2 mb-2">
                <Cpu className="h-4 w-4 text-violet-400" />
                <h3 className="text-base font-bold text-white font-heading tracking-wide">
                  ANALYZE
                </h3>
              </div>
              <p className="text-xs text-zinc-400 leading-relaxed">
                Executes dual-layer risk fusion: deterministic regex &amp; threat intelligence rules corroborated with Amazon Bedrock cognitive kill-chain modeling.
              </p>
            </div>

            {/* Stage 3: PROTECT */}
            <div className="rounded-2xl border border-white/[0.08] bg-[#0c0d15]/80 p-6 backdrop-blur-sm relative overflow-hidden group hover:border-emerald-500/30 transition-colors duration-300">
              <div className="text-3xl font-black font-mono text-emerald-400/25 mb-3 group-hover:text-emerald-400/40 transition-colors">
                03
              </div>
              <div className="flex items-center gap-2 mb-2">
                <ShieldCheck className="h-4 w-4 text-emerald-400" />
                <h3 className="text-base font-bold text-white font-heading tracking-wide">
                  PROTECT
                </h3>
              </div>
              <p className="text-xs text-zinc-400 leading-relaxed">
                Outputs explainable Scam DNA™ breakdown, calibrated 0–100 risk score, attacker objective analysis, and immediately actionable protective guidance.
              </p>
            </div>
          </div>

        </div>

      </div>
    </div>
  );
}
