"use client";

import React, { useState } from "react";
import {
  Send, UserX, AlertTriangle, Key, ShieldAlert,
  ArrowRight, Activity, Terminal,
} from "lucide-react";
import type { AttackStep } from "@/types/analysis";

interface ScamDNAVisualProps {
  customSteps?: AttackStep[];
  interactive?: boolean;
}

interface VisualKillChainStep {
  step: number;
  stage: string;
  tag: string;
  icon: React.ComponentType<{ className?: string }>;
  color: string;
  description: string;
  mechanism: string;
  findingId?: string;
  source?: string;
  evidence?: string;
}

const DEFAULT_KILL_CHAIN: VisualKillChainStep[] = [
  {
    step: 1,
    stage: "Inbound Lure",
    tag: "ENTRY VECTOR",
    icon: Send,
    color: "emerald",
    description: "Spoofed SMS, WhatsApp alert, or deceptive communication initiates unsolicited contact.",
    mechanism: "Spoofed Sender ID / Phishing hook bypassing standard SMS filters",
  },
  {
    step: 2,
    stage: "Authority Impersonation",
    tag: "DECEPTION LAYER",
    icon: UserX,
    color: "indigo",
    description: "Falsely adopts trusted institutional identity (Bank, Utility, Police, Delivery) to induce obedience.",
    mechanism: "Brand spoofing & deceptive authority pretext",
  },
  {
    step: 3,
    stage: "Coercive Urgency",
    tag: "PSYCHOLOGICAL LEVER",
    icon: AlertTriangle,
    color: "amber",
    description: "Imposes an artificial deadline, account freeze threat, or legal ultimatum to disable calm scrutiny.",
    mechanism: "Panic induction & manufactured time pressure",
  },
  {
    step: 4,
    stage: "Credential Extraction",
    tag: "PAYLOAD ACTION",
    icon: Key,
    color: "orange",
    description: "Victim is steered to disclose OTP, banking PIN, NetBanking password, or scan a fraudulent QR code.",
    mechanism: "Credential harvesting form / malicious APK download",
  },
  {
    step: 5,
    stage: "Asset Exfiltration",
    tag: "FINAL IMPACT",
    icon: ShieldAlert,
    color: "red",
    description: "Attacker executes unauthorized fund transfers, account takeover, or identity fraud.",
    mechanism: "Instant debit via unauthorized IMPS/UPI or session hijack",
  },
];

// Color tokens per kill-chain stage
const colorTokens: Record<string, {
  text: string; border: string; bg: string; bgActive: string;
  borderActive: string; dot: string; glow: string; stop: string;
}> = {
  emerald: {
    text: "text-emerald-400", border: "border-emerald-500/20",
    bg: "bg-emerald-500/5", bgActive: "bg-emerald-500/12",
    borderActive: "border-emerald-500/50", dot: "bg-emerald-400",
    glow: "shadow-[0_0_18px_rgba(16,185,129,0.18)]", stop: "#10b981",
  },
  indigo: {
    text: "text-indigo-400", border: "border-indigo-500/20",
    bg: "bg-indigo-500/5", bgActive: "bg-indigo-500/12",
    borderActive: "border-indigo-500/50", dot: "bg-indigo-400",
    glow: "shadow-[0_0_18px_rgba(99,102,241,0.2)]", stop: "#6366f1",
  },
  amber: {
    text: "text-amber-400", border: "border-amber-500/20",
    bg: "bg-amber-500/5", bgActive: "bg-amber-500/12",
    borderActive: "border-amber-500/50", dot: "bg-amber-400",
    glow: "shadow-[0_0_18px_rgba(245,158,11,0.18)]", stop: "#f59e0b",
  },
  orange: {
    text: "text-orange-400", border: "border-orange-500/20",
    bg: "bg-orange-500/5", bgActive: "bg-orange-500/12",
    borderActive: "border-orange-500/50", dot: "bg-orange-400",
    glow: "shadow-[0_0_18px_rgba(249,115,22,0.18)]", stop: "#f97316",
  },
  red: {
    text: "text-red-400", border: "border-red-500/20",
    bg: "bg-red-500/5", bgActive: "bg-red-500/12",
    borderActive: "border-red-500/50", dot: "bg-red-400",
    glow: "shadow-[0_0_18px_rgba(239,68,68,0.18)]", stop: "#ef4444",
  },
};

const DEFAULT_COLORS = ["emerald", "indigo", "amber", "orange", "red"];

export default function ScamDNAVisual({ customSteps, interactive = true }: ScamDNAVisualProps) {
  const [selectedStep, setSelectedStep] = useState<number>(1);

  const steps: VisualKillChainStep[] = customSteps
    ? customSteps.map((s, idx) => ({
        step: s.step || idx + 1,
        stage: s.stage,
        tag: `STAGE 0${s.step || idx + 1}`,
        icon: DEFAULT_KILL_CHAIN[idx % DEFAULT_KILL_CHAIN.length].icon,
        color: DEFAULT_COLORS[idx % DEFAULT_COLORS.length],
        description: s.description,
        findingId: s.findingId,
        source: s.source,
        evidence: s.evidence,
        mechanism: s.findingId
          ? `Grounded in finding: ${s.findingId}`
          : "Observed threat vector during forensic analysis",
      }))
    : DEFAULT_KILL_CHAIN;

  if (steps.length === 0) {
    return null;
  }

  const currentActive = steps.find((s) => s.step === selectedStep) || steps[0];

  return (
    <div
      className="rounded-2xl border border-white/[0.07] bg-[#09091a] p-5 sm:p-7 backdrop-blur-md shadow-2xl relative overflow-hidden"
      aria-label="Scam DNA attack vector visualization"
    >
      {/* Technical watermark */}
      <div
        className="absolute top-0 right-0 p-4 pointer-events-none font-mono text-[8px] text-right hidden sm:block leading-snug"
        style={{ color: "rgba(255,255,255,0.03)" }}
        aria-hidden="true"
      >
        KILL_CHAIN_MAPPING_ENGINE<br />
        ATTACKER_INTENT_ISOLATION
      </div>

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/[0.06] pb-4 mb-5">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-500/10 border border-indigo-500/25 text-indigo-400">
            <Activity className="h-4 w-4" aria-hidden="true" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white font-heading">
              How the Scam Works
            </h3>
            <p className="text-xs text-zinc-400 mt-0.5">
              Step-by-step path showing how this scam attempts to deceive you
            </p>
          </div>
        </div>
        <div className="inline-flex items-center gap-1.5 rounded-full border border-indigo-500/30 bg-indigo-500/10 px-3 py-1 text-xs font-mono font-semibold text-indigo-300">
          <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" aria-hidden="true" />
          {steps.length}-Step Attack Path
        </div>
      </div>

      {/* ─── DESKTOP: Connected horizontal graph ─── */}
      <div className="hidden lg:block relative my-2" aria-label="Kill chain stages">
        {/* SVG connector with animated dash draw */}
        <svg
          className="absolute inset-0 w-full h-full pointer-events-none"
          preserveAspectRatio="none"
          aria-hidden="true"
        >
          <defs>
            <linearGradient id="dnaLineGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              {steps.map((st, i) => (
                <stop
                  key={st.step}
                  offset={`${(i / (steps.length - 1)) * 100}%`}
                  stopColor={colorTokens[st.color]?.stop || "#6366f1"}
                  stopOpacity="0.5"
                />
              ))}
            </linearGradient>
          </defs>
          <line
            x1="4%" y1="50%" x2="96%" y2="50%"
            stroke="url(#dnaLineGrad)"
            strokeWidth="1.5"
            strokeDasharray="6 5"
            className="dna-connector"
          />
        </svg>

        {/* Stage nodes */}
        <div
          className="grid gap-3 relative z-10"
          style={{ gridTemplateColumns: `repeat(${steps.length}, 1fr)` }}
        >
          {steps.map((st) => {
            const Icon       = st.icon;
            const c          = colorTokens[st.color] || colorTokens.indigo;
            const isSelected = selectedStep === st.step;

            return (
              <button
                key={st.step}
                type="button"
                id={`dna-node-${st.step}`}
                onClick={() => interactive && setSelectedStep(st.step)}
                aria-pressed={isSelected}
                aria-label={`Step ${st.step}: ${st.stage}`}
                className={`text-left p-4 rounded-xl border transition-all duration-200 group relative cursor-pointer ${
                  isSelected
                    ? `${c.borderActive} ${c.bgActive} ${c.glow} ring-1 ${c.borderActive.replace("border-", "ring-")}`
                    : `${c.border} ${c.bg} hover:${c.borderActive} hover:${c.bgActive}`
                }`}
              >
                {/* Step number + color dot */}
                <div className="flex items-center justify-between mb-2.5">
                  <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${
                    isSelected ? `bg-${st.color}-500/30 ${c.text}` : "bg-zinc-800/80 text-zinc-400"
                  }`}>
                    0{st.step}
                  </span>
                  <span className={`h-2 w-2 rounded-full ${c.dot} ${isSelected ? "animate-node-pulse" : ""}`} aria-hidden="true" />
                </div>

                {/* Icon + stage name */}
                <div className="flex items-center gap-2 mb-2">
                  <Icon className={`h-4 w-4 shrink-0 transition-colors duration-150 ${
                    isSelected ? c.text : "text-zinc-400 group-hover:text-zinc-200"
                  }`} aria-hidden="true" />
                  <h4 className="text-[15px] font-bold text-zinc-100 leading-snug font-heading">{st.stage}</h4>
                </div>

                {/* Description excerpt */}
                <p className="text-sm text-zinc-300 line-clamp-2 leading-relaxed group-hover:text-zinc-200 transition-colors duration-150">
                  {st.description}
                </p>
              </button>
            );
          })}
        </div>
      </div>

      {/* ─── MOBILE: Vertical stacked list ─── */}
      <div className="block lg:hidden space-y-2.5 my-2" aria-label="Kill chain stages">
        {steps.map((st) => {
          const Icon       = st.icon;
          const c          = colorTokens[st.color] || colorTokens.indigo;
          const isSelected = selectedStep === st.step;

          return (
            <div
              key={st.step}
              role="button"
              tabIndex={0}
              id={`dna-mobile-node-${st.step}`}
              onClick={() => interactive && setSelectedStep(st.step)}
              onKeyDown={(e) => e.key === "Enter" && interactive && setSelectedStep(st.step)}
              aria-pressed={isSelected}
              aria-label={`Step ${st.step}: ${st.stage}`}
              className={`p-3.5 rounded-xl border transition-all duration-200 cursor-pointer ${
                isSelected
                  ? `${c.borderActive} ${c.bgActive}`
                  : `${c.border} bg-zinc-900/30 hover:${c.borderActive}`
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${
                    isSelected ? `${c.bgActive} ${c.text}` : "bg-zinc-800 text-zinc-400"
                  }`}>
                    0{st.step}
                  </span>
                  <Icon className={`h-4 w-4 ${c.text}`} aria-hidden="true" />
                  <span className="text-[15px] font-bold text-zinc-100 font-heading">{st.stage}</span>
                </div>
                <span className="text-xs font-mono text-zinc-400 hidden sm:inline">{st.tag}</span>
              </div>
              {isSelected && (
                <p className="text-sm text-zinc-300 mt-2.5 pl-9 leading-relaxed">{st.description}</p>
              )}
            </div>
          );
        })}
      </div>

      {/* ─── Inspector panel for selected stage ─── */}
      {interactive && currentActive && (
        <div className="mt-4 rounded-xl border border-white/[0.08] bg-[#05060c] p-4 text-xs font-mono">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-white/[0.06] pb-2.5 mb-2.5">
            <div className="flex items-center gap-2">
              <Terminal className="h-3.5 w-3.5 text-indigo-400" aria-hidden="true" />
              <span className="text-indigo-300 font-bold text-xs uppercase tracking-wider">
                Step 0{currentActive.step} Details · {currentActive.tag}
              </span>
            </div>
            <span className="text-xs text-zinc-400">
              Method: <span className="text-zinc-300">{currentActive.mechanism}</span>
            </span>
          </div>
          <div className="flex items-start gap-2.5 text-zinc-300">
            <ArrowRight className="h-4 w-4 text-indigo-400 shrink-0 mt-0.5" aria-hidden="true" />
            <p className="leading-relaxed font-sans text-sm">
              <strong className="text-white font-semibold mr-1.5">{currentActive.stage}:</strong>
              {currentActive.description}
            </p>
          </div>
          {currentActive.evidence && (
            <div className="mt-2 text-zinc-400 pl-6 text-xs font-mono">
              <span className="text-zinc-500">Supporting Evidence: </span>
              <span className="text-indigo-300 font-semibold">&ldquo;{currentActive.evidence}&rdquo;</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
