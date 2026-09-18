"use client";

import React, { useEffect, useState } from "react";
import { CheckCircle2, Loader2, Terminal, Cpu, Search } from "lucide-react";

interface ScanningStateProps {
  onComplete?: () => void;
}

const SCAN_STAGES = [
  {
    id: 1,
    title: "Enforcing Input Boundaries & Sanitization",
    detail: "Validating UTF-8 encoding, stripping control characters, enforcing 4,000-character perimeter.",
    log: "PERIMETER: Sanitization complete • 0 anomalies detected",
    color: "emerald",
  },
  {
    id: 2,
    title: "Deterministic Heuristic Threat Sweep",
    detail: "Pattern matching for credential harvesting, UPI/banking lures, coercive deadlines, and lookalike domains.",
    log: "HEURISTICS: 12 regex signature banks active • Evaluating indicator flags",
    color: "indigo",
  },
  {
    id: 3,
    title: "Amazon Bedrock Contextual Language Evaluation",
    detail: "Prompting Claude for intent extraction, deceptive framing detection, and psychological lever analysis.",
    log: "BEDROCK_AI: Invoking Claude 3.5 Sonnet via AWS Bedrock Runtime",
    color: "violet",
  },
  {
    id: 4,
    title: "Calibrating Risk Fusion & Scam DNA Kill Chain",
    detail: "Synthesizing deterministic indicators with semantic evaluation into unified confidence score.",
    log: "RISK_FUSION: Matrix calibrated • Compiling defensive playbook",
    color: "amber",
  },
];

const colorMap: Record<string, { text: string; bg: string; border: string; dot: string }> = {
  emerald: { text: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/40", dot: "bg-emerald-400" },
  indigo:  { text: "text-indigo-400",  bg: "bg-indigo-500/10",  border: "border-indigo-500/40",  dot: "bg-indigo-400"  },
  violet:  { text: "text-violet-400",  bg: "bg-violet-500/10",  border: "border-violet-500/40",  dot: "bg-violet-400"  },
  amber:   { text: "text-amber-400",   bg: "bg-amber-500/10",   border: "border-amber-500/40",   dot: "bg-amber-400"   },
};

export default function ScanningState({ onComplete }: ScanningStateProps) {
  const [currentStage, setCurrentStage] = useState(1);
  const [progressPercent, setProgressPercent] = useState(8);

  useEffect(() => {
    const STAGE_DURATION = 700;
    const PROGRESS_TICK  = 100;

    const progressInterval = setInterval(() => {
      setProgressPercent((prev) => {
        const target = (currentStage / SCAN_STAGES.length) * 98;
        return prev < target ? Math.min(prev + 3 + Math.random() * 5, target) : prev;
      });
    }, PROGRESS_TICK);

    const stageInterval = setInterval(() => {
      setCurrentStage((prev) => {
        if (prev < SCAN_STAGES.length) return prev + 1;
        clearInterval(stageInterval);
        clearInterval(progressInterval);
        setProgressPercent(100);
        if (onComplete) setTimeout(onComplete, 500);
        return prev;
      });
    }, STAGE_DURATION);

    return () => {
      clearInterval(progressInterval);
      clearInterval(stageInterval);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [onComplete]);

  return (
    <div
      className="rounded-2xl border border-indigo-500/25 bg-[#09091180] p-6 sm:p-8 backdrop-blur-md shadow-2xl relative overflow-hidden"
      role="status"
      aria-label="Threat analysis in progress"
      aria-live="polite"
    >
      {/* Animated top scanline */}
      <div
        className="absolute inset-x-0 top-0 h-[2px] pointer-events-none animate-scanline"
        style={{ background: "linear-gradient(90deg, transparent 0%, rgba(99,102,241,0.8) 40%, rgba(139,92,246,0.8) 60%, transparent 100%)" }}
        aria-hidden="true"
      />

      {/* Ambient glow behind the card */}
      <div
        className="absolute inset-0 pointer-events-none opacity-30"
        style={{ background: "radial-gradient(ellipse at 50% 0%, rgba(99,102,241,0.12) 0%, transparent 60%)" }}
        aria-hidden="true"
      />

      <div className="max-w-xl mx-auto relative">
        {/* Terminal header */}
        <div className="flex items-center justify-between border-b border-white/[0.06] pb-4 mb-6">
          <div className="flex items-center gap-2.5">
            <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-indigo-500/10 border border-indigo-500/25 text-indigo-400">
              <Terminal className="h-3.5 w-3.5" aria-hidden="true" />
            </div>
            <div>
              <div className="text-[11px] font-mono font-bold uppercase tracking-widest text-white">
                Threat Inspection Pipeline Active
              </div>
              <div className="text-[10px] font-mono text-zinc-500 mt-0.5">
                AWS_BEDROCK // DUAL_LAYER_DETECTION_ENGINE
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs font-bold text-indigo-300">
              {Math.floor(progressPercent)}%
            </span>
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-70" aria-hidden="true" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" aria-hidden="true" />
            </span>
          </div>
        </div>

        {/* Progress bar */}
        <div className="mb-6">
          <div className="flex items-center justify-between text-[10px] font-mono text-zinc-500 mb-1.5">
            <span className="flex items-center gap-1.5">
              <Search className="h-2.5 w-2.5 text-indigo-400 animate-spin" aria-hidden="true" />
              Scanning payload vectors...
            </span>
            <span>Stage 0{currentStage} / 04</span>
          </div>
          <div className="h-1.5 w-full bg-zinc-950 rounded-full overflow-hidden border border-white/[0.05]">
            <div
              className="h-full rounded-full transition-all duration-500 ease-out"
              style={{
                width: `${progressPercent}%`,
                background: "linear-gradient(90deg, #6366f1, #8b5cf6, #10b981)",
              }}
              role="progressbar"
              aria-valuenow={Math.floor(progressPercent)}
              aria-valuemin={0}
              aria-valuemax={100}
            />
          </div>
        </div>

        {/* Stage cards */}
        <div className="space-y-2.5">
          {SCAN_STAGES.map((stage) => {
            const isCompleted = currentStage > stage.id;
            const isActive    = currentStage === stage.id;
            const c           = colorMap[stage.color];

            return (
              <div
                key={stage.id}
                className={`rounded-xl border p-3.5 transition-all duration-300 ${
                  isActive
                    ? `${c.border} ${c.bg} shadow-[0_0_20px_rgba(99,102,241,0.08)]`
                    : isCompleted
                    ? "border-white/[0.05] bg-zinc-900/20"
                    : "border-transparent bg-transparent opacity-30"
                }`}
              >
                <div className="flex items-start gap-3">
                  {/* Status icon */}
                  <div className="mt-0.5 shrink-0 w-4">
                    {isCompleted ? (
                      <CheckCircle2 className="h-4 w-4 text-emerald-400" aria-label="Completed" />
                    ) : isActive ? (
                      <Loader2 className={`h-4 w-4 ${c.text} animate-spin`} aria-label="In progress" />
                    ) : (
                      <div className="h-4 w-4 rounded-full border border-zinc-700/50" aria-label="Queued" />
                    )}
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between gap-2">
                      <h4 className={`text-[11px] font-semibold ${
                        isActive ? "text-white" : isCompleted ? "text-zinc-300" : "text-zinc-600"
                      }`}>
                        {stage.title}
                      </h4>
                      <span className={`text-[9px] font-mono uppercase shrink-0 ${
                        isActive ? c.text : isCompleted ? "text-emerald-400" : "text-zinc-600"
                      }`}>
                        {isCompleted ? "✓ Done" : isActive ? "Running" : "Queued"}
                      </span>
                    </div>

                    {(isActive || isCompleted) && (
                      <p className="text-[10px] text-zinc-500 mt-0.5 leading-relaxed">{stage.detail}</p>
                    )}

                    {/* Terminal log line — only for active stage */}
                    {isActive && (
                      <div className="mt-2 rounded-lg bg-[#04050a] border border-white/[0.04] px-2.5 py-1.5 font-mono text-[10px] text-indigo-300 flex items-center gap-1.5">
                        <span className="text-zinc-600">&gt;</span>
                        <span className="truncate">{stage.log}</span>
                        <span className="animate-terminal-blink text-indigo-400 ml-auto shrink-0">▊</span>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Bottom telemetry bar */}
        <div className="mt-6 pt-4 border-t border-white/[0.05] flex items-center justify-between text-[10px] font-mono text-zinc-500">
          <span className="flex items-center gap-1.5">
            <Cpu className="h-2.5 w-2.5 text-indigo-400" aria-hidden="true" />
            Stateless In-Memory Inspection
          </span>
          <span className="text-emerald-500/80 flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" aria-hidden="true" />
            Zero Data Leakage Perimeter
          </span>
        </div>
      </div>
    </div>
  );
}
