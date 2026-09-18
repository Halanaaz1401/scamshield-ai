"use client";

import React from "react";
import { ShieldCheck, ArrowUpRight, Lock, CheckCircle2, ShieldAlert, Terminal } from "lucide-react";

export default function FinalCTA() {
  const scrollToAnalyzer = () => {
    const el = document.getElementById("analyzer");
    if (el) {
      el.scrollIntoView({ behavior: "smooth" });
    }
  };

  return (
    <section className="relative overflow-hidden py-12 sm:py-16 border-t border-white/[0.08]">
      {/* Ambient glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[350px] bg-indigo-500/5 blur-[140px] rounded-full pointer-events-none" />

      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 relative">
        <div className="relative overflow-hidden rounded-3xl border border-white/[0.1] bg-gradient-to-br from-[#0e1017] via-[#090b10] to-[#06070a] p-8 sm:p-12 lg:p-16 shadow-2xl">
          
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 items-center">
            {/* Left Content Column */}
            <div className="lg:col-span-7 space-y-6">
              <div className="inline-flex items-center gap-2 rounded-full border border-indigo-500/30 bg-indigo-500/10 px-3.5 py-1 text-xs font-mono text-indigo-300">
                <ShieldCheck className="h-3.5 w-3.5 text-indigo-400" />
                <span>CYBERSECURITY POSTURE // ACTIVE DEFENSE</span>
              </div>

              <h2 className="text-3xl sm:text-4xl lg:text-5xl font-extrabold tracking-tight text-white leading-tight font-heading">
                Pause before <br />
                <span className="bg-gradient-to-r from-indigo-300 via-purple-200 to-white bg-clip-text text-transparent">
                  you trust.
                </span>
              </h2>

              <p className="text-base sm:text-lg text-zinc-400 max-w-xl leading-relaxed">
                Attackers exploit artificial urgency, impersonation, and pressure to force hasty decisions.
                Taking 10 seconds to inspect message indicators breaks the psychological kill chain.
              </p>

              {/* Defensive Checklist */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
                <div className="flex items-center gap-2.5 text-xs text-zinc-300 font-medium">
                  <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                  <span>Never share OTP or MFA codes</span>
                </div>
                <div className="flex items-center gap-2.5 text-xs text-zinc-300 font-medium">
                  <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                  <span>Verify bank alerts out-of-band</span>
                </div>
                <div className="flex items-center gap-2.5 text-xs text-zinc-300 font-medium">
                  <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                  <span>Inspect deceptive URL domains</span>
                </div>
                <div className="flex items-center gap-2.5 text-xs text-zinc-300 font-medium">
                  <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                  <span>Reject urgent wire / QR demands</span>
                </div>
              </div>

              {/* Action Button & Metadata */}
              <div className="pt-4 flex flex-wrap items-center gap-4">
                <button
                  type="button"
                  onClick={scrollToAnalyzer}
                  className="inline-flex items-center gap-2.5 rounded-xl bg-indigo-600 px-6 py-3.5 text-xs font-mono font-bold uppercase tracking-wider text-white shadow-lg shadow-indigo-500/20 hover:bg-indigo-500 transition border border-indigo-500/50"
                >
                  <ShieldAlert className="h-4 w-4" />
                  <span>Inspect Suspicious Communication</span>
                  <ArrowUpRight className="h-4 w-4" />
                </button>
                <div className="text-xs font-mono text-zinc-400 flex items-center gap-1.5">
                  <Lock className="h-3.5 w-3.5 text-emerald-400" />
                  <span>Stateless In-Memory • Zero-Storage</span>
                </div>
              </div>
            </div>

            {/* Right Visual Column — Cybersecurity Telemetry Visual */}
            <div className="lg:col-span-5 flex justify-center">
              <div className="w-full max-w-sm rounded-2xl border border-white/[0.08] bg-[#07080d] p-6 shadow-xl relative overflow-hidden">
                {/* Decorative scanning line */}
                <div className="absolute inset-x-0 h-px bg-gradient-to-r from-transparent via-indigo-500/50 to-transparent top-0 animate-pulse" />

                <div className="flex items-center justify-between border-b border-white/[0.08] pb-4 mb-4">
                  <div className="flex items-center gap-2">
                    <div className="h-2 w-2 rounded-full bg-emerald-400 animate-ping" />
                    <span className="text-xs font-mono text-zinc-300">SHIELD_STATUS</span>
                  </div>
                  <span className="text-[10px] font-mono text-indigo-400 font-semibold uppercase">
                    Continuous Protection
                  </span>
                </div>

                <div className="space-y-3 font-mono text-xs">
                  <div className="rounded-xl border border-white/[0.06] bg-zinc-900/40 p-3 flex items-start gap-3">
                    <Terminal className="h-4 w-4 text-indigo-400 shrink-0 mt-0.5" />
                    <div>
                      <div className="text-zinc-200 font-semibold text-[11px]">Vector: Social Engineering Trap</div>
                      <p className="text-[10px] text-zinc-400 mt-0.5">
                        Psychological manipulation detected &amp; neutralised before credential compromise
                      </p>
                    </div>
                  </div>

                  <div className="rounded-xl border border-white/[0.06] bg-zinc-900/40 p-3 flex items-start gap-3">
                    <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
                    <div>
                      <div className="text-zinc-200 font-semibold text-[11px]">Status: Defense Playbook Issued</div>
                      <p className="text-[10px] text-zinc-400 mt-0.5">
                        Clear defensive directives generated to protect financial assets
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>

          </div>
        </div>
      </div>
    </section>
  );
}
