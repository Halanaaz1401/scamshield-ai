"use client";

import React from "react";
import { Shield, Lock, Terminal, ShieldCheck } from "lucide-react";

export default function Footer() {
  return (
    <footer className="w-full border-t border-white/[0.08] bg-[#05060a] text-zinc-400">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-12 md:py-16">
        <div className="grid grid-cols-1 md:grid-cols-12 gap-10">
          
          {/* Brand and Mission */}
          <div className="md:col-span-5 space-y-4">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-indigo-500/10 border border-indigo-500/30 text-indigo-400">
                <Shield className="h-4 w-4" />
              </div>
              <div className="flex items-center gap-2">
                <span className="font-bold tracking-tight text-white text-base font-heading">ScamShield</span>
                <span className="text-xs font-semibold uppercase tracking-wider text-indigo-400 font-mono">AI</span>
              </div>
            </div>

            <p className="text-xs text-zinc-400 leading-relaxed max-w-sm">
              An AI-assisted cybersecurity platform that analyzes suspicious communications,
              unmasks attacker intent, reconstructs the psychological kill chain, and delivers
              immediate defensive playbooks.
            </p>

            <div className="flex items-center gap-2 text-[11px] font-mono text-zinc-400">
              <Lock className="h-3 w-3 text-emerald-400 shrink-0" />
              <span>Zero-Storage Architecture: Payload processed strictly in volatile memory.</span>
            </div>
          </div>

          {/* Product & Pipeline Links */}
          <div className="md:col-span-2 space-y-3">
            <h4 className="text-xs font-mono uppercase tracking-wider text-zinc-300 font-semibold">Pipeline</h4>
            <ul className="space-y-2 text-xs">
              <li>
                <a href="#analyzer" className="hover:text-white transition-colors">
                  Threat Analyzer
                </a>
              </li>
              <li>
                <a href="#analyzer" className="hover:text-white transition-colors">
                  Kill Chain / Scam DNA
                </a>
              </li>
              <li>
                <span className="text-zinc-400">Deterministic Engine</span>
              </li>
              <li>
                <span className="text-zinc-400">Amazon Bedrock AI</span>
              </li>
              <li>
                <span className="text-zinc-400">Risk Fusion Matrix</span>
              </li>
            </ul>
          </div>

          {/* Resources & Security */}
          <div className="md:col-span-2 space-y-3">
            <h4 className="text-xs font-mono uppercase tracking-wider text-zinc-300 font-semibold">Security</h4>
            <ul className="space-y-2 text-xs">
              <li className="flex items-center gap-1.5">
                <ShieldCheck className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                <span>Zero-PII Bound</span>
              </li>
              <li>
                <span className="text-zinc-400">Character Boundary (4k)</span>
              </li>
              <li>
                <span className="text-zinc-400">Input Sanitization</span>
              </li>
              <li>
                <span className="text-zinc-400">OWASP Top 10 LLM</span>
              </li>
            </ul>
          </div>

          {/* Attribution & Hackathon Details */}
          <div className="md:col-span-3 space-y-3">
            <h4 className="text-xs font-mono uppercase tracking-wider text-zinc-300 font-semibold">Hackathon</h4>
            <div className="rounded-xl border border-white/[0.08] bg-zinc-900/40 p-3.5 space-y-2">
              <div className="flex items-center gap-2">
                <Terminal className="h-3.5 w-3.5 text-indigo-400" />
                <span className="text-xs font-semibold text-zinc-200">AWS / WeMakeDevs</span>
              </div>
              <p className="text-[11px] text-zinc-400 leading-snug">
                Engineered for First Commit: Explainable scam detection combining AWS Lambda, API Gateway, and Amazon Bedrock.
              </p>
              <div className="text-[10px] font-mono text-indigo-400">
                Release Validation // Production Grade
              </div>
            </div>
          </div>

        </div>

        {/* Bottom Bar */}
        <div className="mt-12 pt-8 border-t border-white/[0.06] flex flex-col sm:flex-row sm:items-center justify-between gap-4 text-xs text-zinc-400">
          <p>© {new Date().getFullYear()} ScamShield AI. Developed for AWS / WeMakeDevs First Commit Hackathon.</p>
          <div className="flex items-center gap-4 text-zinc-400 font-mono text-[11px]">
            <span>Stateless Verification</span>
            <span>•</span>
            <span>OWASP Defended</span>
            <span>•</span>
            <span>Dual-Layer Engine</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
