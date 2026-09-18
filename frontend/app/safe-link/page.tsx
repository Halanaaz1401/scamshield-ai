"use client";

import React, { useState, useRef } from "react";
import Link from "next/link";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ExternalLink,
  RotateCcw,
  Clipboard,
  ArrowRight,
  CheckCircle2,
  Lock,
  Sparkles,
  ChevronDown,
  ChevronUp,
  Info,
} from "lucide-react";
import Navbar from "@/components/layout/Navbar";
import Footer from "@/components/layout/Footer";
import { analyzeMessage } from "@/lib/analysisService";
import type { AnalysisResponse, Indicator } from "@/types/analysis";

interface LinkPreset {
  id: string;
  title: string;
  category: string;
  url: string;
}

const DEMO_PRESETS: LinkPreset[] = [
  {
    id: "sbi-kyc",
    title: "SBI KYC Phishing",
    category: "Banking Fraud",
    url: "https://sbi-verify-login-example.xyz/login",
  },
  {
    id: "electricity-bill",
    title: "Electricity Cutoff Scam",
    category: "Utility Lure",
    url: "https://electricity-update-example.xyz/pay",
  },
  {
    id: "india-post",
    title: "India Post Parcel Seizure",
    category: "Delivery Extortion",
    url: "https://indiapost-parcel-delivery.top",
  },
  {
    id: "hdfc-kyc",
    title: "HDFC Reward Scam",
    category: "Credential Theft",
    url: "https://hdfc-rewards-portal.xyz/claim",
  },
  {
    id: "legitimate-sbi",
    title: "Official State Bank Portal",
    category: "Official Bank",
    url: "https://www.onlinesbi.sbi",
  },
];

const DISALLOWED_SCHEMES = ["javascript:", "data:", "file:", "vbscript:", "blob:"];

export default function SafeLinkPage() {
  const [urlInput, setUrlInput] = useState<string>("");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [showDetails, setShowDetails] = useState<boolean>(false);
  const [analyzedUrl, setAnalyzedUrl] = useState<string>("");
  const [showContinueModal, setShowContinueModal] = useState<boolean>(false);
  const [focused, setFocused] = useState<boolean>(false);

  const inputRef = useRef<HTMLInputElement>(null);

  // Client-side URL validation
  const validateUrl = (raw: string): { isValid: boolean; normalized: string; error?: string } => {
    const trimmed = raw.trim();
    if (!trimmed) {
      return { isValid: false, normalized: "", error: "Please enter or paste a URL to inspect." };
    }

    if (trimmed.length > 4000) {
      return {
        isValid: false,
        normalized: "",
        error: `URL length (${trimmed.length} chars) exceeds the 4,000 character maximum limit.`,
      };
    }

    const lower = trimmed.toLowerCase();
    for (const scheme of DISALLOWED_SCHEMES) {
      if (lower.startsWith(scheme)) {
        return {
          isValid: false,
          normalized: "",
          error: `Disallowed protocol scheme: "${scheme}". Non-web URI schemes are blocked for client-side security.`,
        };
      }
    }

    // Require either a recognized protocol or a valid domain structure
    const hasProtocol = lower.startsWith("http://") || lower.startsWith("https://");
    const testTarget = hasProtocol ? trimmed : `https://${trimmed}`;

    try {
      const parsed = new URL(testTarget);
      if (!parsed.hostname || !parsed.hostname.includes(".")) {
        // Exception for localhost/IPs, otherwise flag malformed domain
        if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(parsed.hostname) && parsed.hostname !== "localhost") {
          return {
            isValid: false,
            normalized: "",
            error: "Please enter a valid website address with a domain name (e.g. example.com).",
          };
        }
      }
      return { isValid: true, normalized: testTarget };
    } catch {
      return {
        isValid: false,
        normalized: "",
        error: "Invalid web address format. Please check the link and try again.",
      };
    }
  };

  const handlePasteClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        setUrlInput(text.trim());
        setErrorMsg(null);
      }
    } catch {
      // Browser permission denied or not supported
    }
  };

  const handleClear = () => {
    setUrlInput("");
    setErrorMsg(null);
    inputRef.current?.focus();
  };

  const handleSelectPreset = (preset: LinkPreset) => {
    setUrlInput(preset.url);
    setErrorMsg(null);
    setResult(null);
    inputRef.current?.focus();
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);

    const check = validateUrl(urlInput);
    if (!check.isValid) {
      setErrorMsg(check.error || "Please enter a valid URL.");
      return;
    }

    setIsLoading(true);
    setAnalyzedUrl(check.normalized);

    try {
      const analysisResult = await analyzeMessage(check.normalized, "url");
      setResult(analysisResult);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to analyze the submitted link.";
      setErrorMsg(msg);
    } finally {
      setIsLoading(false);
    }
  };

  const handleReset = () => {
    setResult(null);
    setErrorMsg(null);
    setUrlInput("");
    setAnalyzedUrl("");
    setShowDetails(false);
    setShowContinueModal(false);
    setTimeout(() => {
      inputRef.current?.focus();
    }, 50);
  };

  // Determine risk presentation state based on canonical backend verdict & score
  const riskScore = result?.riskScore ?? 0;
  const isDangerous =
    result?.riskLevel === "CRITICAL" ||
    result?.riskLevel === "HIGH" ||
    result?.verdict === "KNOWN_MALICIOUS" ||
    result?.verdict === "HIGH_RISK" ||
    riskScore >= 60;
  const isCaution =
    result?.riskLevel === "MEDIUM" ||
    result?.verdict === "SUSPICIOUS" ||
    result?.verdict === "UNKNOWN_UNVERIFIED" ||
    (riskScore >= 20 && riskScore < 60);
  const isSafe = !isDangerous && !isCaution;

  const headlineText =
    result?.verdict === "KNOWN_MALICIOUS"
      ? "DANGEROUS LINK"
      : result?.verdict === "HIGH_RISK"
      ? "HIGH RISK LINK"
      : result?.verdict === "SUSPICIOUS"
      ? "SUSPICIOUS LINK"
      : result?.verdict === "UNKNOWN_UNVERIFIED"
      ? "DESTINATION UNVERIFIED"
      : result?.verdict === "LOW_RISK"
      ? "LOW RISK LINK"
      : result?.verdict === "BENIGN"
      ? "LINK APPEARS SAFE"
      : isDangerous
      ? "DANGEROUS LINK"
      : isCaution
      ? "CAUTION"
      : "LINK APPEARS SAFE";

  return (
    <div className="min-h-screen bg-[#07080d] text-zinc-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-white">
      <Navbar />

      <main className="flex-1 pt-24 pb-20">
        <div className="mx-auto max-w-4xl px-4 sm:px-6 lg:px-8">
          {/* Header Section */}
          <div className="text-center mb-8 sm:mb-12">
            <div className="inline-flex items-center gap-2 rounded-full border border-cyan-500/30 bg-cyan-500/10 px-3.5 py-1 text-[11px] font-mono tracking-wider text-cyan-400 uppercase mb-4 shadow-[0_0_15px_rgba(34,211,238,0.15)]">
              <Lock className="h-3 w-3" />
              <span>Zero-Click Link Inspection Gateway</span>
            </div>

            <h1
              className="text-3xl sm:text-4xl md:text-5xl font-extrabold text-white tracking-tight font-heading"
              style={{ fontFamily: "'Space Grotesk', system-ui, sans-serif" }}
            >
              SAFE LINK
            </h1>

            <p className="text-base sm:text-lg text-zinc-300 mt-2 font-medium">
              Check a suspicious link before you open it.
            </p>

            <p className="text-xs sm:text-sm text-zinc-400 mt-1 max-w-xl mx-auto">
              ScamShield checks the link for suspicious patterns before you continue.
            </p>
          </div>

          {/* Error Banner */}
          {errorMsg && (
            <div
              id="safelink-error"
              role="alert"
              className="mb-6 rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-xs sm:text-sm text-red-300 flex items-start sm:items-center justify-between shadow-lg"
            >
              <div className="flex items-center gap-2.5">
                <AlertTriangle className="h-4 w-4 text-red-400 shrink-0 mt-0.5 sm:mt-0" />
                <span>{errorMsg}</span>
              </div>
              <button
                type="button"
                onClick={() => setErrorMsg(null)}
                className="text-xs font-mono underline hover:text-white ml-3 shrink-0"
              >
                Dismiss
              </button>
            </div>
          )}

          {/* Main Input Card (Shown when not showing results) */}
          {!result && (
            <div
              className={`rounded-2xl border bg-[#0b0c14] backdrop-blur-md shadow-2xl relative overflow-hidden transition-all duration-300 ${
                focused
                  ? "border-cyan-500/40 shadow-[0_0_40px_rgba(34,211,238,0.12)]"
                  : "border-white/[0.08]"
              }`}
            >
              <div
                className={`absolute top-0 left-1/4 right-1/4 h-px transition-opacity duration-300 pointer-events-none ${
                  focused ? "opacity-100" : "opacity-40"
                }`}
                style={{ background: "linear-gradient(90deg, transparent, rgba(34,211,238,0.7), transparent)" }}
                aria-hidden="true"
              />

              <div className="p-6 sm:p-8">
                {/* Form */}
                <form onSubmit={handleSubmit} className="space-y-4">
                  <div className="relative">
                    <label htmlFor="safelink-input" className="block text-xs font-mono text-zinc-400 mb-2">
                      Destination Link to Verify
                    </label>
                    <div className="relative flex items-center">
                      <input
                        ref={inputRef}
                        id="safelink-input"
                        type="text"
                        value={urlInput}
                        onChange={(e) => {
                          setUrlInput(e.target.value);
                          if (errorMsg) setErrorMsg(null);
                        }}
                        onFocus={() => setFocused(true)}
                        onBlur={() => setFocused(false)}
                        placeholder="Paste suspicious URL here (e.g. https://sbi-verify.xyz/login)..."
                        disabled={isLoading}
                        aria-label="URL to inspect"
                        className="w-full rounded-xl border border-white/[0.08] bg-[#06070d] px-4 py-3.5 pr-24 text-sm text-zinc-100 placeholder-zinc-500 focus:border-cyan-500/50 focus:shadow-[0_0_20px_rgba(34,211,238,0.12)] focus:outline-none transition-all duration-200 font-mono"
                      />

                      {/* Input Actions */}
                      <div className="absolute right-2.5 flex items-center gap-1.5">
                        <button
                          type="button"
                          onClick={handlePasteClipboard}
                          title="Paste from clipboard"
                          className="inline-flex items-center gap-1 rounded-lg border border-white/[0.07] bg-zinc-900/90 px-2 py-1 text-[11px] font-mono text-zinc-400 hover:bg-zinc-800 hover:text-white transition-all"
                        >
                          <Clipboard className="h-3 w-3" />
                          <span className="hidden sm:inline">Paste</span>
                        </button>
                        {urlInput.length > 0 && (
                          <button
                            type="button"
                            onClick={handleClear}
                            title="Clear input"
                            className="inline-flex items-center gap-1 rounded-lg border border-white/[0.07] bg-zinc-900/90 px-2 py-1 text-[11px] font-mono text-zinc-500 hover:bg-zinc-800 hover:text-zinc-200 transition-all"
                          >
                            <RotateCcw className="h-3 w-3" />
                          </button>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Submit Button */}
                  <div className="pt-2 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div className="text-[11px] font-mono text-zinc-400 flex items-center gap-2">
                      <Shield className="h-3.5 w-3.5 text-cyan-400" />
                      <span>Zero-Proxy • Memory-Only Analysis</span>
                    </div>

                    <button
                      type="submit"
                      id="safelink-submit-btn"
                      disabled={isLoading || urlInput.trim().length === 0}
                      className={`inline-flex items-center justify-center gap-2 rounded-xl px-8 py-3.5 text-xs font-bold font-mono tracking-widest uppercase transition-all duration-150 ${
                        isLoading || urlInput.trim().length === 0
                          ? "bg-zinc-800/80 text-zinc-600 cursor-not-allowed border border-white/[0.04]"
                          : "bg-cyan-500 text-black hover:bg-cyan-400 shadow-[0_0_20px_rgba(34,211,238,0.3)] cursor-pointer"
                      }`}
                      aria-label="Check link safety"
                    >
                      {isLoading ? (
                        <>
                          <span className="h-3.5 w-3.5 border-2 border-black/30 border-t-black rounded-full animate-spin" />
                          <span>INSPECTING LINK...</span>
                        </>
                      ) : (
                        <>
                          <ShieldCheck className="h-4 w-4" />
                          <span>CHECK LINK</span>
                          <ArrowRight className="h-3.5 w-3.5" />
                        </>
                      )}
                    </button>
                  </div>
                </form>

                {/* Demo Presets Section */}
                <div className="mt-8 pt-6 border-t border-white/[0.06]">
                  <div className="flex items-center justify-between mb-3 text-xs font-mono text-zinc-400">
                    <div className="flex items-center gap-1.5">
                      <Sparkles className="h-3.5 w-3.5 text-cyan-400" />
                      <span className="font-semibold text-zinc-300">Test Realistic Threat Vectors:</span>
                    </div>
                    <span className="text-[11px] text-zinc-400 hidden sm:inline">Click link sample to inspect</span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {DEMO_PRESETS.map((preset) => (
                      <button
                        key={preset.id}
                        type="button"
                        id={`preset-${preset.id}`}
                        onClick={() => handleSelectPreset(preset)}
                        className="flex items-center justify-between rounded-xl border border-white/[0.06] bg-zinc-900/40 p-2.5 text-left hover:border-cyan-500/30 hover:bg-zinc-800/60 transition-all group"
                      >
                        <div className="min-w-0 pr-2">
                          <div className="text-xs sm:text-sm font-medium text-zinc-200 group-hover:text-white truncate">
                            {preset.title}
                          </div>
                          <div className="text-[11px] font-mono text-zinc-400 truncate mt-0.5">
                            {preset.url}
                          </div>
                        </div>
                        <span className="tech-label text-[10px] px-2.5 py-1 rounded border border-white/[0.08] text-zinc-300 shrink-0 font-mono">
                          {preset.category}
                        </span>
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Results View (Clean, human-first UX) */}
          {result && (
            <div id="safelink-result" className="space-y-6 animate-fade-up">
              {/* Primary Risk Banner */}
              <div
                className={`rounded-2xl border p-6 sm:p-8 backdrop-blur-md shadow-2xl relative overflow-hidden ${
                  isDangerous
                    ? "border-red-500/40 bg-[#160b0d]/90 shadow-[0_0_50px_rgba(239,68,68,0.15)]"
                    : isCaution
                    ? "border-amber-500/40 bg-[#16120b]/90 shadow-[0_0_50px_rgba(245,158,11,0.15)]"
                    : "border-emerald-500/40 bg-[#0b1611]/90 shadow-[0_0_50px_rgba(16,185,129,0.15)]"
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/[0.08] pb-6">
                  <div className="flex items-center gap-3.5">
                    <div
                      className={`flex h-12 w-12 items-center justify-center rounded-xl border shrink-0 ${
                        isDangerous
                          ? "bg-red-500/20 border-red-500/40 text-red-400 shadow-[0_0_20px_rgba(239,68,68,0.25)]"
                          : isCaution
                          ? "bg-amber-500/20 border-amber-500/40 text-amber-400 shadow-[0_0_20px_rgba(245,158,11,0.25)]"
                          : "bg-emerald-500/20 border-emerald-500/40 text-emerald-400 shadow-[0_0_20px_rgba(16,185,129,0.25)]"
                      }`}
                    >
                      {isDangerous ? (
                        <ShieldAlert className="h-6 w-6" />
                      ) : isCaution ? (
                        <AlertTriangle className="h-6 w-6" />
                      ) : (
                        <ShieldCheck className="h-6 w-6" />
                      )}
                    </div>

                    <div>
                      <span className="text-[10px] font-mono uppercase tracking-widest text-zinc-400">
                        Analysis Verdict
                      </span>
                      <h2
                        className={`text-2xl sm:text-3xl font-extrabold tracking-tight font-heading ${
                          isDangerous
                            ? "text-red-400"
                            : isCaution
                            ? "text-amber-400"
                            : "text-emerald-400"
                        }`}
                        style={{ fontFamily: "'Space Grotesk', system-ui, sans-serif" }}
                      >
                        {headlineText}
                      </h2>
                    </div>
                  </div>

                  {/* Risk Score Pill */}
                  <div className="flex items-center gap-3 self-start sm:self-auto bg-black/40 border border-white/[0.08] rounded-xl px-4 py-2.5">
                    <div className="text-right">
                      <div className="text-[10px] font-mono uppercase text-zinc-400">Threat Score</div>
                      <div className="text-xl sm:text-2xl font-bold font-mono tracking-tight text-white">
                        {Math.round(riskScore)}{" "}
                        <span className="text-xs text-zinc-500 font-normal">/ 100</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Analyzed Target Display */}
                <div className="mt-4 pt-2">
                  <div className="text-[11px] font-mono text-zinc-400 mb-1">Target Address Inspected:</div>
                  <div className="font-mono text-xs sm:text-sm text-zinc-200 bg-black/50 border border-white/[0.06] rounded-xl p-3 break-all select-all">
                    {analyzedUrl}
                  </div>
                </div>

                {/* Human-First Explanation Sections */}
                <div className="mt-6 grid grid-cols-1 md:grid-cols-2 gap-6">
                  {/* Section 1: Why we flagged it */}
                  <div className="rounded-xl bg-black/30 border border-white/[0.06] p-4 sm:p-5">
                    <h3 className="text-xs font-mono uppercase tracking-wider font-bold text-zinc-300 mb-3 flex items-center gap-2">
                      <span className="h-2 w-2 rounded-full bg-cyan-400" />
                      Why We Flagged It
                    </h3>
                    <ul className="space-y-2 text-xs sm:text-sm text-zinc-300">
                      {result.indicators && result.indicators.length > 0 ? (
                        result.indicators.slice(0, 4).map((ind: Indicator) => (
                          <li key={ind.id} className="flex items-start gap-2">
                            <span className="text-cyan-400 font-bold">•</span>
                            <span>{ind.description || ind.name}</span>
                          </li>
                        ))
                      ) : (
                        <li className="flex items-start gap-2">
                          <span className="text-emerald-400 font-bold">•</span>
                          <span>No malicious signals or suspicious patterns were matched by ScamShield threat checks.</span>
                        </li>
                      )}
                    </ul>
                  </div>

                  {/* Section 2: What the scammer wants */}
                  <div className="rounded-xl bg-black/30 border border-white/[0.06] p-4 sm:p-5">
                    <h3 className="text-xs font-mono uppercase tracking-wider font-bold text-zinc-300 mb-3 flex items-center gap-2">
                      <span className="h-2 w-2 rounded-full bg-violet-400" />
                      What The Scammer Wants
                    </h3>
                    <div className="text-xs sm:text-sm text-zinc-300 leading-relaxed">
                      {isDangerous ? (
                        result.indicators?.find((i) => i.attackerObjective)?.attackerObjective ||
                        "Lure victim into submitting confidential bank credentials, passwords, or executing fraudulent payments on a counterfeit portal."
                      ) : isCaution ? (
                        "Verify sender and organization through an official phone or web portal before continuing."
                      ) : (
                        "No deceptive attack objective detected for this destination domain."
                      )}
                    </div>
                  </div>
                </div>

                {/* Section 3: What you should do */}
                <div className="mt-6 rounded-xl bg-black/40 border border-white/[0.06] p-4 sm:p-5">
                  <h3 className="text-xs font-mono uppercase tracking-wider font-bold text-zinc-300 mb-3 flex items-center gap-2">
                    <span className="h-2 w-2 rounded-full bg-emerald-400" />
                    What You Should Do
                  </h3>
                  <div className="space-y-2 text-xs sm:text-sm text-zinc-300">
                    {isDangerous ? (
                      <ul className="space-y-1.5">
                        <li className="flex items-center gap-2 text-red-300">
                          <span className="font-bold">•</span>
                          <span>Do NOT enter your netbanking password, ATM PIN, or OTP on this site.</span>
                        </li>
                        <li className="flex items-center gap-2 text-red-300">
                          <span className="font-bold">•</span>
                          <span>Do NOT transfer money or approve collect requests.</span>
                        </li>
                        <li className="flex items-center gap-2">
                          <span className="text-zinc-400">•</span>
                          <span>Close the link immediately and delete the communication.</span>
                        </li>
                        <li className="flex items-center gap-2">
                          <span className="text-zinc-400">•</span>
                          <span>Access the organization directly by typing their official website into your browser.</span>
                        </li>
                      </ul>
                    ) : isCaution ? (
                      <ul className="space-y-1.5">
                        <li className="flex items-center gap-2 text-amber-300">
                          <span className="font-bold">•</span>
                          <span>Exercise caution: verify the sender and domain before entering any personal details.</span>
                        </li>
                        <li className="flex items-center gap-2">
                          <span className="text-zinc-400">•</span>
                          <span>Do not submit financial information without verifying the company&apos;s verified contact numbers.</span>
                        </li>
                      </ul>
                    ) : (
                      <div>
                        <p className="text-zinc-300 leading-relaxed">
                          No suspicious indicators were detected by ScamShield&apos;s current checks. This does not guarantee that the destination is completely safe. Always verify the domain name matches the organization you intend to visit.
                        </p>
                      </div>
                    )}
                  </div>
                </div>

                {/* Bottom Action Bar */}
                <div className="mt-8 pt-6 border-t border-white/[0.08] flex flex-col sm:flex-row items-center justify-between gap-4">
                  {/* Primary safe/stay-safe action */}
                  <div>
                    {isSafe ? (
                      <button
                        type="button"
                        id="safelink-continue-btn"
                        onClick={() => setShowContinueModal(true)}
                        className="inline-flex items-center justify-center gap-2 rounded-xl bg-emerald-500 px-6 py-3 text-xs font-mono font-bold text-black hover:bg-emerald-400 shadow-[0_0_25px_rgba(16,185,129,0.3)] transition-all cursor-pointer"
                      >
                        <ExternalLink className="h-4 w-4" />
                        <span>CONTINUE TO DESTINATION</span>
                      </button>
                    ) : (
                      <button
                        type="button"
                        id="safelink-staysafe-btn"
                        onClick={handleReset}
                        className="inline-flex items-center justify-center gap-2 rounded-xl bg-zinc-800 border border-white/[0.1] px-6 py-3 text-xs font-mono font-bold text-white hover:bg-zinc-700 transition-all cursor-pointer"
                      >
                        <Shield className="h-4 w-4 text-cyan-400" />
                        <span>STAY SAFE & CLOSE</span>
                      </button>
                    )}
                  </div>

                  {/* Secondary buttons */}
                  <div className="flex items-center gap-3">
                    <button
                      type="button"
                      id="safelink-details-toggle-btn"
                      onClick={() => setShowDetails(!showDetails)}
                      className="inline-flex items-center gap-1.5 rounded-xl border border-white/[0.08] bg-zinc-900/60 px-4 py-3 text-xs font-mono text-zinc-400 hover:text-white hover:bg-zinc-800 transition-all cursor-pointer"
                    >
                      <Info className="h-3.5 w-3.5" />
                      <span>{showDetails ? "Hide Technical Details" : "View Technical Details"}</span>
                      {showDetails ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
                    </button>

                    <button
                      type="button"
                      id="safelink-reset-btn"
                      onClick={handleReset}
                      className="inline-flex items-center gap-1.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 px-5 py-3 text-xs font-mono font-bold text-cyan-300 hover:bg-cyan-500/20 hover:text-white transition-all cursor-pointer"
                    >
                      <RotateCcw className="h-3.5 w-3.5" />
                      <span>CHECK ANOTHER LINK</span>
                    </button>
                  </div>
                </div>

                {/* Collapsible Technical Details Section */}
                {showDetails && (
                  <div className="mt-6 pt-6 border-t border-white/[0.08] space-y-4 animate-fade-down">
                    <div className="text-xs font-mono uppercase tracking-wider text-zinc-400 flex items-center justify-between">
                      <span>Threat Intelligence Evidence Breakdown</span>
                      <span className="text-xs text-zinc-400">{result.indicators?.length || 0} Indicators Flagged</span>
                    </div>

                    <div className="grid grid-cols-1 gap-2.5">
                      {result.indicators && result.indicators.length > 0 ? (
                        result.indicators.map((ind: Indicator) => (
                          <div
                            key={ind.id}
                            className="rounded-xl border border-white/[0.06] bg-black/40 p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
                          >
                            <div>
                              <div className="flex items-center gap-2">
                                <span className="font-semibold text-zinc-200">{ind.name}</span>
                                <span
                                  className={`tech-label text-[10px] px-2 py-0.5 rounded border font-mono ${
                                    ind.severity === "CRITICAL"
                                      ? "border-red-500/40 bg-red-500/10 text-red-400"
                                      : ind.severity === "HIGH"
                                      ? "border-orange-500/40 bg-orange-500/10 text-orange-400"
                                      : "border-amber-500/40 bg-amber-500/10 text-amber-400"
                                  }`}
                                >
                                  {ind.severity}
                                </span>
                              </div>
                              <p className="text-xs text-zinc-300 mt-1">{ind.whyItMatters || ind.description}</p>
                            </div>
                            <div className="text-xs font-mono text-zinc-400 shrink-0 self-start sm:self-center">
                              Stage: {ind.attackStage || "Detection"}
                            </div>
                          </div>
                        ))
                      ) : (
                        <div className="rounded-xl border border-white/[0.06] bg-black/40 p-4 text-xs text-zinc-400 text-center">
                          No heuristic or brand impersonation indicators detected for this destination.
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Secure Continue Warning Modal (For Phase 6 Navigation) */}
          {showContinueModal && (
            <div
              className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in"
              role="dialog"
              aria-modal="true"
              aria-labelledby="continue-modal-title"
            >
              <div className="rounded-2xl border border-white/[0.12] bg-[#0b0c14] p-6 sm:p-8 max-w-lg w-full shadow-2xl space-y-5 relative">
                <div className="flex items-center gap-3 border-b border-white/[0.08] pb-4">
                  <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 shrink-0">
                    <CheckCircle2 className="h-5 w-5" />
                  </div>
                  <div>
                    <h3 id="continue-modal-title" className="text-base font-bold text-white font-heading">
                      Proceeding to External Destination
                    </h3>
                    <p className="text-xs text-zinc-400 mt-0.5">Automated checks found no known threats</p>
                  </div>
                </div>

                <div className="bg-black/50 border border-white/[0.06] rounded-xl p-3.5 text-xs font-mono text-zinc-300 break-all select-all">
                  {analyzedUrl}
                </div>

                <div className="rounded-xl border border-amber-500/20 bg-amber-500/10 p-3.5 text-xs text-amber-300 flex items-start gap-2.5">
                  <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
                  <p className="leading-relaxed">
                    <strong>Important Security Notice:</strong> Automated threat analysis cannot guarantee 100% safety. Please verify that the address bar matches the intended service before entering any credentials.
                  </p>
                </div>

                <div className="flex items-center justify-end gap-3 pt-2">
                  <button
                    type="button"
                    onClick={() => setShowContinueModal(false)}
                    className="px-4 py-2.5 rounded-xl border border-white/[0.08] bg-zinc-900 text-xs font-mono text-zinc-400 hover:text-white hover:bg-zinc-800 transition-all cursor-pointer"
                  >
                    Cancel
                  </button>

                  <a
                    href={analyzedUrl}
                    target="_blank"
                    rel="noopener noreferrer nofollow"
                    id="safelink-external-link"
                    className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-emerald-500 text-xs font-mono font-bold text-black hover:bg-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.3)] transition-all"
                  >
                    <span>Open Link in New Tab</span>
                    <ExternalLink className="h-3.5 w-3.5" />
                  </a>
                </div>
              </div>
            </div>
          )}

          {/* Quick Back to Message Analyzer Link */}
          <div className="mt-12 text-center">
            <Link
              href="/"
              className="inline-flex items-center gap-2 text-xs font-mono text-zinc-500 hover:text-cyan-400 transition-colors"
            >
              <ArrowRight className="h-3.5 w-3.5 rotate-180" />
              <span>Return to Full Communication Analyzer</span>
            </Link>
          </div>
        </div>
      </main>

      <Footer />
    </div>
  );
}
