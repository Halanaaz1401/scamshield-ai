"use client";

import React, { useState, useEffect, useRef } from "react";
import {
  ShieldAlert, RotateCcw, Clipboard, Sparkles,
  MessageSquare, ArrowRight, AlertCircle, Shield,
} from "lucide-react";
import { PRESET_SAMPLES, type PresetSample } from "@/lib/mockData";

interface MessageInputProps {
  initialValue?: string;
  onAnalyze: (message: string, sourceType?: string) => void;
  isLoading: boolean;
}

const SOURCE_OPTIONS = [
  { id: "message", label: "WhatsApp / Chat" },
  { id: "sms",     label: "SMS Alert" },
  { id: "email",   label: "Email" },
  { id: "url",     label: "Suspicious URL" },
];

export default function MessageInput({ initialValue = "", onAnalyze, isLoading }: MessageInputProps) {
  const [message, setMessage]     = useState(initialValue);
  const [sourceType, setSourceType] = useState<string>("message");
  const [errorMsg, setErrorMsg]   = useState<string | null>(null);
  const [focused, setFocused]     = useState(false);
  const textareaRef               = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    setMessage(initialValue);
    if (initialValue) {
      setErrorMsg(null);
    }
  }, [initialValue]);

  useEffect(() => {
    if (textareaRef.current && textareaRef.current.value && !message) {
      setMessage(textareaRef.current.value);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const charCount   = message.length;
  const isOverLimit = charCount > 4000;
  const isEmpty     = message.trim().length === 0;
  const charPct     = Math.min(charCount / 4000, 1);

  // Char counter color
  const counterColor = isOverLimit
    ? "text-red-400 font-bold"
    : charCount > 3600
    ? "text-amber-400"
    : "text-zinc-500";

  const handlePasteClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) { setMessage(text); setErrorMsg(null); }
    } catch { /* clipboard access not granted */ }
  };

  const handleClear = () => { setMessage(""); setErrorMsg(null); };

  const handleSelectPreset = (preset: PresetSample) => {
    setMessage(preset.message);
    setErrorMsg(null);
    textareaRef.current?.focus();
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (isEmpty)     { setErrorMsg("Please enter or paste a suspicious message to analyze."); return; }
    if (isOverLimit) { setErrorMsg(`Message exceeds the 4,000 character limit (${charCount.toLocaleString()} entered).`); return; }
    setErrorMsg(null);
    onAnalyze(message.trim(), sourceType);
  };

  return (
    <div id="analyzer" className="relative scroll-mt-20 animate-fade-up">
      {/* Card */}
      <div
        className={`rounded-2xl border bg-[#0b0c14] backdrop-blur-md shadow-2xl relative overflow-hidden transition-all duration-300 ${
          focused
            ? "border-indigo-500/40 shadow-[0_0_40px_rgba(99,102,241,0.1)]"
            : "border-white/[0.08]"
        }`}
      >
        {/* Top edge glow — brightens on focus */}
        <div
          className={`absolute top-0 left-1/4 right-1/4 h-px transition-opacity duration-300 pointer-events-none ${
            focused ? "opacity-100" : "opacity-40"
          }`}
          style={{ background: "linear-gradient(90deg, transparent, rgba(99,102,241,0.7), transparent)" }}
          aria-hidden="true"
        />

        <div className="p-6 sm:p-8">
          {/* Card header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/[0.06] pb-5">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-indigo-500/10 border border-indigo-500/25 text-indigo-400">
                <MessageSquare className="h-4 w-4" aria-hidden="true" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-sm font-bold text-white" style={{ fontFamily: "'Space Grotesk', system-ui, sans-serif" }}>
                    Threat Vector Inspection Console
                  </h2>
                  <span className="tech-label bg-indigo-500/10 text-indigo-400 px-2 py-0.5 rounded border border-indigo-500/20">
                    Ready
                  </span>
                </div>
                <p className="text-[11px] text-zinc-500 mt-0.5">
                  Paste suspicious communications to unmask attacker intent and reconstruct the kill chain
                </p>
              </div>
            </div>

            {/* Source selector */}
            <div
              className="flex items-center gap-0.5 bg-[#060710] p-1 rounded-xl border border-white/[0.05] text-xs self-start sm:self-auto"
              role="group"
              aria-label="Message source type"
            >
              {SOURCE_OPTIONS.map((opt) => (
                <button
                  key={opt.id}
                  type="button"
                  id={`source-${opt.id}`}
                  onClick={() => setSourceType(opt.id)}
                  aria-pressed={sourceType === opt.id}
                  className={`rounded-lg px-2.5 py-1.5 font-mono text-[10px] tracking-wide transition-all duration-150 ${
                    sourceType === opt.id
                      ? "bg-indigo-600 text-white font-semibold shadow-sm"
                      : "text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800/50"
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>

          {/* Preset pills */}
          <div className="pt-4 pb-3">
            <div className="flex items-center justify-between mb-2.5 text-[11px] font-mono text-zinc-500">
              <div className="flex items-center gap-1.5">
                <Sparkles className="h-3 w-3 text-indigo-400" aria-hidden="true" />
                Load Realistic Threat Vector:
              </div>
              <span className="text-[10px] text-zinc-600 hidden sm:inline">Click preset to load</span>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {PRESET_SAMPLES.map((sample) => (
                <button
                  key={sample.id}
                  type="button"
                  id={`preset-${sample.id}`}
                  onClick={() => handleSelectPreset(sample)}
                  className="inline-flex items-center gap-2 rounded-lg border border-white/[0.07] bg-zinc-900/50 px-2.5 py-1.5 text-[11px] text-zinc-400 hover:border-indigo-500/35 hover:bg-zinc-800/80 hover:text-zinc-100 transition-all duration-150 cursor-pointer"
                >
                  <span className="h-1.5 w-1.5 rounded-full bg-indigo-400/70 shrink-0" aria-hidden="true" />
                  <span className="font-medium text-zinc-300">{sample.title}</span>
                  <span className="text-[9px] font-mono text-zinc-500 border-l border-white/[0.07] pl-2">{sample.tag}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="mt-2 space-y-3">
            <div className="relative">
              <textarea
                ref={textareaRef}
                id="message-input"
                value={message}
                onChange={(e) => { setMessage(e.target.value); if (errorMsg) setErrorMsg(null); }}
                onInput={(e) => { setMessage((e.target as HTMLTextAreaElement).value); if (errorMsg) setErrorMsg(null); }}
                onFocus={() => setFocused(true)}
                onBlur={() => setFocused(false)}
                placeholder="Paste suspicious SMS, WhatsApp message, email excerpt, or URL here..."
                rows={6}
                disabled={isLoading}
                aria-label="Message to analyze"
                aria-invalid={isOverLimit}
                aria-describedby={errorMsg ? "input-error" : undefined}
                className={`w-full rounded-xl border bg-[#06070d] p-4 pb-10 text-sm text-zinc-100 placeholder-zinc-600 focus:outline-none transition-all duration-200 resize-y min-h-[160px] font-mono leading-relaxed ${
                  isOverLimit
                    ? "border-red-500/50 focus:border-red-500 focus:shadow-[0_0_20px_rgba(239,68,68,0.12)]"
                    : "border-white/[0.08] focus:border-indigo-500/50 focus:shadow-[0_0_20px_rgba(99,102,241,0.12)]"
                }`}
              />

              {/* Char progress bar at bottom of textarea */}
              <div className="absolute bottom-0 left-0 right-0 h-[2px] rounded-b-xl overflow-hidden pointer-events-none">
                <div
                  className={`h-full transition-all duration-300 ${
                    isOverLimit ? "bg-red-500" : charCount > 3600 ? "bg-amber-500" : "bg-indigo-500/50"
                  }`}
                  style={{ width: `${charPct * 100}%` }}
                  aria-hidden="true"
                />
              </div>

              {/* Quick action buttons */}
              <div className="absolute right-3 bottom-3.5 flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={handlePasteClipboard}
                  title="Paste from clipboard"
                  className="inline-flex items-center gap-1 rounded-lg border border-white/[0.07] bg-zinc-900/95 px-2 py-1 text-[10px] font-mono text-zinc-400 hover:bg-zinc-800 hover:text-white transition-all duration-150"
                >
                  <Clipboard className="h-2.5 w-2.5" aria-hidden="true" />
                  Paste
                </button>
                {message.length > 0 && (
                  <button
                    type="button"
                    onClick={handleClear}
                    title="Clear input"
                    className="inline-flex items-center gap-1 rounded-lg border border-white/[0.07] bg-zinc-900/95 px-2 py-1 text-[10px] font-mono text-zinc-500 hover:bg-zinc-800 hover:text-zinc-200 transition-all duration-150"
                  >
                    <RotateCcw className="h-2.5 w-2.5" aria-hidden="true" />
                    Clear
                  </button>
                )}
              </div>
            </div>

            {/* Validation error */}
            {errorMsg && (
              <div
                id="input-error"
                role="alert"
                className="flex items-center gap-2 rounded-xl border border-red-500/25 bg-red-500/8 p-3 text-[11px] text-red-300"
              >
                <AlertCircle className="h-3.5 w-3.5 shrink-0 text-red-400" aria-hidden="true" />
                {errorMsg}
              </div>
            )}

            {/* Bottom bar */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pt-1">
              <div className="flex items-center gap-4 text-[11px] font-mono text-zinc-500">
                <span className={counterColor} aria-live="polite">
                  {charCount.toLocaleString()} / 4,000
                </span>
                <span className="hidden sm:inline-flex items-center gap-1.5 text-emerald-500/80">
                  <Shield className="h-2.5 w-2.5" aria-hidden="true" />
                  Zero-Storage • Memory-Only
                </span>
              </div>

              <button
                type="submit"
                id="analyze-submit-btn"
                disabled={isLoading || isEmpty || isOverLimit}
                className={`inline-flex items-center justify-center gap-2 rounded-xl px-7 py-3 text-[11px] font-bold font-mono tracking-widest uppercase transition-all duration-150 ${
                  isLoading || isEmpty || isOverLimit
                    ? "bg-zinc-800/80 text-zinc-600 cursor-not-allowed border border-white/[0.04]"
                    : "btn-primary cursor-pointer"
                }`}
                aria-label="Run threat analysis"
              >
                <ShieldAlert className="h-4 w-4" aria-hidden="true" />
                Inspect Communication
                <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
