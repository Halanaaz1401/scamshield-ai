"use client";

import React, { useState, useRef } from "react";
import { AlertCircle } from "lucide-react";
import Navbar from "@/components/layout/Navbar";
import Hero from "@/components/landing/Hero";
import MessageInput from "@/components/analyzer/MessageInput";
import ScanningState from "@/components/scanning/ScanningState";
import ResultPanel from "@/components/results/ResultPanel";
import FinalCTA from "@/components/landing/FinalCTA";
import Footer from "@/components/layout/Footer";
import { analyzeMessage } from "@/lib/analysisService";
import type { AnalysisResponse } from "@/types/analysis";

export default function Home() {
  const [inputMessage, setInputMessage] = useState<string>("");
  const [sourceType, setSourceType] = useState<string>("message");
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [analysisResult, setAnalysisResult] = useState<AnalysisResponse | null>(null);

  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const analyzerRef = useRef<HTMLDivElement>(null);

  const handleSelectPreset = (presetMessage: string) => {
    setInputMessage(presetMessage);
    setAnalysisResult(null);
    setErrorMessage(null);
    setIsScanning(false);
    const el = document.getElementById("analyzer");
    if (el) {
      el.scrollIntoView({ behavior: "smooth" });
    }
  };

  const handleStartAnalysis = (message: string, source: string = "message") => {
    setInputMessage(message);
    setSourceType(source);
    setAnalysisResult(null);
    setErrorMessage(null);
    setIsScanning(true);
  };

  const handleScanningComplete = async () => {
    try {
      const result = await analyzeMessage(inputMessage, sourceType);
      setAnalysisResult(result);
      setErrorMessage(null);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Threat analysis engine request failed.";
      setErrorMessage(msg);
    } finally {
      setIsScanning(false);
    }
  };

  const handleReset = () => {
    setAnalysisResult(null);
    setErrorMessage(null);
    setIsScanning(false);
    setInputMessage("");
    const el = document.getElementById("analyzer");
    if (el) {
      el.scrollIntoView({ behavior: "smooth" });
    }
  };

  return (
    <div className="min-h-screen bg-[#07080d] text-zinc-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-white">
      {/* Top sticky navigation */}
      <Navbar />

      {/* Main content flow */}
      <main className="flex-1">
        {/* 1. Hero / Landing Section */}
        <Hero onSelectPreset={handleSelectPreset} />

        {/* 2. Primary Analyzer / Scanning / Result Section */}
        <section id="analyzer" ref={analyzerRef} className="py-12 md:py-16 scroll-mt-20">
          <div className="mx-auto max-w-5xl px-4 sm:px-6 lg:px-8">
            
            {errorMessage && (
              <div className="mb-6 rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-xs text-red-300 flex items-center justify-between shadow-lg">
                <div className="flex items-center gap-2.5">
                  <AlertCircle className="h-4 w-4 text-red-400 shrink-0" />
                  <span>{errorMessage}</span>
                </div>
                <button
                  type="button"
                  onClick={() => setErrorMessage(null)}
                  className="text-xs font-mono underline hover:text-white ml-3 shrink-0"
                >
                  Dismiss
                </button>
              </div>
            )}

            {/* Conditional Display: Scanning State vs Result Panel vs Message Input */}
            {isScanning ? (
              <ScanningState
                onComplete={handleScanningComplete}
              />
            ) : analysisResult ? (
              <ResultPanel
                result={analysisResult}
                onReset={handleReset}
              />
            ) : (
              <MessageInput
                initialValue={inputMessage}
                onAnalyze={handleStartAnalysis}
                isLoading={isScanning}
              />
            )}

          </div>
        </section>

        {/* 3. Final Editorial CTA Section */}
        <FinalCTA />
      </main>

      {/* 4. Dark Cybersecurity Footer */}
      <Footer />
    </div>
  );
}
