"use client";

import React, { useEffect, useRef, useState } from "react";
import {
  ShieldAlert, ShieldCheck, AlertTriangle, RotateCcw,
  CheckCircle2, Copy, Check, Target, Terminal, Activity,
  XCircle, ChevronDown, ChevronUp, FileSearch, AlertCircle,
  Zap,
} from "lucide-react";
import type { AnalysisResponse, Indicator } from "@/types/analysis";
import ScamDNAVisual from "@/components/scam-dna/ScamDNAVisual";

interface ResultPanelProps {
  result: AnalysisResponse;
  onReset: () => void;
}

// Plain-language translation mapping for technical indicators
interface PlainLanguageSignal {
  friendlyTitle: string;
  friendlyExplanation: string;
  friendlyStage: string;
}

const SIGNAL_TRANSLATIONS: Record<string, PlainLanguageSignal> = {
  IND_URL_SUSPICIOUS_TLD: {
    friendlyTitle: "Suspicious Website Link",
    friendlyExplanation:
      "This website address uses an unusual domain extension frequently abused for scam pages, rather than an official institutional domain.",
    friendlyStage: "Step 2 — Suspicious Destination",
  },
  IND_URL_BRAND_IMPERSONATION: {
    friendlyTitle: "Fake Bank / Brand Website",
    friendlyExplanation:
      "The link imitates an official bank or brand name in its address to deceive you into believing it is genuine.",
    friendlyStage: "Step 2 — Pretends to Be Trusted",
  },
  IND_URL_DECEPTIVE_PATH: {
    friendlyTitle: "Your Login Details May Be Stolen",
    friendlyExplanation:
      "The link leads to a login or verification page that may be designed to collect your netbanking credentials, passwords, or PIN.",
    friendlyStage: "Step 3 — Tries to Steal Information",
  },
  IND_URL_IP_HOST: {
    friendlyTitle: "Numeric Address Instead of Official Website",
    friendlyExplanation:
      "Uses a raw numerical IP address instead of an official registered domain to avoid security verification.",
    friendlyStage: "Step 2 — Suspicious Destination",
  },
  IND_URL_SHORTENER: {
    friendlyTitle: "Hidden Web Address (Shortened Link)",
    friendlyExplanation:
      "Uses a link-shortening service to conceal where the link really leads before you click it.",
    friendlyStage: "Step 1 — Inbound Lure",
  },
  IND_URL_HOMOGLYPH: {
    friendlyTitle: "Look-Alike Deceptive Domain",
    friendlyExplanation:
      "Uses look-alike characters from other alphabets to visually trick you into seeing an official website address.",
    friendlyStage: "Step 2 — Pretends to Be Trusted",
  },
  IND_URL_UNSAFE_SCHEME: {
    friendlyTitle: "Dangerous Script or Protocol Scheme",
    friendlyExplanation:
      "Uses a dangerous non-web protocol (like javascript: or data:) that can execute malicious scripts directly in your browser.",
    friendlyStage: "Step 3 — Script Execution Vector",
  },
  IND_BRAND_DOMAIN_MISMATCH: {
    friendlyTitle: "Website Does Not Match Claimed Organization",
    friendlyExplanation:
      "The communication claims to represent a recognized company or government service, but the link points to a completely different, unofficial website.",
    friendlyStage: "Step 2 — Deceptive Link Target",
  },
  IND_THREAT_INTEL_MALICIOUS: {
    friendlyTitle: "Verified Malicious Threat in Security Databases",
    friendlyExplanation:
      "Global cybersecurity intelligence databases confirm that this link is an active phishing, malware, or fraud website.",
    friendlyStage: "Step 3 — Confirmed Dangerous Link",
  },
  IND_URL_UNVERIFIED_DESTINATION: {
    friendlyTitle: "Unverified Website Destination",
    friendlyExplanation:
      "This website has no verified institutional record. Absence from threat lists does NOT mean that an unknown link is safe.",
    friendlyStage: "Step 2 — Unverified Destination",
  },
  IND_URL_PAYMENT_PATH: {
    friendlyTitle: "Urgent Payment or Financial Action Link",
    friendlyExplanation:
      "The link directly prompts you to make a payment, claim a reward, or process a refund through an unofficial portal.",
    friendlyStage: "Step 3 — Tries to Extract Funds",
  },
  IND_URL_SUBDOMAIN_DECEPTION: {
    friendlyTitle: "Brand Name Disguised in Subdomain",
    friendlyExplanation:
      "The web address embeds a trusted brand name inside a subdomain to trick you, while sending you to an unrelated server.",
    friendlyStage: "Step 2 — Disguised Web Address",
  },
  IND_URL_EXCESSIVE_SUBDOMAINS: {
    friendlyTitle: "Deceptive Long Address Stacking",
    friendlyExplanation:
      "Nests multiple subdomains to push the real website name off-screen on mobile devices.",
    friendlyStage: "Step 2 — Address Cloaking",
  },
  IND_URL_INSECURE_HTTP: {
    friendlyTitle: "Insecure Plaintext Link (No Encryption)",
    friendlyExplanation:
      "The link asks for sensitive actions over unencrypted HTTP, which legitimate banks and institutions never do.",
    friendlyStage: "Step 3 — Insecure Connection",
  },
  IND_URGENCY_TACTIC: {
    friendlyTitle: "Scammer Is Creating Panic",
    friendlyExplanation:
      "Words like 'immediately', 'urgent', or 'today' create pressure so you act before checking whether the message is genuine.",
    friendlyStage: "Step 1 — Creates Fear or Urgency",
  },
  IND_THREAT_CONSEQUENCE: {
    friendlyTitle: "Threatening Account Block or Disconnection",
    friendlyExplanation:
      "Threatens to freeze your bank account, block your card, or stop a service to scare you into complying quickly.",
    friendlyStage: "Step 1 — Creates Fear or Urgency",
  },
  IND_IMPERSONATION_BANK: {
    friendlyTitle: "Pretends to Be Your Bank",
    friendlyExplanation:
      "The message uses the name of a recognized bank to appear legitimate and gain your trust.",
    friendlyStage: "Step 2 — Pretends to Be Trusted",
  },
  IND_IMPERSONATION_GOVT: {
    friendlyTitle: "Pretends to Be Police or Government Authority",
    friendlyExplanation:
      "Claims to be Police, CBI, Court, or Income Tax Department to intimidate you into compliance.",
    friendlyStage: "Step 2 — Pretends to Be Trusted",
  },
  IND_ELECTRICITY_DISCONNECT: {
    friendlyTitle: "Electricity Disconnection Threat",
    friendlyExplanation:
      "Claims your power supply will be disconnected tonight unless you call an unofficial phone number or make an immediate payment.",
    friendlyStage: "Step 1 — Creates Fear or Urgency",
  },
  IND_COURIER_PARCEL: {
    friendlyTitle: "Fake Courier / Customs Warning",
    friendlyExplanation:
      "Claims an illegal parcel or contraband was intercepted in your name to frighten you into cooperating with fake officials.",
    friendlyStage: "Step 1 — Creates Fear or Urgency",
  },
  IND_REVERSE_UPI: {
    friendlyTitle: "UPI PIN Fraud (Reverse Charge)",
    friendlyExplanation:
      "Tells you to enter your UPI PIN to 'receive' money; remember that entering your PIN ALWAYS debits money from your account.",
    friendlyStage: "Step 3 — Tries to Steal Money",
  },
  IND_OTP_SOLICIT: {
    friendlyTitle: "Attempt to Steal One-Time Password",
    friendlyExplanation:
      "Asks you to share your OTP, which legitimate banks, government portals, and payment apps never ask you to disclose.",
    friendlyStage: "Step 3 — Tries to Steal Information",
  },
  IND_CUSTOMER_SUPPORT: {
    friendlyTitle: "Fake Customer Support Number",
    friendlyExplanation:
      "Provides an unverified personal mobile phone number instead of the company's verified customer support channel.",
    friendlyStage: "Step 2 — Pretends to Be Trusted",
  },
  IND_MALICIOUS_APK: {
    friendlyTitle: "Dangerous App Download (.apk)",
    friendlyExplanation:
      "Instructs you to download an Android app file directly, which can steal your SMS OTPs and control your phone.",
    friendlyStage: "Step 3 — Malicious App Download",
  },
  IND_LOTTERY_REWARD: {
    friendlyTitle: "Fake Lottery or Prize Offer",
    friendlyExplanation:
      "Promises unexpected cash rewards or prizes to lure you into paying processing fees or sharing your banking details.",
    friendlyStage: "Step 1 — Attractive Prize Bait",
  },
  IND_JOB_TASK: {
    friendlyTitle: "Fake Part-Time Job Offer",
    friendlyExplanation:
      "Offers high daily earnings for simple tasks like rating apps, designed to trick you into depositing your own money later.",
    friendlyStage: "Step 1 — Attractive Job Bait",
  },
  IND_SIM_BLOCK: {
    friendlyTitle: "SIM Card Block Threat",
    friendlyExplanation:
      "Claims your SIM card will be deactivated unless you call an unknown number or submit KYC documents.",
    friendlyStage: "Step 1 — Creates Fear or Urgency",
  },
  IND_SUSPICIOUS_URL: {
    friendlyTitle: "Suspicious Website Link",
    friendlyExplanation:
      "The message directs to an unverified web address that does not match the official domain of the organization.",
    friendlyStage: "Step 2 — Suspicious Destination",
  },
};

const REQUESTED_ACTION_LABELS: Record<string, string> = {
  CLICK_LINK: "Click on an Unverified Web Link",
  CALL_NUMBER: "Call an Unknown Phone Number",
  PROVIDE_OTP: "Share Your Private OTP / Verification Code",
  MAKE_PAYMENT: "Send Money or Enter UPI PIN",
  INSTALL_APP: "Download & Install an Unverified App (.apk)",
  SHARE_CREDENTIALS: "Enter NetBanking Passwords or Card Details",
  VERIFY_IDENTITY: "Submit Personal Identity / KYC Details",
  NO_ACTION: "No Direct Action Demanded",
};

const TACTIC_LABELS: Record<string, string> = {
  URGENCY_COERCION: "Artificial Urgency & Panic",
  AUTHORITY_IMPERSONATION: "Impersonating an Official Authority or Brand",
  FEAR_OF_PENALTY: "Threat of Legal Action or Penalties",
  FEAR_OF_ACCOUNT_SUSPENSION: "Threat to Block Bank Account / Card",
  FEAR_OF_SERVICE_DISCONNECTION: "Threat to Cut Off Electricity / Power",
  FEAR_OF_POLICE_INVOLVEMENT: "Threat of Police or CBI Arrest",
  GREED_LURE: "Unrealistic Cash Prize, Refund, or Subsidy Lure",
  FALSE_TRUST: "Building False Trust / Pretexting",
  REVERSE_PAYMENT_TRICK: "Misleading UPI PIN / Collect Request",
  MALICIOUS_APP_LURE: "Spyware / Dangerous .apk Download",
  UNVERIFIED_SOLICITATION: "Unsolicited Cold Solicitation",
};

function translateIndicator(ind: Indicator): PlainLanguageSignal {
  const match = SIGNAL_TRANSLATIONS[ind.id];
  if (match) return match;

  const lowerName = ind.name.toLowerCase();
  let friendlyTitle = ind.name;
  let friendlyStage = ind.attackStage || "Suspicious Signal";

  if (lowerName.includes("url") || lowerName.includes("domain") || lowerName.includes("tld")) {
    friendlyTitle = "Suspicious Website Link";
    friendlyStage = "Step 2 — Suspicious Destination";
  } else if (lowerName.includes("urgency") || lowerName.includes("deadline")) {
    friendlyTitle = "Scammer Is Creating Panic";
    friendlyStage = "Step 1 — Creates Fear or Urgency";
  } else if (lowerName.includes("impersonat") || lowerName.includes("bank")) {
    friendlyTitle = "Pretends to Be a Trusted Organization";
    friendlyStage = "Step 2 — Pretends to Be Trusted";
  } else if (lowerName.includes("otp") || lowerName.includes("credential")) {
    friendlyTitle = "Your Login Details May Be Stolen";
    friendlyStage = "Step 3 — Tries to Steal Information";
  }

  return {
    friendlyTitle,
    friendlyExplanation: ind.description,
    friendlyStage,
  };
}

function getRiskStyles(level: string) {
  switch (level) {
    case "CRITICAL":
      return {
        border: "border-red-500/50",
        bg: "bg-red-950/20",
        text: "text-red-400",
        badge: "bg-red-500/15 text-red-300 border-red-500/40",
        glow: "shadow-[0_0_30px_rgba(239,68,68,0.15)]",
        bar: "from-red-600 via-orange-500 to-red-400",
        scanline: "rgba(239, 68, 68, 0.4)",
      };
    case "HIGH":
      return {
        border: "border-orange-500/50",
        bg: "bg-orange-950/20",
        text: "text-orange-400",
        badge: "bg-orange-500/15 text-orange-300 border-orange-500/40",
        glow: "shadow-[0_0_30px_rgba(249,115,22,0.15)]",
        bar: "from-orange-600 via-amber-500 to-orange-400",
        scanline: "rgba(249, 115, 22, 0.4)",
      };
    case "MEDIUM":
    case "SUSPICIOUS":
      return {
        border: "border-amber-500/50",
        bg: "bg-amber-950/20",
        text: "text-amber-400",
        badge: "bg-amber-500/15 text-amber-300 border-amber-500/40",
        glow: "shadow-[0_0_30px_rgba(245,158,11,0.15)]",
        bar: "from-amber-600 via-yellow-500 to-amber-400",
        scanline: "rgba(245, 158, 11, 0.4)",
      };
    default:
      return {
        border: "border-emerald-500/40",
        bg: "bg-emerald-950/15",
        text: "text-emerald-400",
        badge: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
        glow: "shadow-[0_0_25px_rgba(16,185,129,0.1)]",
        bar: "from-emerald-600 to-teal-400",
        scanline: "rgba(16, 185, 129, 0.3)",
      };
  }
}

function getHeadlineForVerdict(
  category?: string,
  riskLevel?: string,
  indicators?: Indicator[],
  verdict?: string
): string {
  if (verdict === "KNOWN_MALICIOUS") {
    return "Verified Dangerous Link Detected";
  }

  const isBenign =
    (riskLevel === "LOW" || riskLevel === "SAFE" || verdict === "BENIGN") &&
    (!indicators || indicators.length === 0 || category === "BENIGN");

  if (isBenign) {
    return "Message Appears Safe";
  }

  const hasElectricity = indicators?.some((i) => i.id === "IND_ELECTRICITY_DISCONNECT");
  const hasCourier = indicators?.some((i) => i.id === "IND_COURIER_PARCEL");
  const hasBank = indicators?.some((i) => i.id === "IND_IMPERSONATION_BANK" || i.id === "IND_URL_BRAND_IMPERSONATION");
  const hasUpi = indicators?.some((i) => i.id === "IND_REVERSE_UPI");
  const hasApk = indicators?.some((i) => i.id === "IND_MALICIOUS_APK");
  const hasBrandMismatch = indicators?.some((i) => i.id === "IND_BRAND_DOMAIN_MISMATCH");

  if (hasElectricity) return "Electricity Disconnection Scam";
  if (hasCourier) return "Fake Courier / Customs Scam";
  if (hasUpi) return "UPI Payment / Cashback Fraud";
  if (hasApk) return "Dangerous App (.apk) Download Detected";
  if (hasBrandMismatch) return "Fake Organization Website (Brand Impersonation)";
  if (hasBank) return "Fake Bank / KYC Verification Lure";

  if (riskLevel === "CRITICAL") return "Dangerous Phishing Lure Detected";
  if (riskLevel === "HIGH") return "High-Risk Fraud Communication";
  if (riskLevel === "MEDIUM" || verdict === "UNKNOWN_UNVERIFIED") return "Caution: Suspicious Communication";

  return "Suspicious Communication Detected";
}

function AnimatedScore({ target, className }: { target: number; className?: string }) {
  const [displayed, setDisplayed] = useState(0);
  const raf = useRef<number | null>(null);

  useEffect(() => {
    const start = performance.now();
    const duration = 1000;
    const animate = (now: number) => {
      const elapsed = now - start;
      const pct = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - pct, 3);
      setDisplayed(Math.round(target * eased));
      if (pct < 1) raf.current = requestAnimationFrame(animate);
    };
    raf.current = requestAnimationFrame(animate);
    return () => {
      if (raf.current) cancelAnimationFrame(raf.current);
    };
  }, [target]);

  return <span className={className}>{displayed}</span>;
}

function buildSimpleSummary(result: AnalysisResponse): string {
  if (result.aiIntent?.explanation) {
    return result.aiIntent.explanation;
  }

  const isBenign =
    (result.riskLevel === "LOW" || result.riskLevel === "SAFE" || result.verdict === "BENIGN") &&
    (result.category === "BENIGN" || !result.indicators || result.indicators.length === 0);

  if (isBenign) {
    return "This message does not contain significant scam indicators. It appears consistent with standard legitimate communication.";
  }

  if (result.reasoning && !result.reasoning.includes("Deterministic engine flagged")) {
    return result.reasoning;
  }

  const count = result.indicators?.length || 0;
  return `This message contains ${count} suspicious security signal${count === 1 ? "" : "s"} commonly associated with online fraud.`;
}

export default function ResultPanel({ result, onReset }: ResultPanelProps) {
  const [copiedAction, setCopiedAction] = useState<string | null>(null);
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);
  const s = getRiskStyles(result.riskLevel);

  const isTrulyBenign =
    (result.riskLevel === "LOW" || result.riskLevel === "SAFE" || result.verdict === "BENIGN") &&
    (result.category === "BENIGN" || !result.indicators || result.indicators.length === 0);

  const headline = getHeadlineForVerdict(result.category, result.riskLevel, result.indicators, result.verdict);
  const simpleSummary = buildSimpleSummary(result);

  const handleCopyAction = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedAction(text);
    setTimeout(() => setCopiedAction(null), 2000);
  };

  const severityColors: Record<string, string> = {
    CRITICAL: "bg-red-500/15 text-red-300 border border-red-500/30",
    HIGH: "bg-orange-500/15 text-orange-300 border border-orange-500/30",
    MEDIUM: "bg-amber-500/15 text-amber-300 border border-amber-500/30",
    LOW: "bg-zinc-800 text-zinc-300 border border-zinc-700",
  };

  const isHighThreat = result.riskLevel === "CRITICAL" || result.riskLevel === "HIGH";

  const doNotActions =
    result.doNotActions && result.doNotActions.length > 0
      ? result.doNotActions
      : [
          "Do NOT click any link or web address in the message.",
          "Do NOT share your OTP, UPI PIN, ATM PIN, or NetBanking password.",
          "Do NOT transfer money or pay advance fees to 'unfreeze' your account or electricity.",
          "Do NOT download any .apk file or install remote support apps (AnyDesk, TeamViewer).",
        ];

  const doActions =
    result.doActions && result.doActions.length > 0
      ? result.doActions
      : [
          result.aiIntent?.recommendedAction || result.recommendedAction,
          ...(result.recommendedActions ? result.recommendedActions.slice(1) : []),
          "If in doubt, open your bank or provider's official app yourself to verify.",
          "Report suspicious scam messages to the National Cybercrime Portal (cybercrime.gov.in or call 1930).",
        ].filter(Boolean) as string[];

  // Attacker intent & requested action strings from canonical analysis
  const attackerIntentText =
    result.attackerIntent ||
    result.aiIntent?.attackerIntent ||
    (isTrulyBenign
      ? "No fraudulent or manipulative intent detected."
      : "Suspicious communication pattern requiring user verification.");

  const requestedActionCode = result.aiIntent?.requestedAction || "NO_ACTION";
  const requestedActionDisplay =
    result.demandedAction ||
    REQUESTED_ACTION_LABELS[requestedActionCode] ||
    requestedActionCode;

  const pressureLevelDisplay =
    result.pressureLevel && result.pressureLevel !== "NONE"
      ? `${result.pressureLevel} Pressure`
      : result.aiIntent?.urgencyLevel && result.aiIntent.urgencyLevel !== "NONE"
      ? `${result.aiIntent.urgencyLevel} Urgency`
      : "Standard / No Pressure";

  const manipulationTacticDisplay =
    result.manipulationTactic ||
    (result.aiIntent?.manipulationTactics && result.aiIntent.manipulationTactics.length > 0
      ? TACTIC_LABELS[result.aiIntent.manipulationTactics[0]] || result.aiIntent.manipulationTactics[0]
      : isTrulyBenign
      ? "None"
      : "None detected");

  const potentialConsequenceText =
    (result.potentialImpact && result.potentialImpact.length > 0
      ? result.potentialImpact.join(". ")
      : null) ||
    result.aiIntent?.potentialConsequence ||
    (isTrulyBenign
      ? "Standard legitimate communication with no immediate threat identified."
      : "Unauthorized actions, credential disclosure, or financial loss.");

  return (
    <div className="space-y-6 animate-fade-up" role="region" aria-label="Threat analysis result">

      {/* ===== TOP RESULT BANNER: VERDICT & SUMMARY (User First Impression) ===== */}
      <div className={`rounded-2xl border ${s.border} ${s.bg} ${s.glow} relative overflow-hidden`}>
        <div
          className="absolute inset-x-0 top-0 h-[2px] pointer-events-none"
          style={{ background: `linear-gradient(90deg, transparent, ${s.scanline}, transparent)` }}
          aria-hidden="true"
        />

        <div className="p-6 sm:p-7">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
            <div className="flex items-start gap-4 flex-1 min-w-0">
              <div
                className={`flex h-14 w-14 shrink-0 items-center justify-center rounded-xl border ${s.border} ${s.bg} ${s.text}`}
              >
                {isTrulyBenign ? (
                  <ShieldCheck className="h-7 w-7 text-emerald-400" aria-hidden="true" />
                ) : (
                  <ShieldAlert className="h-7 w-7" aria-hidden="true" />
                )}
              </div>

              <div className="min-w-0 flex-1">
                {/* Category & Status Badges */}
                <div className="flex flex-wrap items-center gap-2 mb-2">
                  <span
                    className={`rounded-full border px-3 py-1 text-xs font-mono font-bold tracking-wider uppercase ${s.badge}`}
                  >
                    {result.riskLevel} RISK
                  </span>
                  <span className="rounded-full border border-white/[0.1] bg-zinc-900/90 px-3 py-1 text-xs font-mono font-semibold text-zinc-200">
                    {result.category?.replace(/_/g, " ") || "GENERAL"}
                  </span>
                  {result.confidence && (
                    <span className="rounded-full border border-indigo-500/35 bg-indigo-500/15 px-3 py-1 text-xs font-mono font-semibold text-indigo-300">
                      CONFIDENCE: {result.confidence}
                    </span>
                  )}
                  {result.aiIntent && !result.aiIntent.aiAvailable && (
                    <span className="rounded-full border border-zinc-700 bg-zinc-800/80 px-2.5 py-0.5 text-[11px] font-mono text-zinc-400">
                      Rule-Engine Fallback
                    </span>
                  )}
                </div>

                {/* Primary Headline */}
                <h2 className="text-2xl sm:text-3xl font-bold tracking-tight text-white leading-tight font-heading">
                  {headline}
                </h2>

                {/* Plain-language sub-summary */}
                <p className="text-base text-zinc-300 mt-2 leading-relaxed font-sans">
                  {simpleSummary}
                </p>

                {/* Verification metadata */}
                <div className="flex items-center gap-2 text-xs text-zinc-400 mt-2.5 font-mono">
                  <span className="h-2 w-2 rounded-full bg-emerald-400" aria-hidden="true" />
                  <span>Verified: {new Date(result.timestamp).toLocaleTimeString()}</span>
                  <span className="text-zinc-600">·</span>
                  <span>ID: {result.analysisId?.slice(-8) || "LIVE"}</span>
                </div>
              </div>
            </div>

            {/* Compact Threat Rating Pill on Right */}
            <div className="flex flex-col items-start md:items-end shrink-0 border-t md:border-t-0 md:border-l border-white/[0.08] pt-3 md:pt-0 md:pl-5">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-zinc-400 uppercase tracking-wider">Rating:</span>
                <span className={`text-lg font-mono font-bold ${s.text}`}>
                  {result.riskLevel}
                </span>
              </div>
              <div className="text-xs font-mono text-zinc-500 mt-0.5">
                Score: {result.riskScore} / 100
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ===== 1. WHAT IS THIS TRYING TO MAKE YOU DO? ===== */}
      <div className="rounded-2xl border border-orange-500/30 bg-[#0d0c14] p-5 sm:p-6 shadow-lg">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-white/[0.08] pb-3 mb-4">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-orange-500/15 border border-orange-500/30 text-orange-400">
              <Target className="h-4 w-4" aria-hidden="true" />
            </div>
            <h3 className="text-lg font-bold text-white font-heading">
              1. What is this trying to make you do?
            </h3>
          </div>
          <span className="text-xs font-mono text-orange-300 bg-orange-500/10 border border-orange-500/25 px-2.5 py-1 rounded-full self-start sm:self-auto">
            Scammer Kya Karwana Chahta Hai?
          </span>
        </div>

        {/* Attacker Goal */}
        <p className="text-base text-zinc-200 leading-relaxed font-sans mb-4">
          {attackerIntentText}
        </p>

        {/* Structured Intent Badges (Demanded Action + Tactics + Urgency) */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 pt-1">
          {/* Action Demanded */}
          <div className="rounded-xl border border-white/[0.08] bg-zinc-950/80 p-3.5 space-y-1">
            <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-500 block">
              Demanded Action
            </span>
            <span className="text-sm font-semibold text-orange-300 font-sans block">
              {requestedActionDisplay}
            </span>
          </div>

          {/* Urgency Level */}
          <div className="rounded-xl border border-white/[0.08] bg-zinc-950/80 p-3.5 space-y-1">
            <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-500 block">
              Pressure Level
            </span>
            <span className="text-sm font-semibold text-amber-300 font-sans block flex items-center gap-1.5">
              <Zap className="h-3.5 w-3.5" />
              {pressureLevelDisplay}
            </span>
          </div>

          {/* Key Manipulation Tactic */}
          <div className="rounded-xl border border-white/[0.08] bg-zinc-950/80 p-3.5 space-y-1 sm:col-span-2 lg:col-span-1">
            <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-500 block">
              Manipulation Tactic
            </span>
            <span className="text-sm font-semibold text-zinc-200 font-sans block">
              {manipulationTacticDisplay}
            </span>
          </div>
        </div>

        {/* Additional tactic tags */}
        {(() => {
          const tacticsList =
            result.manipulationTactics && result.manipulationTactics.length > 0
              ? result.manipulationTactics
              : result.aiIntent?.manipulationTactics || [];
          return tacticsList.length > 1 ? (
            <div className="flex flex-wrap items-center gap-2 mt-3 pt-3 border-t border-white/[0.05]">
              <span className="text-xs font-mono text-zinc-500">Additional manipulation tactics:</span>
              {tacticsList.slice(1).map((tactic, idx) => (
                <span
                  key={idx}
                  className="text-xs font-mono bg-zinc-900 border border-white/[0.08] text-zinc-300 px-2.5 py-0.5 rounded-full"
                >
                  {TACTIC_LABELS[tactic] || tactic}
                </span>
              ))}
            </div>
          ) : null;
        })()}
      </div>

      {/* ===== 2. WHY IS IT SUSPICIOUS? ===== */}
      <div className="rounded-2xl border border-white/[0.08] bg-[#0b0c14] p-5 sm:p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-white/[0.08] pb-3 mb-4">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-500/15 border border-indigo-500/30 text-indigo-400">
              <AlertTriangle className="h-4 w-4" aria-hidden="true" />
            </div>
            <h3 className="text-lg font-bold text-white font-heading">
              2. Why is it suspicious?
            </h3>
          </div>
          <span className="text-xs font-mono text-indigo-300 bg-indigo-500/10 border border-indigo-500/25 px-2.5 py-1 rounded-full self-start sm:self-auto">
            Kyun Sandehaspad Hai?
          </span>
        </div>

        {/* Plain-Language Explanation */}
        <p className="text-base text-zinc-200 leading-relaxed font-sans mb-5">
          {result.aiIntent?.explanation || result.reasoning || simpleSummary}
        </p>

        {/* Detected Warning Signs Grid */}
        {result.indicators && result.indicators.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
            {result.indicators.map((ind, idx) => {
              const trans = translateIndicator(ind);
              return (
                <div
                  key={`${ind.id}-${idx}`}
                  className="rounded-xl border border-white/[0.08] bg-[#080910] p-4 hover:border-white/[0.16] transition-colors duration-150 flex flex-col justify-between space-y-2.5"
                >
                  <div>
                    <div className="flex items-start justify-between gap-3 mb-1.5">
                      <span className="text-sm sm:text-base font-bold text-white font-heading">
                        {trans.friendlyTitle}
                      </span>
                      <span
                        className={`text-[11px] font-mono font-bold uppercase px-2 py-0.5 rounded-full shrink-0 ${
                          severityColors[ind.severity] || severityColors.LOW
                        }`}
                      >
                        {ind.severity}
                      </span>
                    </div>
                    <p className="text-sm text-zinc-300 leading-relaxed font-sans">
                      {trans.friendlyExplanation}
                    </p>
                  </div>

                  {ind.evidence && (
                    <div className="rounded-lg bg-zinc-950 border border-white/[0.06] px-3 py-2 text-xs font-mono">
                      <span className="text-zinc-500 mr-1.5">Found in text:</span>
                      <span className="text-red-300 font-semibold break-all">
                        &ldquo;{ind.evidence}&rdquo;
                      </span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ) : (
          <div className="rounded-xl border border-emerald-500/25 bg-emerald-500/[0.04] p-4 text-sm text-emerald-300 font-sans flex items-center gap-3">
            <CheckCircle2 className="h-5 w-5 text-emerald-400 shrink-0" />
            <span>No suspicious urgency patterns, coercive threats, or fraudulent indicators were found.</span>
          </div>
        )}
      </div>

      {/* ===== 3. WHAT COULD HAPPEN? (Potential Consequence) ===== */}
      <div className="rounded-2xl border border-red-500/25 bg-red-950/[0.08] p-5 sm:p-6 shadow-lg">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-red-500/20 pb-3 mb-4">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-red-500/15 border border-red-500/30 text-red-400">
              <AlertCircle className="h-4 w-4" aria-hidden="true" />
            </div>
            <h3 className="text-lg font-bold text-white font-heading">
              3. What could happen if you comply?
            </h3>
          </div>
          <span className="text-xs font-mono text-red-300 bg-red-500/10 border border-red-500/25 px-2.5 py-1 rounded-full self-start sm:self-auto">
            Khatra / Potential Impact
          </span>
        </div>

        <p className="text-base text-zinc-200 leading-relaxed font-sans">
          {potentialConsequenceText}
        </p>
      </div>

      {/* ===== 4. WHAT SHOULD YOU DO? ===== */}
      <div className="rounded-2xl border border-emerald-500/30 bg-[#0b0c14] p-5 sm:p-7 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-white/[0.08] pb-3 mb-5">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-500/15 border border-emerald-500/30 text-emerald-400">
              <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
            </div>
            <h3 className="text-lg font-bold text-white font-heading">
              4. What should you do right now?
            </h3>
          </div>
          <span className="text-xs font-mono text-emerald-300 bg-emerald-500/10 border border-emerald-500/25 px-2.5 py-1 rounded-full self-start sm:self-auto">
            Abhi Kya Karein?
          </span>
        </div>

        {/* Immediate Primary Directive Card */}
        <div className="rounded-xl border border-emerald-500/40 bg-emerald-500/10 p-4 sm:p-5 mb-5">
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="text-xs font-mono font-bold tracking-wider uppercase text-emerald-300 mb-1">
                Immediate Safe Action
              </div>
              <p className="text-base font-semibold text-white leading-relaxed font-sans">
                {result.aiIntent?.recommendedAction || result.recommendedAction}
              </p>
            </div>
            <button
              type="button"
              onClick={() => handleCopyAction(result.aiIntent?.recommendedAction || result.recommendedAction)}
              className="p-2 rounded-lg border border-white/[0.08] bg-zinc-900 text-zinc-300 hover:text-white hover:bg-zinc-800 transition-all duration-150 shrink-0"
              title="Copy directive"
              aria-label="Copy action directive"
            >
              {copiedAction === (result.aiIntent?.recommendedAction || result.recommendedAction) ? (
                <Check className="h-4 w-4 text-emerald-400" />
              ) : (
                <Copy className="h-4 w-4" />
              )}
            </button>
          </div>
        </div>

        {/* High Threat DO NOT vs DO Split Columns */}
        {isHighThreat ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* DO NOT Column */}
            <div className="rounded-xl border border-red-500/25 bg-red-500/[0.04] p-5 space-y-3">
              <div className="flex items-center gap-2 text-xs font-mono font-bold uppercase text-red-400 tracking-wider">
                <XCircle className="h-4 w-4 text-red-400 shrink-0" />
                <span>DO NOT</span>
              </div>
              <ul className="space-y-2.5 text-sm text-zinc-200 font-sans">
                {doNotActions.map((act, i) => (
                  <li key={i} className="flex items-start gap-2.5 leading-relaxed">
                    <span className="text-red-400 font-bold text-base leading-tight">•</span>
                    <span>{act}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* DO Column */}
            <div className="rounded-xl border border-emerald-500/25 bg-emerald-500/[0.04] p-5 space-y-3">
              <div className="flex items-center gap-2 text-xs font-mono font-bold uppercase text-emerald-400 tracking-wider">
                <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                <span>DO</span>
              </div>
              <ul className="space-y-2.5 text-sm text-zinc-200 font-sans">
                {doActions.map((act, i) => (
                  <li key={i} className="flex items-start gap-2.5 leading-relaxed">
                    <span className="text-emerald-400 font-bold text-base leading-tight">•</span>
                    <span>{act}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        ) : (
          /* Single list for benign / caution results */
          <div className="space-y-2.5">
            {doActions.map((act, idx) => (
              <div
                key={idx}
                className="flex items-start justify-between gap-3 rounded-xl border border-white/[0.06] bg-[#07080d] p-3.5 text-sm text-zinc-200 hover:border-white/[0.12] transition-colors duration-150 font-sans"
              >
                <div className="flex items-start gap-3">
                  <span className="font-mono text-zinc-400 font-bold text-xs shrink-0 mt-0.5">
                    0{idx + 1}.
                  </span>
                  <span className="leading-relaxed">{act}</span>
                </div>
                <button
                  type="button"
                  onClick={() => handleCopyAction(act)}
                  className="p-1 rounded text-zinc-400 hover:text-zinc-200 transition-colors duration-150 shrink-0"
                  title="Copy step"
                  aria-label={`Copy step ${idx + 1}`}
                >
                  {copiedAction === act ? (
                    <Check className="h-4 w-4 text-emerald-400" />
                  ) : (
                    <Copy className="h-4 w-4" />
                  )}
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ===== 5. TECHNICAL SECURITY ANALYSIS & FORENSICS ===== */}
      <div className="rounded-2xl border border-white/[0.1] bg-[#070810] overflow-hidden">
        <div className="p-5 sm:p-6 border-b border-white/[0.06] bg-zinc-950/60">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-zinc-800 border border-white/[0.1] text-zinc-300">
                <Terminal className="h-4 w-4" aria-hidden="true" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-white font-heading">
                  5. Technical Security Analysis & Forensics
                </h3>
                <p className="text-xs text-zinc-400 font-mono mt-0.5">
                  Authoritative risk scoring, threat intelligence feeds, and deterministic evidence
                </p>
              </div>
            </div>

            {/* Score & Verdict Display */}
            <div className="flex items-center gap-4">
              <div className="flex items-baseline gap-1">
                <AnimatedScore
                  target={Math.round(result.riskScore)}
                  className={`text-4xl font-extrabold font-mono leading-none ${s.text}`}
                />
                <span className="text-base font-mono text-zinc-500">/100</span>
              </div>
              <div className="flex flex-col">
                <span className="text-[10px] font-mono uppercase text-zinc-500">Verdict</span>
                <span className="text-xs font-mono font-bold text-zinc-200">
                  {result.verdict || result.riskLevel}
                </span>
              </div>
            </div>
          </div>

          {/* Score progress bar */}
          <div className="w-full h-2 bg-zinc-900 rounded-full overflow-hidden border border-white/[0.08] mt-4">
            <div
              className={`h-full bg-gradient-to-r ${s.bar} animate-score-reveal`}
              style={{ width: `${result.riskScore}%` }}
              role="meter"
              aria-valuenow={result.riskScore}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-label={`Threat score: ${result.riskScore} out of 100`}
            />
          </div>
        </div>

        {/* Dynamic Scam DNA Progression */}
        {result.attackPath && result.attackPath.length > 0 && (
          <div className="p-5 sm:p-6 border-b border-white/[0.06]">
            <div className="text-xs font-mono uppercase tracking-wider text-zinc-400 mb-3 flex items-center gap-2">
              <Activity className="h-3.5 w-3.5 text-indigo-400" />
              <span>Scam Kill Chain & Attack Progression (Scam DNA)</span>
            </div>
            <ScamDNAVisual customSteps={result.attackPath} interactive={true} />
          </div>
        )}

        {/* Collapsible Forensics Drawer */}
        <button
          type="button"
          onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
          className="w-full flex items-center justify-between p-4 sm:p-5 text-left hover:bg-white/[0.02] transition-colors duration-150 cursor-pointer"
          aria-expanded={showTechnicalDetails}
        >
          <div className="flex items-center gap-2.5 text-sm font-mono font-semibold text-zinc-300">
            <FileSearch className="h-4 w-4 text-indigo-400" />
            <span>Forensic Evidence, Rule IDs & Threat Telemetry</span>
          </div>
          <div className="flex items-center gap-2 text-xs font-mono text-zinc-400">
            <span>{showTechnicalDetails ? "Hide Forensic Details" : "Inspect Forensic Details"}</span>
            {showTechnicalDetails ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          </div>
        </button>

        {showTechnicalDetails && (
          <div className="p-5 sm:p-6 border-t border-white/[0.06] space-y-4 bg-[#05060b] animate-fade-in font-mono text-xs">
            {/* Telemetry Summary Cards */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-zinc-950 p-4 rounded-xl border border-white/[0.06]">
              <div>
                <span className="text-zinc-500 block">Analysis Engine:</span>
                <span className="text-zinc-300 font-semibold">Gemini + Rules + Threat Intel</span>
              </div>
              <div>
                <span className="text-zinc-500 block">Threat Score:</span>
                <span className="text-zinc-300 font-semibold">{result.riskScore} / 100.0</span>
              </div>
              <div>
                <span className="text-zinc-500 block">Threat Intel Status:</span>
                <span className="text-zinc-300 font-semibold">
                  {result.threatIntelligence?.isKnownMalicious ? "MALICIOUS HIT" : "No Blacklist Hit"}
                </span>
              </div>
              <div>
                <span className="text-zinc-500 block">Total Indicators:</span>
                <span className="text-zinc-300 font-semibold">{result.indicators?.length || 0} signals</span>
              </div>
            </div>

            {/* Individual technical indicator cards */}
            {result.indicators && result.indicators.length > 0 ? (
              <div className="space-y-3">
                {result.indicators.map((ind, idx) => (
                  <div
                    key={`tech-${ind.id}-${idx}`}
                    className="p-4 rounded-xl border border-white/[0.06] bg-[#07080f] space-y-2"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.04] pb-2">
                      <div className="flex items-center gap-2">
                        <span className="text-indigo-400 font-bold">{ind.findingId || ind.id}</span>
                        <span className="text-zinc-600">|</span>
                        <span className="text-zinc-200 font-sans font-semibold">{ind.name}</span>
                      </div>
                      <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${severityColors[ind.severity] || severityColors.LOW}`}>
                        {ind.severity}
                      </span>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-zinc-400">
                      <div>
                        <span className="text-zinc-500">Attack Stage: </span>
                        <span className="text-zinc-300">{ind.attackStage || "General Signal"}</span>
                      </div>
                      {ind.type && (
                        <div>
                          <span className="text-zinc-500">Type: </span>
                          <span className="text-zinc-300 font-semibold">{ind.type}</span>
                        </div>
                      )}
                      {ind.source && (
                        <div>
                          <span className="text-zinc-500">Source: </span>
                          <span className="text-zinc-300">{ind.source}</span>
                        </div>
                      )}
                      {ind.confidence && (
                        <div>
                          <span className="text-zinc-500">Confidence: </span>
                          <span className="text-indigo-300 font-semibold">{ind.confidence}</span>
                        </div>
                      )}
                      {ind.evidence && (
                        <div className="sm:col-span-2">
                          <span className="text-zinc-500">Extracted Cue: </span>
                          <span className="text-red-300 font-semibold break-all">&ldquo;{ind.evidence}&rdquo;</span>
                        </div>
                      )}
                    </div>

                    {ind.whyItMatters && (
                      <div className="text-zinc-300 bg-white/[0.02] border border-white/[0.04] rounded p-2">
                        <span className="text-zinc-500">Forensic Rationale: </span>
                        {ind.whyItMatters}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-3 rounded-lg bg-zinc-950 text-zinc-400">
                No deterministic threat indicators flagged for this input.
              </div>
            )}
          </div>
        )}
      </div>

      {/* ===== 6. RESET / SCAN ANOTHER MESSAGE BUTTON ===== */}
      <div className="flex justify-center pt-2 pb-2">
        <button
          type="button"
          id="reset-analyze-btn"
          onClick={onReset}
          className="inline-flex items-center gap-2.5 rounded-xl border border-white/[0.12] bg-zinc-900/90 px-7 py-3.5 text-xs font-mono font-bold tracking-widest uppercase text-zinc-200 hover:text-white hover:bg-zinc-800 hover:border-white/[0.25] transition-all duration-150 shadow-lg cursor-pointer"
          aria-label="Scan another message"
        >
          <RotateCcw className="h-4 w-4 text-indigo-400" aria-hidden="true" />
          Scan Another Message
        </button>
      </div>
    </div>
  );
}
