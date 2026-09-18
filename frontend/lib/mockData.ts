import type { AnalysisResponse } from "@/types/analysis";

export interface PresetSample {
  id: string;
  title: string;
  tag: string;
  message: string;
  mockResult: AnalysisResponse;
}

export const PRESET_SAMPLES: PresetSample[] = [
  {
    id: "kyc-phishing",
    title: "Bank KYC Expiration",
    tag: "High Urgency",
    message:
      "Dear Customer, your HDFC bank account has been suspended due to pending PAN-KYC verification. Please update immediately at https://hdfc-kyc-portal.xyz/login to prevent account deactivation within 2 hours.",
    mockResult: {
      analysisId: "mock-kyc-001",
      riskScore: 94.0,
      riskLevel: "CRITICAL",
      category: "BANKING_SCAM",
      reasoning:
        "Severe phishing threat mimicking official HDFC banking communications. Employs artificial deadline urgency, fraudulent domain spoofing, and credential harvesting mechanisms designed to steal netbanking logins.",
      attackerIntent:
        "Obtain netbanking user credentials and trigger unauthorized funds transfers via fraudulent mirror portal.",
      indicators: [
        {
          id: "IND_CREDENTIAL_PHISH",
          name: "Credential Harvesting Link",
          description: "Directs user to an unverified third-party domain mimicking official bank infrastructure.",
          severity: "CRITICAL",
          evidence: "https://hdfc-kyc-portal.xyz/login",
        },
        {
          id: "IND_ARTIFICIAL_URGENCY",
          name: "Coercive Deadline Pressure",
          description: "Creates an artificial 2-hour deadline to prevent cognitive scrutiny and promote panic.",
          severity: "HIGH",
          evidence: "to prevent account deactivation within 2 hours",
        },
        {
          id: "IND_IMPERSONATION",
          name: "Financial Institution Impersonation",
          description: "Illegitimately invokes HDFC Bank identity without official sender authentication.",
          severity: "HIGH",
          evidence: "your HDFC bank account has been suspended",
        },
      ],
      attackPath: [
        {
          step: 1,
          stage: "Initial Lure",
          description: "Unsolicited SMS alerting user to sudden account suspension.",
        },
        {
          step: 2,
          stage: "Panic Induction",
          description: "2-hour ultimatum pressures victim into acting without verification.",
        },
        {
          step: 3,
          stage: "Credential Interception",
          description: "Fake login page captures customer ID, password, and subsequent 2FA OTP.",
        },
        {
          step: 4,
          stage: "Financial Exfiltration",
          description: "Attacker executes immediate unauthorized NEFT/IMPS transfer.",
        },
      ],
      recommendedAction: "Do not click the link or enter banking credentials. Report and block the sender.",
      recommendedActions: [
        "Do not click on https://hdfc-kyc-portal.xyz/login or enter any credentials.",
        "Check your actual account status by logging in only through the official bank app or portal.",
        "Forward the phishing message to your bank's fraud reporting desk (report.phishing@hdfcbank.com).",
        "Block the sender number on your mobile device immediately.",
      ],
      timestamp: new Date().toISOString(),
    },
  },
  {
    id: "upi-fraud",
    title: "Fake UPI Reward",
    tag: "Financial Lure",
    message:
      "Congratulations! You won ₹25,000 cashback reward from Google Pay festive offer. To transfer cash directly to your bank account, click here and approve the collect request: upi://pay?pa=claimreward99@upi&pn=CashbackPortal",
    mockResult: {
      analysisId: "mock-upi-002",
      riskScore: 88.0,
      riskLevel: "HIGH",
      category: "PAYMENT_SCAM",
      reasoning:
        "Classic UPI collect request deception. Tricking victim into believing they are receiving funds, while entering a UPI PIN will authorize an immediate debit from the victim's account.",
      attackerIntent:
        "Exploit misunderstanding of UPI collect requests to withdraw ₹25,000 from victim's account.",
      indicators: [
        {
          id: "IND_REWARD_LURE",
          name: "Unrealistic Prize / Reward Incentive",
          description: "Promises unsolicited financial rewards to entice uncritical action.",
          severity: "HIGH",
          evidence: "won ₹25,000 cashback reward",
        },
        {
          id: "IND_REVERSE_UPI",
          name: "Reverse UPI Collect Deception",
          description: "Instructs user to approve a request or enter PIN to 'receive' money.",
          severity: "CRITICAL",
          evidence: "approve the collect request",
        },
      ],
      attackPath: [
        {
          step: 1,
          stage: "Bait",
          description: "Offers a high-value festive reward out of the blue.",
        },
        {
          step: 2,
          stage: "Misdirection",
          description: "Frames an outgoing debit collect request as an incoming credit.",
        },
        {
          step: 3,
          stage: "Authorization Trap",
          description: "User enters UPI PIN thinking it confirms receipt, which actually approves debit.",
        },
      ],
      recommendedAction: "Decline any pending UPI collect requests. Entering your UPI PIN always sends money, never receives it.",
      recommendedActions: [
        "Never enter your UPI PIN to receive money. Entering PIN always debits your account.",
        "Decline and report the collect request in your UPI app (Google Pay/PhonePe/Paytm).",
        "Block the VPA handle 'claimreward99@upi'.",
      ],
      timestamp: new Date().toISOString(),
    },
  },
  {
    id: "job-scam",
    title: "Telegram Job Offer",
    tag: "Social Engineering",
    message:
      "Part-time work from home! Earn ₹3,000 - ₹8,000 per day by rating hotels on Google Maps. No skills required. Immediate payout. Contact our recruitment manager on Telegram @GlobalHR_Priya now.",
    mockResult: {
      analysisId: "mock-job-003",
      riskScore: 72.0,
      riskLevel: "MEDIUM",
      category: "JOB_SCAM",
      reasoning:
        "Task-based investment/job scam. Promises outsized daily earnings for trivial actions, typically leading to prepaid 'recharge' or task deposit extortion.",
      attackerIntent:
        "Lure user into private Telegram channel, pay small initial amount, then demand upfront deposit for high-tier tasks.",
      indicators: [
        {
          id: "IND_UNREALISTIC_EARNINGS",
          name: "Disproportionate Compensation",
          description: "Offers high daily income for minimal effort with no qualifications required.",
          severity: "MEDIUM",
          evidence: "Earn ₹3,000 - ₹8,000 per day by rating hotels",
        },
        {
          id: "IND_ENCRYPTED_MIGRATION",
          name: "Off-Platform Migration to Telegram",
          description: "Directs conversation to unmoderated messaging channels to evade platform detection.",
          severity: "HIGH",
          evidence: "Contact our recruitment manager on Telegram @GlobalHR_Priya",
        },
      ],
      attackPath: [
        {
          step: 1,
          stage: "Hook",
          description: "Mass-SMS broadcast advertising effortless remote income.",
        },
        {
          step: 2,
          stage: "Channel Shift",
          description: "Victim moves to Telegram where scammers control the environment.",
        },
        {
          step: 3,
          stage: "Prepaid Task Trap",
          description: "User is asked to deposit security money to unlock earnings, which is never returned.",
        },
      ],
      recommendedAction: "Do not contact the Telegram account. Legitimate employers never require prepaid fees for tasks.",
      recommendedActions: [
        "Ignore and delete the message. Legitimate recruiters do not hire via anonymous Telegram handles.",
        "Never pay any 'registration', 'security', or 'task' fee to start a job.",
        "Report the phone number as spam on your carrier.",
      ],
      timestamp: new Date().toISOString(),
    },
  },
  {
    id: "legitimate-bank-alert",
    title: "Legitimate Transaction Alert",
    tag: "Legitimate Baseline",
    message:
      "INR 540.00 debited from A/C XX1049 on 17-Sep-2026 at BLR METRO. Avl Bal: INR 24,190.40. If not done by you, SMS BLOCK to 567676 or call 1800-425-0018.",
    mockResult: {
      analysisId: "mock-legit-004",
      riskScore: 8.0,
      riskLevel: "LOW",
      category: "BENIGN",
      reasoning:
        "Standard legitimate banking debit alert. Contains specific account masking, exact merchant context, balanced balance disclosure, and verified bank helpline numbers without suspicious links.",
      attackerIntent: "None detected. Message exhibits characteristic markers of authentic automated bank notification.",
      indicators: [],
      attackPath: [],
      recommendedAction: "No protective action required. Message appears legitimate.",
      recommendedActions: [
        "Verify transaction against your personal purchase history at the mentioned merchant.",
        "If the charge was unauthorized, contact the verified bank helpline listed on the back of your card.",
      ],
      timestamp: new Date().toISOString(),
    },
  },
];
