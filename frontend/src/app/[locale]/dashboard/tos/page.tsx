"use client";
import { motion } from "framer-motion";
import { ScrollText, Shield, AlertTriangle, Lock, Eye, Ban, Zap, Server } from "lucide-react";

const sections = [
  {
    icon: ScrollText,
    color: "#00f5ff",
    title: "1. Acceptance of Terms",
    content: `By accessing or using PhishGuard ("the Service"), you agree to be bound by these Terms of Service ("Terms"). If you do not agree to these Terms in their entirety, you must not use the Service.

These Terms constitute a legally binding agreement between you ("User") and PhishGuard ("we", "us", or "our"). We reserve the right to amend these Terms at any time. Continued use of the Service following notice of changes constitutes acceptance of the revised Terms.

You must be at least 18 years of age and legally capable of entering into a binding contract to use this Service. By using PhishGuard, you represent and warrant that you meet these requirements.`,
  },
  {
    icon: Shield,
    color: "#00ff88",
    title: "2. Description of Service",
    content: `PhishGuard is a cybersecurity platform that provides:

• Phishing URL detection and analysis using machine learning and rule-based systems
• SMS and message fraud detection
• File content scanning for embedded threats
• Live network traffic threat monitoring
• Threat intelligence dashboards and historical scan reporting

The Service is provided for legitimate security research, organizational threat protection, and personal cybersecurity awareness. PhishGuard is a detection and analysis tool only — it does not prevent, block, or remediate threats on your infrastructure.`,
  },
  {
    icon: Eye,
    color: "#bf5af2",
    title: "3. User Responsibilities",
    content: `You are solely responsible for:

• The accuracy and legality of all content you submit for scanning
• Ensuring you have authorization to scan URLs, files, and messages you submit
• Maintaining the confidentiality of your account credentials
• All activity that occurs under your account
• Complying with all applicable local, national, and international laws

You must not submit content you do not have the legal right to share, including but not limited to content covered by confidentiality agreements, personal data of third parties without consent, or content protected by intellectual property rights without authorization.`,
  },
  {
    icon: Lock,
    color: "#ffd60a",
    title: "4. Privacy and Data Handling",
    content: `Data you submit to PhishGuard for analysis ("Scan Data") is processed as follows:

• URLs and domain names are analyzed by our detection engines and stored in association with your account for history and reporting purposes.
• File uploads are encrypted at rest using AES-256-CBC encryption immediately upon receipt. Files are stored encrypted and are never shared with third parties.
• Message content submitted for fraud analysis is stored in encrypted form and associated with your account.
• We do not sell, rent, or trade your Scan Data to third parties.
• You may request deletion of your account and associated Scan Data at any time by contacting support.
• Aggregate, anonymized threat statistics may be used to improve our detection models.

By using the Service, you grant us a limited, non-exclusive license to process your Scan Data solely for the purpose of providing the Service.`,
  },
  {
    icon: Ban,
    color: "#ff2d55",
    title: "5. Acceptable Use Policy",
    content: `The following uses of PhishGuard are strictly prohibited:

• Submitting URLs, files, or messages with the intent to evade detection or test evasion techniques against our platform
• Using the Service to scan third-party systems, URLs, or content you do not own or have explicit authorization to test
• Attempting to reverse-engineer, decompile, or extract our detection models or algorithms
• Abusing the Service through automated scraping, excessive API calls beyond documented rate limits, or denial-of-service attacks
• Using the Service in connection with any illegal activity, including but not limited to cybercrime, fraud, unauthorized access, or harassment
• Creating multiple accounts to circumvent rate limits or access restrictions
• Impersonating any person or entity or misrepresenting your affiliation

Violation of this policy may result in immediate account termination and, where appropriate, referral to law enforcement authorities.`,
  },
  {
    icon: AlertTriangle,
    color: "#ff9f0a",
    title: "6. Security Limitations and Disclaimer",
    content: `PhishGuard is a threat detection tool and is subject to inherent limitations:

• No detection system achieves 100% accuracy. PhishGuard may produce false positives (safe content flagged as threats) or false negatives (threats not detected).
• Detection models are based on known threat patterns and may not identify zero-day or novel attack techniques.
• The Live Threat Detection feature provides indicators of suspicious activity and should be used in conjunction with professional network security monitoring, not as a replacement for it.
• Threat intelligence databases are updated regularly but may not reflect the most current threat landscape at all times.

PhishGuard does not guarantee that use of the Service will protect you from all phishing attacks, fraud, or malware. You are responsible for implementing comprehensive security measures appropriate to your risk profile.`,
  },
  {
    icon: Zap,
    color: "#30d158",
    title: "7. Limitation of Liability",
    content: `TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW:

The Service is provided "as is" and "as available" without warranties of any kind, whether express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, or non-infringement.

PhishGuard shall not be liable for any indirect, incidental, special, consequential, or punitive damages, including but not limited to loss of profits, data, or business opportunities, arising from your use of or inability to use the Service, even if advised of the possibility of such damages.

Our total cumulative liability to you for any claims arising from these Terms or your use of the Service shall not exceed the amount paid by you for the Service in the twelve (12) months preceding the claim.`,
  },
  {
    icon: Server,
    color: "#00f5ff",
    title: "8. Service Availability",
    content: `We strive to maintain high availability of the PhishGuard platform but do not guarantee uninterrupted service. Scheduled and emergency maintenance may result in temporary unavailability.

We reserve the right to:
• Modify, suspend, or discontinue any aspect of the Service at any time with reasonable notice where possible
• Impose usage limits or restrictions to protect Service availability for all users
• Terminate or restrict access to accounts that violate these Terms or negatively impact Service performance

We will use reasonable efforts to provide advance notice of planned maintenance or significant changes to the Service.`,
  },
];

export default function TermsOfServicePage() {
  return (
    <div className="p-6 max-w-4xl">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        className="mb-10"
      >
        <div className="flex items-center gap-2 mb-1">
          <ScrollText className="w-4 h-4" style={{ color: "#00f5ff" }} />
          <span className="font-mono text-xs uppercase tracking-widest" style={{ color: "#00f5ff" }}>
            Legal
          </span>
        </div>
        <h1 className="font-display text-2xl font-bold mb-2" style={{ color: "#e8eaf0" }}>
          Terms of Service
        </h1>
        <p className="font-mono text-sm" style={{ color: "#8892b0" }}>
          Last updated: March 2025 · Effective: Immediately upon account creation
        </p>

        {/* Summary banner */}
        <div
          className="mt-5 p-4 rounded-xl border font-mono text-sm"
          style={{ borderColor: "rgba(0,245,255,0.2)", background: "rgba(0,245,255,0.04)", color: "#8892b0" }}
        >
          <span style={{ color: "#00f5ff" }}>TL;DR</span>{" "}
          PhishGuard is a cybersecurity detection tool. Use it lawfully and responsibly. We protect your data.
          We make no guarantee of perfect detection. Do not use it to test systems you don't own.
        </div>
      </motion.div>

      {/* Sections */}
      <div className="space-y-5">
        {sections.map((section, i) => {
          const Icon = section.icon;
          return (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.05 }}
              className="cyber-card p-6"
            >
              <div className="flex items-center gap-3 mb-4">
                <div
                  className="w-9 h-9 rounded-lg flex items-center justify-center border shrink-0"
                  style={{ background: `${section.color}12`, borderColor: `${section.color}30` }}
                >
                  <Icon className="w-4.5 h-4.5" style={{ color: section.color }} />
                </div>
                <h2 className="font-display font-bold text-base" style={{ color: "#e8eaf0" }}>
                  {section.title}
                </h2>
              </div>
              <div
                className="font-mono text-sm leading-relaxed whitespace-pre-line"
                style={{ color: "#8892b0" }}
              >
                {section.content}
              </div>
            </motion.div>
          );
        })}
      </div>

      {/* Footer */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.6 }}
        className="mt-8 p-5 rounded-xl border text-center"
        style={{ borderColor: "#1a2540", background: "rgba(12,17,32,0.8)" }}
      >
        <p className="font-mono text-xs" style={{ color: "#8892b0" }}>
          Questions about these Terms?{" "}
          <span style={{ color: "#00f5ff" }}>legal@phishguard.io</span>
        </p>
        <p className="font-mono text-xs mt-1" style={{ color: "#8892b0", opacity: 0.5 }}>
          PhishGuard · Cybersecurity Platform · All rights reserved
        </p>
      </motion.div>
    </div>
  );
}
