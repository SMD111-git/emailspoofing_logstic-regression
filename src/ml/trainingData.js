/**
 * Synthetic Training Data Generator
 * Produces realistic labeled email samples for training the logistic regression model.
 *
 * Label: 1 = spoofed/phishing, 0 = legitimate
 *
 * Strategy: rule-based feature construction — we know the ground truth
 * for each generated sample, so labels are 100% accurate.
 */

import { extractFeatures } from "./featureExtractor.js";

// ─── Vocabulary pools ─────────────────────────────────────────────────────────

const LEGIT_DOMAINS = [
  "gmail.com", "outlook.com", "company.com", "acme.org", "techcorp.io",
  "university.edu", "gov.in", "nonprofit.org", "mybusiness.net", "startup.co",
];

const MALICIOUS_DOMAINS = [
  "phishing.xyz", "malicious.top", "spoof-mail.click", "hackerdomain.tk",
  "evil-corp.gq", "fakepaypal.ml", "scam-alert.pw", "phish-attempt.cf",
  "urgent-verify.cc", "account-secure.su", "login-required.icu", "prize-winner.buzz",
];

const LEGIT_SUBJECTS = [
  "Meeting at 3pm tomorrow",
  "Your order has shipped",
  "Invoice #INV-2024-0012 attached",
  "Weekly team standup notes",
  "Project update — Q1 roadmap",
  "Re: Proposal review",
  "Welcome to our platform",
  "Your subscription renewal",
  "Newsletter — March Edition",
  "Job offer — Software Engineer position",
  "Ticket #48291 resolved",
  "Your appointment is confirmed",
  "New comment on your document",
  "Password changed successfully",
  "Two-factor authentication enabled",
];

const PHISH_SUBJECTS = [
  "URGENT: Your account will be suspended",
  "Action Required: Verify your account NOW",
  "⚠️ Security Alert — Unusual login detected",
  "FINAL NOTICE: Update your billing information",
  "Your password expires in 24 hours",
  "URGENT: Confirm your identity immediately",
  "You have won a $1,000,000 prize!",
  "Reset your password — click here",
  "WARNING: Your account has been compromised",
  "ALERT: Unauthorized access detected",
  "Limited Time Offer — Claim your reward NOW",
  "Your bank account has been flagged",
  "Immediate action required to avoid suspension",
  "URGENT wire transfer required",
  "Dear valued customer: verify now",
];

const LEGIT_BODIES = [
  "Hi team, please find the attached report for review. Let me know if you have any questions.",
  "Your order #12345 has been dispatched. Expected delivery in 3-5 business days.",
  "Hello, this is a reminder about your appointment scheduled for Thursday at 2pm.",
  "Please see the meeting notes attached. Next steps are outlined in the document.",
  "We're happy to inform you that your support ticket has been resolved.",
];

const PHISH_BODIES = [
  "Click here immediately to verify your account: http://bit.ly/fake-verify. Failure to act will result in suspension.",
  "Your account has been compromised. Enable macros in the attached document to restore access.",
  "Congratulations! You have won $500,000. Send your bank account details to claim your prize.",
  "URGENT: We detected unauthorized activity. Reset your password NOW or your account will be disabled.",
  "Dear valued customer, please confirm your billing details within 24 hours to avoid service interruption.",
];

// ─── Sample generators ────────────────────────────────────────────────────────

function randomFrom(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomFloat(min, max) {
  return Math.random() * (max - min) + min;
}

/**
 * Generate a LEGITIMATE email sample (label = 0)
 */
function generateLegitSample() {
  const domain = randomFrom(LEGIT_DOMAINS);
  const authVariant = Math.random();

  // Occasionally legitimate emails have one check missing (not all servers set all three)
  let spf = "pass", dkim = "pass", dmarc = "pass";
  if (authVariant < 0.1) dmarc = "unknown"; // 10% chance dmarc not configured

  return {
    from: `sender@${domain}`,
    returnPath: `sender@${domain}`, // matches From
    subject: randomFrom(LEGIT_SUBJECTS),
    body: randomFrom(LEGIT_BODIES),
    authentication: { spf, dkim, dmarc },
    rawHeaders: `From: sender@${domain}\nReturn-Path: <sender@${domain}>\nAuthentication-Results: spf=${spf} dkim=${dkim} dmarc=${dmarc}`,
    label: 0,
  };
}

/**
 * Generate a SPOOFED/PHISHING email sample (label = 1)
 * Multiple attack variants to create diverse training data
 */
function generatePhishSample() {
  const variant = Math.floor(Math.random() * 6);
  const fromDomain = randomFrom(LEGIT_DOMAINS);    // impersonates legit domain
  const rpDomain   = randomFrom(MALICIOUS_DOMAINS); // real sender is malicious

  switch (variant) {
    case 0: // All auth fails — classic full spoof
      return {
        from: `admin@${fromDomain}`,
        returnPath: `attacker@${rpDomain}`,
        subject: randomFrom(PHISH_SUBJECTS),
        body: randomFrom(PHISH_BODIES),
        authentication: { spf: "fail", dkim: "fail", dmarc: "fail" },
        rawHeaders: `From: admin@${fromDomain}\nReturn-Path: <attacker@${rpDomain}>\nAuthentication-Results: spf=fail dkim=fail dmarc=fail`,
        label: 1,
      };

    case 1: // SPF fail only + suspicious subject
      return {
        from: `security@${fromDomain}`,
        returnPath: `noreply@${fromDomain}`,
        subject: randomFrom(PHISH_SUBJECTS),
        body: randomFrom(PHISH_BODIES),
        authentication: { spf: "fail", dkim: "pass", dmarc: "fail" },
        rawHeaders: `From: security@${fromDomain}\nReturn-Path: <noreply@${fromDomain}>\nAuthentication-Results: spf=fail dkim=pass dmarc=fail`,
        label: 1,
      };

    case 2: // No auth headers at all + phishing content
      return {
        from: `support@${fromDomain}`,
        returnPath: "",
        subject: randomFrom(PHISH_SUBJECTS),
        body: randomFrom(PHISH_BODIES),
        authentication: { spf: "unknown", dkim: "unknown", dmarc: "unknown" },
        rawHeaders: `From: support@${fromDomain}`,
        label: 1,
      };

    case 3: // Return-path mismatch + DKIM fail
      return {
        from: `billing@${fromDomain}`,
        returnPath: `harvest@${rpDomain}`,
        subject: randomFrom(PHISH_SUBJECTS),
        body: randomFrom(PHISH_BODIES),
        authentication: { spf: "pass", dkim: "fail", dmarc: "fail" },
        rawHeaders: `From: billing@${fromDomain}\nReturn-Path: <harvest@${rpDomain}>\nAuthentication-Results: spf=pass dkim=fail dmarc=fail`,
        label: 1,
      };

    case 4: // Suspicious TLD sender
      return {
        from: `noreply@prize-winner.buzz`,
        returnPath: `noreply@prize-winner.buzz`,
        subject: randomFrom(PHISH_SUBJECTS),
        body: randomFrom(PHISH_BODIES),
        authentication: { spf: "fail", dkim: "fail", dmarc: "fail" },
        rawHeaders: `From: noreply@prize-winner.buzz\nReturn-Path: <noreply@prize-winner.buzz>\nAuthentication-Results: spf=fail dkim=fail dmarc=fail`,
        label: 1,
      };

    default: // DMARC fail + urgent subject
      return {
        from: `it-support@${fromDomain}`,
        returnPath: `it-support@${fromDomain}`,
        subject: randomFrom(PHISH_SUBJECTS),
        body: randomFrom(PHISH_BODIES),
        authentication: { spf: "pass", dkim: "pass", dmarc: "fail" },
        rawHeaders: `From: it-support@${fromDomain}\nReturn-Path: <it-support@${fromDomain}>\nAuthentication-Results: spf=pass dkim=pass dmarc=fail`,
        label: 1,
      };
  }
}

/**
 * Generate the full training dataset
 * @param {number} n - number of samples (split 50/50 legit vs phish)
 * @returns {{ X: number[][], y: number[] }}
 */
export function generateTrainingData(n = 600) {
  const half = Math.floor(n / 2);
  const samples = [];

  for (let i = 0; i < half; i++) samples.push(generateLegitSample());
  for (let i = 0; i < half; i++) samples.push(generatePhishSample());

  // Shuffle
  for (let i = samples.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [samples[i], samples[j]] = [samples[j], samples[i]];
  }

  const X = samples.map(s => extractFeatures(s).vector);
  const y = samples.map(s => s.label);

  return { X, y };
}
