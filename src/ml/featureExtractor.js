/**
 * ML Feature Extractor
 * Converts raw email data into a 20-dimensional numeric feature vector
 * for logistic regression classification.
 *
 * Feature Index Map:
 *  0  spfFail              — SPF check failed (0/1)
 *  1  dkimFail             — DKIM check failed (0/1)
 *  2  dmarcFail            — DMARC check failed (0/1)
 *  3  spfUnknown           — SPF result missing (0/1)
 *  4  dkimUnknown          — DKIM result missing (0/1)
 *  5  dmarcUnknown         — DMARC result missing (0/1)
 *  6  returnPathMismatch   — Return-Path domain ≠ From domain (0/1)
 *  7  returnPathMissing    — No Return-Path header (0/1)
 *  8  subjectUrgency       — Urgency keyword count (normalized 0–1)
 *  9  subjectCapsRatio     — Ratio of uppercase letters in subject (0–1)
 * 10  subjectLength        — Subject length (normalized, capped at 200 chars)
 * 11  phishingKeywordScore — Weighted phishing keyword hit score (0–1)
 * 12  hasNoAuthHeader      — No Authentication-Results header at all (0/1)
 * 13  authFailCount        — Number of failed checks (0, 1, 2, 3) / 3
 * 14  fromDomainSuspicious — From domain in known suspicious TLD list (0/1)
 * 15  subjectExclamations  — Exclamation mark count in subject (norm. 0–1)
 * 16  subjectQuestions     — Question mark count in subject (norm. 0–1)
 * 17  bodyUrlCount         — URL count in body (norm. 0–1, capped at 10)
 * 18  bodyLength           — Body length (norm., capped at 2000 chars)
 * 19  multipleFromHeaders  — Suspicious header repetition (0/1)
 */

// ─── Phishing Keyword Dictionary ─────────────────────────────────────────────
// Each entry: [keyword/pattern, weight]
// Weight 1.0 = extremely strong phishing indicator
// Weight 0.5 = moderate indicator
// Weight 0.3 = weak/contextual indicator

export const PHISHING_KEYWORDS = [
  // Critical credential harvesting
  { pattern: /verify your (account|identity|email|password)/i, weight: 1.0, category: "Credential Harvesting" },
  { pattern: /confirm your (account|details|information|password)/i, weight: 1.0, category: "Credential Harvesting" },
  { pattern: /your account (will be|has been) (suspended|disabled|blocked|terminated)/i, weight: 1.0, category: "Account Threat" },
  { pattern: /reset your password/i, weight: 0.9, category: "Credential Harvesting" },
  { pattern: /click here (to|and) (verify|confirm|activate|reset)/i, weight: 1.0, category: "Deceptive CTA" },
  { pattern: /login (immediately|now|urgently)/i, weight: 0.9, category: "Urgency" },
  { pattern: /update (your )?(billing|payment|credit card|bank)/i, weight: 0.9, category: "Financial Fraud" },

  // Urgency & pressure
  { pattern: /\burgent\b/i, weight: 0.7, category: "Urgency" },
  { pattern: /\bimmediately\b/i, weight: 0.6, category: "Urgency" },
  { pattern: /action required/i, weight: 0.8, category: "Urgency" },
  { pattern: /within \d+ (hour|day)/i, weight: 0.7, category: "Urgency" },
  { pattern: /expire[sd]? (in|within|today)/i, weight: 0.8, category: "Urgency" },
  { pattern: /limited time/i, weight: 0.5, category: "Urgency" },
  { pattern: /act now/i, weight: 0.7, category: "Urgency" },
  { pattern: /final (notice|warning|reminder)/i, weight: 0.8, category: "Urgency" },
  { pattern: /last chance/i, weight: 0.6, category: "Urgency" },

  // Impersonation signals
  { pattern: /dear (valued |trusted )?(customer|user|member|client)/i, weight: 0.5, category: "Impersonation" },
  { pattern: /from the (security|it|support|help) (team|department|desk)/i, weight: 0.6, category: "Impersonation" },
  { pattern: /official (notice|communication|email|message)/i, weight: 0.5, category: "Impersonation" },
  { pattern: /no.?reply@/i, weight: 0.4, category: "Impersonation" },
  { pattern: /do not (reply|respond) to this (email|message)/i, weight: 0.3, category: "Impersonation" },

  // Financial / prize scams
  { pattern: /you (have|'ve) won/i, weight: 0.9, category: "Scam" },
  { pattern: /claim your (prize|reward|gift|money)/i, weight: 0.9, category: "Scam" },
  { pattern: /\$\d+[\d,]* (million|thousand|reward|prize)/i, weight: 0.9, category: "Scam" },
  { pattern: /wire transfer/i, weight: 0.8, category: "Financial Fraud" },
  { pattern: /bank account (details|information|number)/i, weight: 0.9, category: "Financial Fraud" },
  { pattern: /western union|money gram/i, weight: 0.8, category: "Financial Fraud" },
  { pattern: /inheritance|next of kin/i, weight: 0.9, category: "Scam" },

  // Malware / delivery
  { pattern: /download (the )?(attached|attachment|file|document)/i, weight: 0.7, category: "Malware Delivery" },
  { pattern: /open (the )?(attached|attachment)/i, weight: 0.7, category: "Malware Delivery" },
  { pattern: /enable (macros|content|editing)/i, weight: 1.0, category: "Malware Delivery" },
  { pattern: /invoice (attached|enclosed|below)/i, weight: 0.5, category: "Malware Delivery" },

  // Privacy / security threats
  { pattern: /we (detected|noticed|found) (unusual|suspicious|unauthorized) activity/i, weight: 0.8, category: "Fear Tactics" },
  { pattern: /your (account|computer|device) (has been|is) (hacked|compromised|infected)/i, weight: 0.9, category: "Fear Tactics" },
  { pattern: /virus (detected|found|identified)/i, weight: 0.8, category: "Fear Tactics" },
  { pattern: /security (breach|alert|warning|issue)/i, weight: 0.6, category: "Fear Tactics" },

  // Generic deception
  { pattern: /click (the|this|below) link/i, weight: 0.6, category: "Deceptive CTA" },
  { pattern: /http[s]?:\/\/[^\s]{0,20}(bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly)/i, weight: 0.9, category: "URL Obfuscation" },
  { pattern: /\bfree\b.{0,20}\b(gift|offer|trial|access|download)\b/i, weight: 0.5, category: "Scam" },
];

// ─── Suspicious TLD list ──────────────────────────────────────────────────────
const SUSPICIOUS_TLDS = new Set([
  "xyz", "top", "click", "loan", "win", "gq", "ml", "cf", "tk",
  "pw", "cc", "su", "icu", "buzz", "monster", "cyou", "shop",
]);

// ─── URL regex ────────────────────────────────────────────────────────────────
const URL_REGEX = /https?:\/\/[^\s"'<>]+/gi;

// ─── Main Feature Extractor ───────────────────────────────────────────────────

/**
 * @param {object} emailData
 * @returns {{ vector: number[], labels: string[], details: object }}
 */
export function extractFeatures(emailData) {
  const {
    from = "",
    subject = "",
    returnPath = "",
    authentication = {},
    body = "",
    rawHeaders = "",
  } = emailData;

  const subjectStr = String(subject || "");
  const bodyStr = String(body || "");
  const fromStr = String(from || "");
  const returnPathStr = String(returnPath || "");
  const authObj = authentication || {};

  // ── Auth features ─────────────────────────────────────────────
  const spfFail    = authObj.spf === "fail"    ? 1 : 0;
  const dkimFail   = authObj.dkim === "fail"   ? 1 : 0;
  const dmarcFail  = authObj.dmarc === "fail"  ? 1 : 0;
  const spfUnk     = authObj.spf === "unknown" ? 1 : 0;
  const dkimUnk    = authObj.dkim === "unknown"? 1 : 0;
  const dmarcUnk   = authObj.dmarc === "unknown"? 1: 0;
  const authFailCount = (spfFail + dkimFail + dmarcFail) / 3;
  const hasNoAuth  = (spfUnk && dkimUnk && dmarcUnk) ? 1 : 0;

  // ── Return-Path features ──────────────────────────────────────
  const fromDomain = extractDomain(fromStr);
  const rpDomain   = extractDomain(returnPathStr);
  const returnPathMismatch = (fromDomain && rpDomain && fromDomain !== rpDomain) ? 1 : 0;
  const returnPathMissing  = (!returnPathStr || returnPathStr === "Not Present") ? 1 : 0;

  // ── Subject features ──────────────────────────────────────────
  const urgencyWords = [
    "urgent", "immediately", "asap", "now", "today", "alert",
    "warning", "critical", "important", "required", "action",
    "expire", "suspended", "disabled", "verify", "confirm", "reset",
  ];
  const subjectLower = subjectStr.toLowerCase();
  const urgencyCount = urgencyWords.filter(w => subjectLower.includes(w)).length;
  const subjectUrgency = Math.min(urgencyCount / 4, 1);

  const capsCount = (subjectStr.match(/[A-Z]/g) || []).length;
  const subjectCapsRatio = subjectStr.length > 0 ? Math.min(capsCount / subjectStr.length, 1) : 0;
  const subjectLength = Math.min(subjectStr.length / 200, 1);
  const exclamations = Math.min((subjectStr.match(/!/g) || []).length / 5, 1);
  const questions    = Math.min((subjectStr.match(/\?/g) || []).length / 3, 1);

  // ── Phishing keyword score ────────────────────────────────────
  const fullText = subjectStr + " " + bodyStr;
  const phishingHits = PHISHING_KEYWORDS
    .filter(({ pattern }) => pattern.test(fullText))
    .map(({ weight }) => weight);
  const rawPhishScore = phishingHits.reduce((sum, w) => sum + w, 0);
  const phishingKeywordScore = Math.min(rawPhishScore / 3, 1); // cap at 1.0

  // ── Domain suspicion ─────────────────────────────────────────
  const fromTLD = (fromDomain || "").split(".").pop()?.toLowerCase() || "";
  const fromDomainSuspicious = SUSPICIOUS_TLDS.has(fromTLD) ? 1 : 0;

  // ── Body features ─────────────────────────────────────────────
  const urls = (bodyStr.match(URL_REGEX) || []);
  const bodyUrlCount = Math.min(urls.length / 10, 1);
  const bodyLength   = Math.min(bodyStr.length / 2000, 1);

  // ── Header anomaly ────────────────────────────────────────────
  const fromHeaderCount = (rawHeaders.match(/^From:/gim) || []).length;
  const multipleFromHeaders = fromHeaderCount > 1 ? 1 : 0;

  // ── Assemble vector ───────────────────────────────────────────
  const vector = [
    spfFail,               // 0
    dkimFail,              // 1
    dmarcFail,             // 2
    spfUnk,                // 3
    dkimUnk,               // 4
    dmarcUnk,              // 5
    returnPathMismatch,    // 6
    returnPathMissing,     // 7
    subjectUrgency,        // 8
    subjectCapsRatio,      // 9
    subjectLength,         // 10
    phishingKeywordScore,  // 11
    hasNoAuth,             // 12
    authFailCount,         // 13
    fromDomainSuspicious,  // 14
    exclamations,          // 15
    questions,             // 16
    bodyUrlCount,          // 17
    bodyLength,            // 18
    multipleFromHeaders,   // 19
  ];

  // ── Keyword details (for UI) ──────────────────────────────────
  const keywordMatches = PHISHING_KEYWORDS
    .filter(({ pattern }) => pattern.test(fullText))
    .map(({ pattern, weight, category }) => ({
      category,
      weight,
      match: fullText.match(pattern)?.[0]?.slice(0, 80) || "detected",
    }));

  const details = {
    authFailCount: spfFail + dkimFail + dmarcFail,
    returnPathMismatch: !!returnPathMismatch,
    urgencyCount,
    subjectCapsRatio: +(subjectCapsRatio * 100).toFixed(1),
    phishingKeywordScore: +rawPhishScore.toFixed(2),
    keywordMatches,
    urlsFound: urls.slice(0, 5),
    fromDomain,
    rpDomain,
    fromDomainSuspicious: !!fromDomainSuspicious,
  };

  return { vector, details };
}

// ─── Helper ───────────────────────────────────────────────────────────────────
function extractDomain(str) {
  const match = str.match(/@([a-zA-Z0-9._-]+)/);
  return match ? match[1].toLowerCase().replace(/[<>]/g, "") : null;
}
