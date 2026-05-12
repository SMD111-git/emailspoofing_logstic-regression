import { simpleParser } from "mailparser";
import { asyncHandler } from "../utils/asynchandler.js";
import { ApiResponse } from "../utils/Apiresponse.js";
import { ApiError } from "../utils/Apierror.js";
import { detectMitreTechniques } from "../middlewares/Mitreattack.js";
import { SPOOFING_SCORE_WEIGHTS } from "../constant.js";
import { extractFeatures } from "../ml/featureExtractor.js";
import { detectPhishingKeywords } from "../ml/keywordDetector.js";
import { modelManager } from "../ml/model.js";

// ─── Auth parsing ─────────────────────────────────────────────────────────────

function parseAuthResults(authHeader) {
  if (!authHeader) return { spf: "unknown", dkim: "unknown", dmarc: "unknown" };
  const auth = authHeader.toLowerCase();
  const extract = (proto) => {
    const m = auth.match(new RegExp(`${proto}=([a-z]+)`));
    return m ? m[1] : "unknown";
  };
  return { spf: extract("spf"), dkim: extract("dkim"), dmarc: extract("dmarc") };
}

function calculateSpoofingScore(auth) {
  let score = 0;
  if (auth.spf === "fail")   score += SPOOFING_SCORE_WEIGHTS.SPF_FAIL;
  if (auth.dkim === "fail")  score += SPOOFING_SCORE_WEIGHTS.DKIM_FAIL;
  if (auth.dmarc === "fail") score += SPOOFING_SCORE_WEIGHTS.DMARC_FAIL;
  return score;
}

function getRiskLevel(score) {
  if (score === 0)   return { level: "Legitimate",   severity: "safe",   emoji: "✅" };
  if (score <= 40)   return { level: "Low Risk",      severity: "low",    emoji: "⚠️" };
  if (score <= 80)   return { level: "Medium Risk",   severity: "medium", emoji: "🔶" };
  return               { level: "High Risk",      severity: "high",   emoji: "🚨" };
}

function extractHeaderValue(raw, name) {
  const m = raw.match(new RegExp(`^${name}:\\s*(.+)`, "im"));
  return m ? m[1].trim() : null;
}

// ─── Unified threat fusion ────────────────────────────────────────────────────

function buildUnifiedThreatScore(spoofingScore, mlProb, keywordRisk) {
  const authNorm = (spoofingScore / 120) * 100;
  const combined = (authNorm * 0.40) + (mlProb * 0.40) + (keywordRisk * 0.20);
  return +combined.toFixed(1);
}

function getUnifiedRiskLabel(score) {
  if (score < 15)  return { label: "Legitimate",      severity: "safe",     emoji: "✅" };
  if (score < 35)  return { label: "Low Risk",         severity: "low",      emoji: "⚠️" };
  if (score < 60)  return { label: "Suspicious",       severity: "medium",   emoji: "🔶" };
  if (score < 80)  return { label: "Likely Spoofed",   severity: "high",     emoji: "🚨" };
  return              { label: "Definite Attack",   severity: "critical", emoji: "🔴" };
}

// ─── Main analysis endpoint ───────────────────────────────────────────────────

export const analyzeEmail = asyncHandler(async (req, res) => {
  let rawEmail = req.body?.rawEmail;
  const header = req.body?.header;

  if (!rawEmail && !header && req.file) {
    rawEmail = req.file.buffer.toString("utf8");
  }

  const emailContent = rawEmail || header;
  if (!emailContent) {
    throw new ApiError(400, "Raw email, headers, or .eml file attachment are required");
  }

  let parsed;
  try {
    parsed = await simpleParser(emailContent);
  } catch (error) {
    throw new ApiError(400, "Failed to parse email", [error.message]);
  }

  const authHeader =
    parsed.headers?.get("authentication-results") ||
    extractHeaderValue(emailContent, "Authentication-Results");

  const returnPath =
    parsed.headers?.get("return-path") ||
    extractHeaderValue(emailContent, "Return-Path") ||
    "Not Present";

  const authentication = parseAuthResults(authHeader);
  const spoofingScore  = calculateSpoofingScore(authentication);
  const riskLevel      = getRiskLevel(spoofingScore);

  const fromText    = parsed.from?.text || extractHeaderValue(emailContent, "From") || "unknown";
  const subjectText = parsed.subject || extractHeaderValue(emailContent, "Subject") || "No Subject";
  const bodyText    = parsed.text || "";

  const emailData = {
    from: fromText, subject: subjectText, returnPath,
    body: bodyText, authentication, spoofingScore, rawHeaders: emailContent,
  };

  // ── Feature extraction ────────────────────────────────────────
  const { vector, details: featureDetails } = extractFeatures(emailData);

  // ── ML classification ─────────────────────────────────────────
  let mlResult = null;
  try {
    mlResult = modelManager.infer(vector);
  } catch (err) {
    console.warn("ML inference skipped:", err.message);
  }

  // ── Keyword detection ─────────────────────────────────────────
  const keywordResult = detectPhishingKeywords({ subject: subjectText, body: bodyText });

  // ── Unified threat score ──────────────────────────────────────
  const unifiedScore = buildUnifiedThreatScore(
    spoofingScore,
    mlResult?.probability ?? (spoofingScore / 120 * 100),
    keywordResult.riskScore,
  );
  const unifiedRisk = getUnifiedRiskLabel(unifiedScore);

  // ── MITRE ATT&CK ──────────────────────────────────────────────
  const mitreAnalysis = detectMitreTechniques(emailData);

  return res.status(200).json(new ApiResponse(200, {
    from:        parsed.from || fromText,
    to:          parsed.to   || extractHeaderValue(emailContent, "To") || "unknown",
    subject:     subjectText,
    returnPath,
    date:        parsed.date || new Date().toISOString(),
    authentication,
    spoofingScore,
    riskLevel,

    ml: {
      classification: mlResult ? {
        spoofingProbability: mlResult.probability,
        label:               mlResult.label,
        confidence:          mlResult.confidence,
        verdict:             mlResult.label === 1 ? "Spoofed / Phishing" : "Likely Legitimate",
      } : null,

      keywordDetection: {
        riskScore:        keywordResult.riskScore,
        riskLabel:        keywordResult.riskLabel,
        riskSeverity:     keywordResult.riskSeverity,
        totalHits:        keywordResult.totalHits,
        uniqueCategories: keywordResult.uniqueCategories,
        topCategories:    keywordResult.topCategories,
        hits:             keywordResult.hits,
      },

      featureVector: {
        spfFail:              vector[0],
        dkimFail:             vector[1],
        dmarcFail:            vector[2],
        returnPathMismatch:   vector[6],
        subjectUrgency:       +vector[8].toFixed(3),
        subjectCapsRatio:     +vector[9].toFixed(3),
        phishingKeywordScore: +vector[11].toFixed(3),
        authFailCount:        +(vector[13] * 3).toFixed(0),
        fromDomainSuspicious: vector[14],
        bodyUrlCount:         +(vector[17] * 10).toFixed(0),
      },

      details: featureDetails,
    },

    unifiedThreat: {
      score:    unifiedScore,
      label:    unifiedRisk.label,
      severity: unifiedRisk.severity,
      emoji:    unifiedRisk.emoji,
      breakdown: {
        authScore:    +(spoofingScore / 120 * 100).toFixed(1),
        mlScore:      mlResult?.probability ?? null,
        keywordScore: keywordResult.riskScore,
      },
    },

    mitreAttack: mitreAnalysis,
  }, "Email analyzed successfully"));
});

// ─── Model status ─────────────────────────────────────────────────────────────

export const getModelStatus = asyncHandler(async (req, res) => {
  return res.status(200).json(
    new ApiResponse(200, modelManager.getStatus(), "Model status retrieved")
  );
});

// ─── Retrain ──────────────────────────────────────────────────────────────────

export const retrainModel = asyncHandler(async (req, res) => {
  const { samples = 600 } = req.body || {};
  if (samples < 100 || samples > 5000) {
    throw new ApiError(400, "Sample count must be between 100 and 5000");
  }
  const metrics = await modelManager.retrain(Number(samples));
  return res.status(200).json(
    new ApiResponse(200, metrics, "Model retrained successfully")
  );
});
