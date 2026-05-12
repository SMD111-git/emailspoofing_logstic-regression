/**
 * Phishing Keyword Detector
 * Runs against email subject + body text.
 * Returns categorized hits, risk score, and highlighted snippets.
 */

import { PHISHING_KEYWORDS } from "./featureExtractor.js";

/**
 * @param {{ subject: string, body: string }} emailData
 * @returns {PhishingKeywordResult}
 */
export function detectPhishingKeywords(emailData) {
  const subject = String(emailData.subject || "");
  const body    = String(emailData.body || "");
  const fullText = subject + "\n" + body;

  const hits = [];
  let totalScore = 0;

  for (const { pattern, weight, category } of PHISHING_KEYWORDS) {
    const match = fullText.match(pattern);
    if (match) {
      const snippet = getSnippet(fullText, match.index, match[0].length);
      hits.push({
        category,
        weight,
        matchedText: match[0].slice(0, 100),
        snippet,
        severity: weight >= 0.9 ? "critical" : weight >= 0.7 ? "high" : weight >= 0.5 ? "medium" : "low",
      });
      totalScore += weight;
    }
  }

  // Deduplicate by category — keep highest weight per category
  const byCategory = {};
  for (const hit of hits) {
    if (!byCategory[hit.category] || hit.weight > byCategory[hit.category].weight) {
      byCategory[hit.category] = hit;
    }
  }
  const uniqueHits = Object.values(byCategory);

  // Normalize score
  const normalizedScore = Math.min(totalScore / 4, 1);
  const riskScore = +(normalizedScore * 100).toFixed(1);

  // Category breakdown
  const categoryCounts = {};
  for (const hit of hits) {
    categoryCounts[hit.category] = (categoryCounts[hit.category] || 0) + 1;
  }

  // Risk label
  let riskLabel, riskSeverity;
  if (riskScore === 0)      { riskLabel = "Clean"; riskSeverity = "safe"; }
  else if (riskScore < 25)  { riskLabel = "Mild Concern"; riskSeverity = "low"; }
  else if (riskScore < 55)  { riskLabel = "Suspicious"; riskSeverity = "medium"; }
  else if (riskScore < 80)  { riskLabel = "Likely Phishing"; riskSeverity = "high"; }
  else                       { riskLabel = "Definite Phishing"; riskSeverity = "critical"; }

  return {
    hits: uniqueHits.sort((a, b) => b.weight - a.weight),
    totalHits: hits.length,
    uniqueCategories: Object.keys(byCategory).length,
    categoryCounts,
    riskScore,
    riskLabel,
    riskSeverity,
    topCategories: Object.entries(categoryCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([cat, count]) => ({ category: cat, count })),
  };
}

function getSnippet(text, index, matchLen, context = 40) {
  const start = Math.max(0, index - context);
  const end   = Math.min(text.length, index + matchLen + context);
  let snippet = text.slice(start, end).replace(/\n/g, " ");
  if (start > 0) snippet = "..." + snippet;
  if (end < text.length) snippet += "...";
  return snippet;
}
