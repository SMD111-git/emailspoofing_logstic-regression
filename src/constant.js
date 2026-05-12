export const SPOOFING_SCORE_WEIGHTS = {
  SPF_FAIL: 40,
  DKIM_FAIL: 40,
  DMARC_FAIL: 40,
};

export const RISK_LEVELS = {
  LEGITIMATE: { max: 0, label: "Legitimate", color: "green" },
  LOW: { max: 40, label: "Low Risk", color: "yellow" },
  MEDIUM: { max: 80, label: "Medium Risk", color: "orange" },
  HIGH: { max: 120, label: "High Risk", color: "red" },
};
