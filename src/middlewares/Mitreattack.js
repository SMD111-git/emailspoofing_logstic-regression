/**
 * MITRE ATT&CK Framework - Email Spoofing Detection
 * Full implementation covering all relevant techniques and sub-techniques
 * Reference: https://attack.mitre.org/
 */

// ─── Complete MITRE ATT&CK Technique Database ────────────────────────────────

const MITRE_TECHNIQUES = {
  // Initial Access
  "T1566": {
    id: "T1566",
    name: "Phishing",
    tactic: "Initial Access",
    tacticId: "TA0001",
    description: "Adversaries send phishing messages to gain access to victim systems. Phishing is a common method used in conjunction with email spoofing.",
    url: "https://attack.mitre.org/techniques/T1566",
    subtechniques: {
      "T1566.001": {
        id: "T1566.001",
        name: "Spearphishing Attachment",
        description: "Adversaries send spearphishing emails with a malicious attachment to gain access to victim systems.",
        url: "https://attack.mitre.org/techniques/T1566/001",
      },
      "T1566.002": {
        id: "T1566.002",
        name: "Spearphishing Link",
        description: "Adversaries send spearphishing emails with a malicious link to gain access to victim systems.",
        url: "https://attack.mitre.org/techniques/T1566/002",
      },
      "T1566.003": {
        id: "T1566.003",
        name: "Spearphishing via Service",
        description: "Adversaries send spearphishing messages via third-party services to gain access to victim systems.",
        url: "https://attack.mitre.org/techniques/T1566/003",
      },
    },
  },

  // Defense Evasion
  "T1036": {
    id: "T1036",
    name: "Masquerading",
    tactic: "Defense Evasion",
    tacticId: "TA0005",
    description: "Adversaries attempt to manipulate features of artifacts to make them appear legitimate.",
    url: "https://attack.mitre.org/techniques/T1036",
    subtechniques: {
      "T1036.005": {
        id: "T1036.005",
        name: "Match Legitimate Name or Location",
        description: "Adversaries match or approximate the name or location of legitimate files to evade detection.",
        url: "https://attack.mitre.org/techniques/T1036/005",
      },
      "T1036.006": {
        id: "T1036.006",
        name: "Space after Filename",
        description: "Adversaries append spaces in filenames to confuse automated analysis tools.",
        url: "https://attack.mitre.org/techniques/T1036/006",
      },
    },
  },

  // Collection
  "T1114": {
    id: "T1114",
    name: "Email Collection",
    tactic: "Collection",
    tacticId: "TA0009",
    description: "Adversaries may target user email to collect sensitive information.",
    url: "https://attack.mitre.org/techniques/T1114",
    subtechniques: {
      "T1114.001": {
        id: "T1114.001",
        name: "Local Email Collection",
        description: "Adversaries may target user email on local systems to collect sensitive information.",
        url: "https://attack.mitre.org/techniques/T1114/001",
      },
      "T1114.002": {
        id: "T1114.002",
        name: "Remote Email Collection",
        description: "Adversaries may target an Exchange server, Office 365, or Google Workspace to collect sensitive information.",
        url: "https://attack.mitre.org/techniques/T1114/002",
      },
      "T1114.003": {
        id: "T1114.003",
        name: "Email Forwarding Rule",
        description: "Adversaries may setup email forwarding rules to collect sensitive information.",
        url: "https://attack.mitre.org/techniques/T1114/003",
      },
    },
  },

  // Credential Access
  "T1078": {
    id: "T1078",
    name: "Valid Accounts",
    tactic: "Credential Access",
    tacticId: "TA0006",
    description: "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access.",
    url: "https://attack.mitre.org/techniques/T1078",
    subtechniques: {
      "T1078.002": {
        id: "T1078.002",
        name: "Domain Accounts",
        description: "Adversaries may obtain and abuse credentials of a domain account.",
        url: "https://attack.mitre.org/techniques/T1078/002",
      },
      "T1078.004": {
        id: "T1078.004",
        name: "Cloud Accounts",
        description: "Adversaries may obtain and abuse credentials of cloud accounts.",
        url: "https://attack.mitre.org/techniques/T1078/004",
      },
    },
  },

  // Impact
  "T1565": {
    id: "T1565",
    name: "Data Manipulation",
    tactic: "Impact",
    tacticId: "TA0040",
    description: "Adversaries may insert, delete, or manipulate data to influence external outcomes or hide activity.",
    url: "https://attack.mitre.org/techniques/T1565",
    subtechniques: {
      "T1565.001": {
        id: "T1565.001",
        name: "Stored Data Manipulation",
        description: "Adversaries may insert, delete, or manipulate data at rest in order to manipulate external outcomes.",
        url: "https://attack.mitre.org/techniques/T1565/001",
      },
    },
  },

  // Exfiltration
  "T1048": {
    id: "T1048",
    name: "Exfiltration Over Alternative Protocol",
    tactic: "Exfiltration",
    tacticId: "TA0010",
    description: "Adversaries may steal data by exfiltrating it over a different protocol than that of the existing C2 channel.",
    url: "https://attack.mitre.org/techniques/T1048",
    subtechniques: {
      "T1048.003": {
        id: "T1048.003",
        name: "Exfiltration Over Unencrypted Non-C2 Protocol",
        description: "Adversaries may steal data by exfiltrating it over an unencrypted network protocol.",
        url: "https://attack.mitre.org/techniques/T1048/003",
      },
    },
  },

  // Reconnaissance
  "T1598": {
    id: "T1598",
    name: "Phishing for Information",
    tactic: "Reconnaissance",
    tacticId: "TA0043",
    description: "Adversaries may send phishing messages to elicit sensitive information that can be used during targeting.",
    url: "https://attack.mitre.org/techniques/T1598",
    subtechniques: {
      "T1598.001": {
        id: "T1598.001",
        name: "Spearphishing Service",
        description: "Adversaries may send spearphishing messages via third-party services to elicit sensitive information.",
        url: "https://attack.mitre.org/techniques/T1598/001",
      },
      "T1598.002": {
        id: "T1598.002",
        name: "Spearphishing Attachment",
        description: "Adversaries may send spearphishing messages with a malicious attachment to elicit sensitive information.",
        url: "https://attack.mitre.org/techniques/T1598/002",
      },
      "T1598.003": {
        id: "T1598.003",
        name: "Spearphishing Link",
        description: "Adversaries may send spearphishing messages with a malicious link to elicit sensitive information.",
        url: "https://attack.mitre.org/techniques/T1598/003",
      },
    },
  },

  // Resource Development
  "T1583": {
    id: "T1583",
    name: "Acquire Infrastructure",
    tactic: "Resource Development",
    tacticId: "TA0042",
    description: "Adversaries may buy, lease, rent, or obtain infrastructure that can be used during targeting.",
    url: "https://attack.mitre.org/techniques/T1583",
    subtechniques: {
      "T1583.001": {
        id: "T1583.001",
        name: "Domains",
        description: "Adversaries may purchase domains that can be used during targeting.",
        url: "https://attack.mitre.org/techniques/T1583/001",
      },
      "T1583.002": {
        id: "T1583.002",
        name: "DNS Server",
        description: "Adversaries may set up their own DNS servers to be used during targeting.",
        url: "https://attack.mitre.org/techniques/T1583/002",
      },
      "T1583.006": {
        id: "T1583.006",
        name: "Web Services",
        description: "Adversaries may register for web services that can be used to further their operations.",
        url: "https://attack.mitre.org/techniques/T1583/006",
      },
    },
  },

  // Identity-based attacks
  "T1656": {
    id: "T1656",
    name: "Impersonation",
    tactic: "Defense Evasion",
    tacticId: "TA0005",
    description: "Adversaries may impersonate a trusted person or organization to deceive and manipulate victims.",
    url: "https://attack.mitre.org/techniques/T1656",
    subtechniques: {},
  },
};

// ─── MITRE Detection Rules ────────────────────────────────────────────────────

/**
 * Analyze email headers and authentication results to detect MITRE ATT&CK techniques
 */
function detectMitreTechniques(emailData) {
  const detectedTechniques = [];
  const {
    from,
    returnPath,
    authentication,
    subject,
    spoofingScore,
    rawHeaders,
  } = emailData;

  const spfFailed = authentication?.spf === "fail" || authentication?.spf === "unknown";
  const dkimFailed = authentication?.dkim === "fail" || authentication?.dkim === "unknown";
  const dmarcFailed = authentication?.dmarc === "fail" || authentication?.dmarc === "unknown";

  const fromAddress = (typeof from === "string" ? from : from?.text || "").toLowerCase();
  const returnPathStr = (returnPath || "").toLowerCase();
  const subjectStr = (subject || "").toLowerCase();

  const hasMismatchedReturnPath =
    returnPathStr &&
    fromAddress &&
    !returnPathStr.includes(fromAddress.split("@")[1] || "");

  const hasUrgentKeywords = /urgent|reset|suspend|verify|confirm|immediately|click here|account|password|secure|update/i.test(subjectStr);

  // ── T1566: Phishing ──────────────────────────────────────────────
  if (spfFailed || dkimFailed || dmarcFailed) {
    const technique = buildTechnique(MITRE_TECHNIQUES["T1566"], {
      confidence: calculateConfidence([spfFailed, dkimFailed, dmarcFailed]),
      evidence: buildEvidence({ spfFailed, dkimFailed, dmarcFailed }),
      subtechniques: [],
      detectionMethod: "Email authentication header analysis (SPF/DKIM/DMARC)",
      mitigations: [
        "M1054 - Software Configuration: Implement SPF, DKIM, and DMARC records",
        "M1049 - Antivirus/Antimalware: Use email security gateways",
        "M1017 - User Training: Train users to identify phishing attempts",
      ],
    });

    // Add subtechniques based on content
    if (hasUrgentKeywords) {
      technique.matchedSubtechniques.push(MITRE_TECHNIQUES["T1566"].subtechniques["T1566.002"]);
    }
    if (hasMismatchedReturnPath) {
      technique.matchedSubtechniques.push(MITRE_TECHNIQUES["T1566"].subtechniques["T1566.001"]);
    }

    detectedTechniques.push(technique);
  }

  // ── T1036: Masquerading ──────────────────────────────────────────
  if (hasMismatchedReturnPath || (spfFailed && !dkimFailed)) {
    detectedTechniques.push(
      buildTechnique(MITRE_TECHNIQUES["T1036"], {
        confidence: hasMismatchedReturnPath ? "High" : "Medium",
        evidence: [
          hasMismatchedReturnPath
            ? `Return-Path domain differs from From domain: From(${fromAddress}) vs Return-Path(${returnPathStr})`
            : "SPF failure indicates sender IP mismatch with declared domain",
        ],
        matchedSubtechniques: [MITRE_TECHNIQUES["T1036"].subtechniques["T1036.005"]],
        detectionMethod: "Header field cross-correlation and domain analysis",
        mitigations: [
          "M1054 - Software Configuration: Enable strict DMARC policy (p=reject)",
          "M1038 - Execution Prevention: Deploy email header inspection rules",
        ],
      })
    );
  }

  // ── T1598: Phishing for Information ─────────────────────────────
  if (hasUrgentKeywords && (spfFailed || dkimFailed)) {
    const subTechs = [];
    if (hasMismatchedReturnPath) subTechs.push(MITRE_TECHNIQUES["T1598"].subtechniques["T1598.002"]);
    subTechs.push(MITRE_TECHNIQUES["T1598"].subtechniques["T1598.003"]);

    detectedTechniques.push(
      buildTechnique(MITRE_TECHNIQUES["T1598"], {
        confidence: "High",
        evidence: [
          `Subject contains urgency/credential-harvesting keywords: "${subject}"`,
          "Authentication failures corroborate malicious sender identity",
        ],
        matchedSubtechniques: subTechs,
        detectionMethod: "Subject line keyword analysis combined with authentication failure correlation",
        mitigations: [
          "M1017 - User Training: Security awareness training on social engineering",
          "M1054 - Software Configuration: Email filtering rules for urgency keywords",
          "M1021 - Restrict Web-Based Content: Block suspicious redirects",
        ],
      })
    );
  }

  // ── T1583: Acquire Infrastructure (Domain Spoofing) ─────────────
  if (spfFailed && dmarcFailed) {
    detectedTechniques.push(
      buildTechnique(MITRE_TECHNIQUES["T1583"], {
        confidence: dmarcFailed && spfFailed ? "High" : "Medium",
        evidence: [
          "SPF failure: Sending IP not authorized for claimed domain",
          dmarcFailed ? "DMARC failure: Domain policy violated — likely unauthorized infrastructure" : null,
        ].filter(Boolean),
        matchedSubtechniques: [
          MITRE_TECHNIQUES["T1583"].subtechniques["T1583.001"],
          MITRE_TECHNIQUES["T1583"].subtechniques["T1583.002"],
        ],
        detectionMethod: "SPF/DMARC failure analysis for unauthorized infrastructure usage",
        mitigations: [
          "M1056 - Pre-compromise: Monitor for lookalike domain registrations",
          "M1054 - Software Configuration: Implement strict SPF with -all mechanism",
          "M1031 - Network Intrusion Prevention: Block spoofed domain traffic",
        ],
      })
    );
  }

  // ── T1656: Impersonation ─────────────────────────────────────────
  if (hasMismatchedReturnPath || (spfFailed && dkimFailed)) {
    detectedTechniques.push(
      buildTechnique(MITRE_TECHNIQUES["T1656"], {
        confidence: spfFailed && dkimFailed ? "High" : "Medium",
        evidence: [
          "Email sender identity cannot be cryptographically verified",
          hasMismatchedReturnPath
            ? "Return-Path mismatch indicates deliberate identity concealment"
            : "Multiple authentication failures indicate impersonation attempt",
        ],
        matchedSubtechniques: [],
        detectionMethod: "Cross-validation of From, Return-Path, and DKIM signing domain",
        mitigations: [
          "M1054 - Software Configuration: Deploy DMARC with p=quarantine or p=reject",
          "M1017 - User Training: Train staff to verify sender identity via secondary channel",
          "M1049 - Antivirus/Antimalware: Use AI-based email impersonation detection",
        ],
      })
    );
  }

  // ── T1114: Email Collection (if all auth fails — likely account compromise) ─
  if (spfFailed && dkimFailed && dmarcFailed) {
    detectedTechniques.push(
      buildTechnique(MITRE_TECHNIQUES["T1114"], {
        confidence: "High",
        evidence: [
          "Total authentication failure (SPF+DKIM+DMARC) indicates high-confidence spoofing or account compromise",
          "Attacker may be harvesting responses from compromised or spoofed mailbox",
        ],
        matchedSubtechniques: [
          MITRE_TECHNIQUES["T1114"].subtechniques["T1114.002"],
          MITRE_TECHNIQUES["T1114"].subtechniques["T1114.003"],
        ],
        detectionMethod: "Combined authentication failure analysis indicating active account exploitation",
        mitigations: [
          "M1032 - Multi-factor Authentication: Enforce MFA on all email accounts",
          "M1041 - Encrypt Sensitive Information: Encrypt mailbox data at rest",
          "M1054 - Software Configuration: Disable legacy email protocols (POP3/IMAP without MFA)",
        ],
      })
    );
  }

  // ── T1078: Valid Accounts (credential phishing) ──────────────────
  if (hasUrgentKeywords && spfFailed) {
    detectedTechniques.push(
      buildTechnique(MITRE_TECHNIQUES["T1078"], {
        confidence: dkimFailed ? "High" : "Medium",
        evidence: [
          "Email content suggests credential harvesting (urgency + authentication failure)",
          `Subject "${subject}" uses social engineering to prompt credential submission`,
        ],
        matchedSubtechniques: [
          MITRE_TECHNIQUES["T1078"].subtechniques["T1078.002"],
          MITRE_TECHNIQUES["T1078"].subtechniques["T1078.004"],
        ],
        detectionMethod: "Subject keyword analysis correlated with authentication failure",
        mitigations: [
          "M1032 - Multi-factor Authentication: Enforce MFA to prevent credential reuse",
          "M1036 - Account Use Policies: Implement account lockout and anomaly detection",
          "M1017 - User Training: Educate users about credential phishing indicators",
        ],
      })
    );
  }

  // ── T1048: Exfiltration (if from domain is suspicious) ──────────
  if (hasMismatchedReturnPath && dmarcFailed) {
    detectedTechniques.push(
      buildTechnique(MITRE_TECHNIQUES["T1048"], {
        confidence: "Medium",
        evidence: [
          "Mismatched Return-Path may route replies to attacker-controlled infrastructure",
          "DMARC failure with domain mismatch indicates potential exfiltration setup",
        ],
        matchedSubtechniques: [MITRE_TECHNIQUES["T1048"].subtechniques["T1048.003"]],
        detectionMethod: "Return-Path and Reply-To domain analysis for exfiltration routing",
        mitigations: [
          "M1031 - Network Intrusion Prevention: Monitor outbound email routing",
          "M1057 - Data Loss Prevention: Implement DLP on email gateways",
        ],
      })
    );
  }

  // ── T1565: Data Manipulation (header tampering) ──────────────────
  if (dkimFailed && spfFailed) {
    detectedTechniques.push(
      buildTechnique(MITRE_TECHNIQUES["T1565"], {
        confidence: "Medium",
        evidence: [
          "DKIM failure indicates email content or headers may have been tampered post-sending",
          "SPF failure corroborates unauthorized message injection",
        ],
        matchedSubtechniques: [MITRE_TECHNIQUES["T1565"].subtechniques["T1565.001"]],
        detectionMethod: "DKIM signature validation failure indicating header/body tampering",
        mitigations: [
          "M1041 - Encrypt Sensitive Information: Use end-to-end email encryption (S/MIME, PGP)",
          "M1054 - Software Configuration: Enable strict DKIM with short key rotation",
        ],
      })
    );
  }

  return {
    techniques: detectedTechniques,
    summary: buildMitreSummary(detectedTechniques, spoofingScore),
    tacticsTimeline: buildTacticsTimeline(detectedTechniques),
  };
}

// ─── Helper Functions ─────────────────────────────────────────────────────────

function buildTechnique(baseTechnique, extras) {
  return {
    id: baseTechnique.id,
    name: baseTechnique.name,
    tactic: baseTechnique.tactic,
    tacticId: baseTechnique.tacticId,
    url: baseTechnique.url,
    description: baseTechnique.description,
    confidence: extras.confidence || "Medium",
    evidence: extras.evidence || [],
    matchedSubtechniques: extras.matchedSubtechniques || [],
    detectionMethod: extras.detectionMethod || "",
    mitigations: extras.mitigations || [],
  };
}

function calculateConfidence(failureFlags) {
  const failCount = failureFlags.filter(Boolean).length;
  if (failCount === 3) return "High";
  if (failCount === 2) return "Medium";
  return "Low";
}

function buildEvidence({ spfFailed, dkimFailed, dmarcFailed }) {
  const evidence = [];
  if (spfFailed) evidence.push("SPF check failed — sending IP not authorized for domain");
  if (dkimFailed) evidence.push("DKIM check failed — email signature invalid or absent");
  if (dmarcFailed) evidence.push("DMARC check failed — domain policy violated");
  return evidence;
}

function buildMitreSummary(techniques, spoofingScore) {
  const tacticsSet = new Set(techniques.map((t) => t.tactic));
  const highConfidence = techniques.filter((t) => t.confidence === "High").length;

  let threatLevel = "None";
  let threatDescription = "No MITRE ATT&CK techniques detected. Email appears legitimate.";

  if (spoofingScore >= 120) {
    threatLevel = "Critical";
    threatDescription = "Email exhibits characteristics of a sophisticated multi-vector attack. Immediate action required.";
  } else if (spoofingScore >= 80) {
    threatLevel = "High";
    threatDescription = "Multiple attack techniques detected. High probability of malicious intent.";
  } else if (spoofingScore >= 40) {
    threatLevel = "Medium";
    threatDescription = "Suspicious patterns detected. Manual review recommended.";
  } else if (techniques.length > 0) {
    threatLevel = "Low";
    threatDescription = "Minor anomalies detected. Monitor for recurring patterns.";
  }

  return {
    threatLevel,
    threatDescription,
    totalTechniquesDetected: techniques.length,
    totalTacticsInvolved: tacticsSet.size,
    highConfidenceDetections: highConfidence,
    tacticsInvolved: Array.from(tacticsSet),
    attackPhases: mapToAttackPhases(techniques),
  };
}

function mapToAttackPhases(techniques) {
  const phaseOrder = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
  ];

  const phases = {};
  techniques.forEach((t) => {
    if (!phases[t.tactic]) phases[t.tactic] = [];
    phases[t.tactic].push({ id: t.id, name: t.name, confidence: t.confidence });
  });

  return phaseOrder
    .filter((phase) => phases[phase])
    .map((phase) => ({ phase, techniques: phases[phase] }));
}

function buildTacticsTimeline(techniques) {
  const tacticOrder = {
    "Reconnaissance": 1,
    "Resource Development": 2,
    "Initial Access": 3,
    "Defense Evasion": 4,
    "Credential Access": 5,
    "Collection": 6,
    "Exfiltration": 7,
    "Impact": 8,
  };

  return techniques
    .sort((a, b) => (tacticOrder[a.tactic] || 99) - (tacticOrder[b.tactic] || 99))
    .map((t) => ({
      phase: t.tactic,
      techniqueId: t.id,
      techniqueName: t.name,
      confidence: t.confidence,
    }));
}

// ─── Middleware Export ────────────────────────────────────────────────────────

export const mitreAttackAnalysis = (req, res, next) => {
  // Attach the analyzer to req so controller can use it after parsing
  req.mitreAnalyzer = detectMitreTechniques;
  next();
};

export { detectMitreTechniques };
