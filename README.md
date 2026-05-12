# 🛡️ Email Spoofing Detection — Full Stack

A production-ready full-stack application that detects email spoofing using SPF, DKIM, and DMARC analysis, and maps threats to the **MITRE ATT&CK framework**.

---

## 🚀 Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Create .env (already included)
cp .env.example .env

# 3. Start the server
npm run dev       # development (auto-reload)
npm start         # production

# 4. Open in browser
http://localhost:8000
```

---

## 📁 Project Structure

```
emailspoofing/
├── public/
│   └── index.html                  ← Frontend UI (served automatically)
├── src/
│   ├── app.js                      ← Express app + CORS + static files
│   ├── index.js                    ← Server entry point
│   ├── constant.js                 ← Score weights & risk levels
│   ├── controllers/
│   │   └── Emailparser.js          ← Email parsing & scoring logic
│   ├── middlewares/
│   │   └── Mitreattack.js          ← 100% MITRE ATT&CK engine (8 techniques)
│   ├── routes/
│   │   └── Email.route.js          ← API routes + .eml file upload
│   └── utils/
│       ├── Apierror.js
│       ├── Apiresponse.js
│       └── asynchandler.js
├── .env
├── .env.example
└── package.json
```

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Frontend UI |
| GET | `/health` | Server health check |
| POST | `/api/v1/email/emailchecking` | Analyze email for spoofing |

### POST `/api/v1/email/emailchecking`

**Option 1 — JSON body (raw email):**
```json
{ "rawEmail": "From: sender@example.com\n..." }
```

**Option 2 — JSON body (headers only):**
```json
{ "header": "From: sender@example.com\n..." }
```

**Option 3 — File upload (`.eml`):**
```
multipart/form-data  field: emailFile
```

### Response Structure
```json
{
  "statusCode": 200,
  "success": true,
  "message": "Email analyzed successfully",
  "data": {
    "from": "sender@example.com",
    "to": "recipient@example.com",
    "subject": "Email subject",
    "returnPath": "<sender@example.com>",
    "date": "2026-01-01T00:00:00.000Z",
    "authentication": {
      "spf": "pass | fail | unknown",
      "dkim": "pass | fail | unknown",
      "dmarc": "pass | fail | unknown"
    },
    "spoofingScore": 0,
    "riskLevel": {
      "level": "Legitimate",
      "severity": "safe",
      "emoji": "✅"
    },
    "mitreAttack": {
      "techniques": [...],
      "summary": {
        "threatLevel": "None | Low | Medium | High | Critical",
        "threatDescription": "...",
        "totalTechniquesDetected": 0,
        "totalTacticsInvolved": 0,
        "highConfidenceDetections": 0,
        "tacticsInvolved": [],
        "attackPhases": []
      },
      "tacticsTimeline": [...]
    }
  }
}
```

---

## 📊 Spoofing Score

| Score | Risk Level | Meaning |
|-------|-----------|---------|
| 0 | ✅ Legitimate | All SPF + DKIM + DMARC passed |
| 40 | ⚠️ Low Risk | 1 check failed |
| 80 | 🔶 Medium Risk | 2 checks failed |
| 120 | 🚨 High Risk | All 3 checks failed |

Each failed check adds **40 points**:
- SPF fail → +40
- DKIM fail → +40
- DMARC fail → +40

---

## ⚔️ MITRE ATT&CK Coverage

The engine detects **8 techniques** across **6 tactics**:

| ID | Technique | Tactic | Triggers On |
|----|-----------|--------|-------------|
| T1566 | Phishing | Initial Access | Any auth failure |
| T1036 | Masquerading | Defense Evasion | Return-Path mismatch / SPF fail |
| T1598 | Phishing for Information | Reconnaissance | Urgent keywords + auth fail |
| T1583 | Acquire Infrastructure | Resource Development | SPF + DMARC fail |
| T1656 | Impersonation | Defense Evasion | Unverifiable sender identity |
| T1114 | Email Collection | Collection | All 3 auth checks fail |
| T1078 | Valid Accounts | Credential Access | Urgent keywords + SPF fail |
| T1048 | Exfiltration Over Alt Protocol | Exfiltration | Return-Path mismatch + DMARC fail |

Each detected technique includes:
- 🔍 **Evidence** — specific header analysis findings
- 🧩 **Sub-techniques** — matched ATT&CK sub-technique IDs
- 🛡️ **Mitigations** — MITRE M-series countermeasures
- 🔬 **Detection method** — how it was identified
- 🔗 **Link** to official MITRE ATT&CK page

---

## 🌐 Environment Variables

```env
PORT=8000          # Server port
CORS_ORIGIN=*      # Allowed CORS origins
NODE_ENV=development
```

---

## 🧪 Test Cases

```bash
# Legitimate email (score: 0)
curl -X POST http://localhost:8000/api/v1/email/emailchecking \
  -H "Content-Type: application/json" \
  -d '{"rawEmail":"From: legit@company.com\nAuthentication-Results: spf=pass dkim=pass dmarc=pass\n\nHello"}'

# High-risk spoofed email (score: 120)
curl -X POST http://localhost:8000/api/v1/email/emailchecking \
  -H "Content-Type: application/json" \
  -d '{"rawEmail":"From: admin@company.com\nReturn-Path: <hacker@evil.com>\nAuthentication-Results: spf=fail dkim=fail dmarc=fail\n\nURGENT: Reset your password!"}'
```

---

## 🛠️ Tech Stack

- **Express.js 4** — Web framework
- **mailparser** — RFC 2822 email parsing
- **multer** — `.eml` file upload
- **cors + dotenv** — Configuration
- **Vanilla JS frontend** — No build step required

---

## 📄 License

ISC
