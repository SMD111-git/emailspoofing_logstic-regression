import express from "express";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import emailRouter from "./routes/Email.route.js";
import { modelManager } from "./ml/model.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const app = express();

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors({ origin: process.env.CORS_ORIGIN || "*", credentials: true }));
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static(path.join(__dirname, "../public")));

// ─── Routes ───────────────────────────────────────────────────────────────────
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "OK",
    timestamp: new Date().toISOString(),
    service: "Email Spoofing Detection API",
    version: "2.0.0",
    ml: modelManager.getStatus(),
  });
});

app.get("/api", (req, res) => {
  res.status(200).json({
    message: "Email Spoofing Detection API v2.0",
    endpoints: {
      health:      "GET  /health",
      analyze:     "POST /api/v1/email/emailchecking",
      modelStatus: "GET  /api/v1/email/model-status",
      retrain:     "POST /api/v1/email/retrain",
    },
  });
});

app.use("/api/v1/email", emailRouter);

// Serve frontend for all other routes
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/index.html"));
});

// ─── Global error handler ─────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  res.status(err.statusCode || 500).json({
    statusCode: err.statusCode || 500,
    message:    err.message || "Internal Server Error",
    success:    false,
    errors:     err.errors || [],
  });
});

// ─── ML model initialization ──────────────────────────────────────────────────
modelManager.initialize().catch(err => {
  console.error("⚠️  ML model initialization failed:", err.message);
});

export { app };
