/**
 * Logistic Regression Classifier
 * Pure JavaScript implementation — no runtime dependency on TensorFlow.
 *
 * Uses:
 *  - Sigmoid activation
 *  - Binary cross-entropy loss
 *  - Mini-batch gradient descent with L2 regularization
 *  - Feature standardization (z-score normalization)
 *  - Trained weights are persisted to disk and hot-reloaded on startup
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { generateTrainingData } from "./trainingData.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MODEL_PATH = path.join(__dirname, "model.weights.json");

const FEATURE_COUNT = 20;

// ─── Math helpers ─────────────────────────────────────────────────────────────

const sigmoid = (z) => 1 / (1 + Math.exp(-Math.max(-500, Math.min(500, z))));

function dot(weights, x) {
  return weights.reduce((sum, w, i) => sum + w * x[i], 0);
}

function predict(weights, bias, x) {
  return sigmoid(dot(weights, x) + bias);
}

// ─── Standardization ──────────────────────────────────────────────────────────

function computeScaler(X) {
  const n = X.length;
  const k = X[0].length;
  const mean = new Array(k).fill(0);
  const std  = new Array(k).fill(1);

  for (let j = 0; j < k; j++) {
    mean[j] = X.reduce((s, row) => s + row[j], 0) / n;
  }
  for (let j = 0; j < k; j++) {
    const variance = X.reduce((s, row) => s + (row[j] - mean[j]) ** 2, 0) / n;
    std[j] = Math.sqrt(variance) || 1;
  }
  return { mean, std };
}

function scaleRow(row, scaler) {
  return row.map((v, j) => (v - scaler.mean[j]) / scaler.std[j]);
}

function scaleMatrix(X, scaler) {
  return X.map(row => scaleRow(row, scaler));
}

// ─── Training ─────────────────────────────────────────────────────────────────

/**
 * Train logistic regression via mini-batch gradient descent
 * @param {{ X: number[][], y: number[] }} dataset
 * @returns {{ weights, bias, scaler, metrics }}
 */
export function trainModel(dataset) {
  const { X: rawX, y } = dataset;
  const scaler = computeScaler(rawX);
  const X = scaleMatrix(rawX, scaler);
  const n = X.length;

  // Hyperparameters
  const LR         = 0.1;
  const EPOCHS     = 500;
  const BATCH_SIZE = 32;
  const LAMBDA     = 0.01; // L2 regularization

  let weights = new Array(FEATURE_COUNT).fill(0).map(() => (Math.random() - 0.5) * 0.01);
  let bias    = 0;

  const lossHistory = [];

  for (let epoch = 0; epoch < EPOCHS; epoch++) {
    // Shuffle indices each epoch
    const indices = Array.from({ length: n }, (_, i) => i);
    for (let i = n - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [indices[i], indices[j]] = [indices[j], indices[i]];
    }

    for (let start = 0; start < n; start += BATCH_SIZE) {
      const batchIdx = indices.slice(start, start + BATCH_SIZE);
      const batchSize = batchIdx.length;

      const dW = new Array(FEATURE_COUNT).fill(0);
      let dB = 0;
      let batchLoss = 0;

      for (const i of batchIdx) {
        const pred = predict(weights, bias, X[i]);
        const err  = pred - y[i];
        const eps  = 1e-9;
        batchLoss += -(y[i] * Math.log(pred + eps) + (1 - y[i]) * Math.log(1 - pred + eps));

        for (let j = 0; j < FEATURE_COUNT; j++) {
          dW[j] += err * X[i][j];
        }
        dB += err;
      }

      // Update weights with L2 regularization
      for (let j = 0; j < FEATURE_COUNT; j++) {
        weights[j] -= LR * (dW[j] / batchSize + LAMBDA * weights[j]);
      }
      bias -= LR * (dB / batchSize);
    }

    // Record loss every 50 epochs
    if (epoch % 50 === 0) {
      let totalLoss = 0;
      for (let i = 0; i < n; i++) {
        const p = predict(weights, bias, X[i]);
        const eps = 1e-9;
        totalLoss += -(y[i] * Math.log(p + eps) + (1 - y[i]) * Math.log(1 - p + eps));
      }
      lossHistory.push({ epoch, loss: +(totalLoss / n).toFixed(4) });
    }
  }

  // ── Evaluation on training data ───────────────────────────────
  let tp = 0, tn = 0, fp = 0, fn = 0;
  for (let i = 0; i < n; i++) {
    const pred = predict(weights, bias, X[i]) >= 0.5 ? 1 : 0;
    if (pred === 1 && y[i] === 1) tp++;
    else if (pred === 0 && y[i] === 0) tn++;
    else if (pred === 1 && y[i] === 0) fp++;
    else fn++;
  }

  const accuracy  = +((tp + tn) / n * 100).toFixed(2);
  const precision = tp + fp > 0 ? +( tp / (tp + fp) * 100).toFixed(2) : 0;
  const recall    = tp + fn > 0 ? +( tp / (tp + fn) * 100).toFixed(2) : 0;
  const f1        = precision + recall > 0
    ? +(2 * precision * recall / (precision + recall)).toFixed(2)
    : 0;

  const metrics = {
    accuracy, precision, recall, f1Score: f1,
    confusionMatrix: { tp, tn, fp, fn },
    lossHistory,
    trainingSamples: n,
  };

  return { weights, bias, scaler, metrics };
}

// ─── Model persistence ────────────────────────────────────────────────────────

export function saveModel(modelData) {
  fs.writeFileSync(MODEL_PATH, JSON.stringify(modelData, null, 2), "utf8");
}

export function loadModel() {
  if (!fs.existsSync(MODEL_PATH)) return null;
  try {
    return JSON.parse(fs.readFileSync(MODEL_PATH, "utf8"));
  } catch {
    return null;
  }
}

// ─── Inference ────────────────────────────────────────────────────────────────

/**
 * Run inference on a single feature vector
 * @param {object} model - { weights, bias, scaler }
 * @param {number[]} rawVector - 20-dimensional feature vector
 * @returns {{ probability: number, label: number, confidence: string }}
 */
export function runInference(model, rawVector) {
  const { weights, bias, scaler } = model;
  const scaled = scaleRow(rawVector, scaler);
  const prob   = predict(weights, bias, scaled);

  const pct = +(prob * 100).toFixed(1);

  let confidence;
  if (prob >= 0.85 || prob <= 0.15) confidence = "High";
  else if (prob >= 0.65 || prob <= 0.35) confidence = "Medium";
  else confidence = "Low";

  return {
    probability: pct,        // 0–100 (%)
    label: prob >= 0.5 ? 1 : 0,
    confidence,
    raw: +prob.toFixed(4),
  };
}

// ─── Model Manager (singleton) ────────────────────────────────────────────────

class ModelManager {
  constructor() {
    this.model   = null;
    this.metrics = null;
    this.trained = false;
    this.trainedAt = null;
  }

  async initialize() {
    // Try loading saved model first
    const saved = loadModel();
    if (saved) {
      this.model    = { weights: saved.weights, bias: saved.bias, scaler: saved.scaler };
      this.metrics  = saved.metrics;
      this.trained  = true;
      this.trainedAt = saved.trainedAt;
      console.log(`🤖 ML model loaded from disk (accuracy: ${saved.metrics?.accuracy}%)`);
      return;
    }

    // Otherwise train fresh
    await this.retrain();
  }

  async retrain(sampleCount = 600) {
    console.log(`🔄 Training ML model on ${sampleCount} synthetic samples...`);
    const start = Date.now();
    const dataset = generateTrainingData(sampleCount);
    const result  = trainModel(dataset);

    this.model    = { weights: result.weights, bias: result.bias, scaler: result.scaler };
    this.metrics  = result.metrics;
    this.trained  = true;
    this.trainedAt = new Date().toISOString();

    saveModel({
      weights:   result.weights,
      bias:      result.bias,
      scaler:    result.scaler,
      metrics:   result.metrics,
      trainedAt: this.trainedAt,
      version:   "1.0.0",
    });

    const elapsed = Date.now() - start;
    console.log(`✅ ML model trained in ${elapsed}ms — Accuracy: ${result.metrics.accuracy}%, F1: ${result.metrics.f1Score}%`);
    return result.metrics;
  }

  infer(rawVector) {
    if (!this.trained || !this.model) {
      throw new Error("Model not initialized. Call initialize() first.");
    }
    return runInference(this.model, rawVector);
  }

  getStatus() {
    return {
      trained: this.trained,
      trainedAt: this.trainedAt,
      metrics: this.metrics,
    };
  }
}

export const modelManager = new ModelManager();
