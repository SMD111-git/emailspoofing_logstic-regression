import { Router } from "express";
import multer from "multer";
import { analyzeEmail, getModelStatus, retrainModel } from "../controllers/Emailparser.js";
import { mitreAttackAnalysis } from "../middlewares/Mitreattack.js";

const router = Router();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = file.originalname.endsWith(".eml") ||
               file.mimetype.includes("message") ||
               file.mimetype.includes("text");
    cb(null, ok);
  },
});

router.post("/emailchecking", upload.single("emailFile"), mitreAttackAnalysis, analyzeEmail);
router.get("/model-status",   getModelStatus);
router.post("/retrain",       retrainModel);

export default router;
