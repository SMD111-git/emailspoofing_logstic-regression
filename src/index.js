import dotenv from "dotenv";
import { app } from "./app.js";

dotenv.config();

const PORT = process.env.PORT || 8000;

app.listen(PORT, () => {
  console.log(`\n🛡️  Email Spoofing Detection API`);
  console.log(`🚀 Server running at http://localhost:${PORT}`);
  console.log(`📋 Health check: http://localhost:${PORT}/health`);
  console.log(`🌐 Frontend: http://localhost:${PORT}`);
  console.log(`📡 API: http://localhost:${PORT}/api/v1/email/emailchecking\n`);
});
