const path = require("path");
require("dotenv").config({ path: path.resolve(__dirname, "../.env") });
require("dotenv").config({ path: path.resolve(__dirname, ".env") });

// Default test/fallback JWT_SECRET if none provided
if (!process.env.JWT_SECRET) {
  process.env.JWT_SECRET = "sih_master_secret_key_jwt_2026_investigation_platform_secure";
}

const express = require("express");
const { router: authRouter } = require("./routes");
const store = require("./store");
const auth = require("./auth");
const mailer = require("./mailer");

// Perform startup validations
auth.validateJwtSecret();
mailer.validateSmtpConfig();

const app = express();
app.use(express.json());

// Health Check
app.get("/health", (req, res) => {
  res.json({
    status: "healthy",
    service: "sih-auth-service",
    version: "1.0.0",
    timestamp: new Date().toISOString()
  });
});

// Mount auth router at root level so POST /signup, POST /login, POST /verify-otp work directly,
// as well as under /api/auth and /auth for maximum reverse proxy flexibility.
app.use(authRouter);
app.use("/auth", authRouter);
app.use("/api/auth", authRouter);

const PORT = process.env.AUTH_PORT || process.env.PORT || 5001;

async function startServer() {
  await store.initStore();
  return app.listen(PORT, () => {
    console.log(`[AUTH SERVICE] SIH Email-OTP MFA Auth Microservice listening on port ${PORT}`);
  });
}

if (require.main === module) {
  startServer().catch(err => {
    console.error("[AUTH SERVICE FATAL]", err);
    process.exit(1);
  });
}

module.exports = {
  app,
  startServer
};
