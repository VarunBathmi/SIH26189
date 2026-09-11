const crypto = require("crypto");
const store = require("./store");

const OTP_LENGTH = parseInt(process.env.OTP_LENGTH, 10) || 6;
const OTP_EXPIRY_MINUTES = parseInt(process.env.OTP_EXPIRY_MINUTES, 10) || 10;
const OTP_MAX_ATTEMPTS = parseInt(process.env.OTP_MAX_ATTEMPTS, 10) || 3;
const OTP_RESEND_COOLDOWN_SECONDS = parseInt(process.env.OTP_RESEND_COOLDOWN_SECONDS, 10) || 60;

/**
 * Generate a cryptographically secure numeric OTP string of given length.
 */
function generateOtpCode(length = OTP_LENGTH) {
  const min = Math.pow(10, length - 1);
  const max = Math.pow(10, length);
  const num = crypto.randomInt(min, max);
  return num.toString();
}

/**
 * Hash an OTP using SHA-256 for secure storage in database.
 */
function hashOtp(otp) {
  return crypto.createHash("sha256").update(String(otp)).digest("hex");
}

/**
 * Issue a new OTP for an email address with optional cooldown and expiry checks.
 */
async function issueOtp(email, enforceCooldown = false) {
  const normEmail = store.normalizeEmail(email);
  if (!normEmail) {
    throw new Error("Valid email is required to issue OTP.");
  }

  const existing = await store.getOtp(normEmail);
  const now = Date.now();

  // Enforce resend cooldown if requested (e.g. on POST /resend-otp)
  if (enforceCooldown && existing && existing.last_sent_at) {
    const elapsedSeconds = Math.floor((now - existing.last_sent_at) / 1000);
    if (elapsedSeconds < OTP_RESEND_COOLDOWN_SECONDS) {
      const waitTime = OTP_RESEND_COOLDOWN_SECONDS - elapsedSeconds;
      const cooldownError = new Error(`Please wait ${waitTime} second(s) before requesting another OTP.`);
      cooldownError.statusCode = 429;
      cooldownError.retryAfter = waitTime;
      throw cooldownError;
    }
  }

  const code = generateOtpCode(OTP_LENGTH);
  const codeHash = hashOtp(code);
  const expiresAt = now + OTP_EXPIRY_MINUTES * 60 * 1000;

  await store.setOtp(normEmail, codeHash, expiresAt, OTP_MAX_ATTEMPTS, now);

  return {
    otp: code,
    expiresAt,
    expiryMinutes: OTP_EXPIRY_MINUTES
  };
}

/**
 * Verify an OTP submission against the stored record.
 */
async function verifyOtp(email, submittedCode) {
  const normEmail = store.normalizeEmail(email);
  if (!normEmail || !submittedCode) {
    return { success: false, error: "Email and OTP code are required." };
  }

  const record = await store.getOtp(normEmail);
  if (!record) {
    return { success: false, error: "No active OTP found. Please request a new one." };
  }

  const now = Date.now();
  if (now > record.expires_at) {
    await store.clearOtp(normEmail);
    return { success: false, error: "OTP has expired. Please request a new one." };
  }

  if (record.attempts_left <= 0) {
    await store.clearOtp(normEmail);
    return { success: false, error: "Maximum verification attempts exceeded. Please request a new OTP." };
  }

  const inputHash = hashOtp(String(submittedCode).trim());
  const isMatch = inputHash === record.otp_hash;

  if (isMatch) {
    await store.clearOtp(normEmail);
    await store.markUserVerified(normEmail);
    return { success: true };
  }

  // Handle wrong code
  const remaining = await store.decrementOtpAttempts(normEmail);
  if (remaining <= 0) {
    await store.clearOtp(normEmail);
    return {
      success: false,
      error: "Invalid OTP. 0 attempts remaining. Please request a new OTP."
    };
  }

  return {
    success: false,
    error: `Invalid OTP. ${remaining} attempt(s) remaining.`
  };
}

module.exports = {
  issueOtp,
  verifyOtp,
  generateOtpCode,
  hashOtp,
  OTP_LENGTH,
  OTP_EXPIRY_MINUTES,
  OTP_MAX_ATTEMPTS,
  OTP_RESEND_COOLDOWN_SECONDS
};
