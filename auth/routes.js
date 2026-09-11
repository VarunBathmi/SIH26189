const express = require("express");
const store = require("./store");
const otpService = require("./otp");
const mailer = require("./mailer");
const auth = require("./auth");

const router = express.Router();

/**
 * Async handler wrapper to catch unhandled rejections and forward to error middleware.
 */
function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

/**
 * Lightweight, in-memory rate limiter supporting both IP-based and Email-based tracking.
 */
const rateLimitBuckets = new Map();

function createRateLimiter({ windowMs = 15 * 60 * 1000, maxPerIp = 10, maxPerEmail = 5, endpointName = "endpoint" }) {
  return (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress || "127.0.0.1";
    const email = req.body && req.body.email ? store.normalizeEmail(req.body.email) : null;
    const now = Date.now();

    // Check IP bucket
    const ipKey = `ip:${endpointName}:${ip}`;
    let ipBucket = rateLimitBuckets.get(ipKey);
    if (!ipBucket || now > ipBucket.resetAt) {
      ipBucket = { count: 0, resetAt: now + windowMs };
      rateLimitBuckets.set(ipKey, ipBucket);
    }
    ipBucket.count += 1;
    if (ipBucket.count > maxPerIp) {
      const waitSeconds = Math.ceil((ipBucket.resetAt - now) / 1000);
      res.setHeader("Retry-After", waitSeconds);
      return res.status(429).json({
        error: `Too many requests from this IP for ${endpointName}. Please try again in ${waitSeconds} seconds.`
      });
    }

    // Check Email bucket if email is present
    if (email) {
      const emailKey = `email:${endpointName}:${email}`;
      let emailBucket = rateLimitBuckets.get(emailKey);
      if (!emailBucket || now > emailBucket.resetAt) {
        emailBucket = { count: 0, resetAt: now + windowMs };
        rateLimitBuckets.set(emailKey, emailBucket);
      }
      emailBucket.count += 1;
      if (emailBucket.count > maxPerEmail) {
        const waitSeconds = Math.ceil((emailBucket.resetAt - now) / 1000);
        res.setHeader("Retry-After", waitSeconds);
        return res.status(429).json({
          error: `Too many attempts for account '${email}'. Please try again in ${waitSeconds} seconds.`
        });
      }
    }

    next();
  };
}

// Reset rate limits helper for tests
function resetRateLimits() {
  rateLimitBuckets.clear();
}

// Stricter multi-dimensional rate limiters
const signupLimiter = createRateLimiter({ windowMs: 15 * 60 * 1000, maxPerIp: 10, maxPerEmail: 5, endpointName: "signup" });
const loginLimiter = createRateLimiter({ windowMs: 15 * 60 * 1000, maxPerIp: 15, maxPerEmail: 10, endpointName: "login" });
const verifyOtpLimiter = createRateLimiter({ windowMs: 10 * 60 * 1000, maxPerIp: 20, maxPerEmail: 10, endpointName: "verify-otp" });
const resendOtpLimiter = createRateLimiter({ windowMs: 10 * 60 * 1000, maxPerIp: 10, maxPerEmail: 5, endpointName: "resend-otp" });

/**
 * POST /signup
 * Public registration for investigators. Role is always forced to INVESTIGATOR.
 */
router.post(
  "/signup",
  signupLimiter,
  asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required." });
    }

    const normEmail = store.normalizeEmail(email);
    if (!normEmail || !/^\S+@\S+\.\S+$/.test(normEmail)) {
      return res.status(400).json({ error: "Invalid email format." });
    }

    if (typeof password !== "string" || password.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters long." });
    }

    const existingUser = await store.getUserByEmail(normEmail);
    if (existingUser) {
      return res.status(409).json({ error: "An account with this email already exists." });
    }

    const passwordHash = await auth.hashPassword(password);
    // Role is strictly forced to INVESTIGATOR - never allow client to elevate to ADMINISTRATOR on public signup
    const user = await store.createUser(normEmail, passwordHash, "INVESTIGATOR");

    // Issue initial verification OTP
    const { otp, expiryMinutes } = await otpService.issueOtp(normEmail);

    // Send email with handled async error wrapper
    const mailResult = await mailer.sendOtpEmail(normEmail, otp, expiryMinutes);

    const showPreview = mailResult.devMode || process.env.NODE_ENV === "test" || process.env.ENVIRONMENT === "development";
    return res.status(201).json({
      message: "Registration successful. Please verify your email with the OTP sent.",
      email: normEmail,
      role: user.role,
      dev_otp_preview: showPreview ? otp : undefined
    });
  })
);

/**
 * POST /login
 * First factor verification (password) -> issues second factor OTP.
 */
router.post(
  "/login",
  loginLimiter,
  asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required." });
    }

    const normEmail = store.normalizeEmail(email);

    // Check account lockout status
    const lockout = await store.isAccountLocked(normEmail);
    if (lockout.locked) {
      return res.status(423).json({
        error: `Account is temporarily locked due to excessive failed attempts. Please try again in ${lockout.minutesLeft} minute(s).`
      });
    }

    const user = await store.getUserByEmail(normEmail);
    if (!user) {
      // Record failed attempt even if user does not exist to prevent user enumeration timing attacks
      await store.recordFailedLogin(normEmail);
      return res.status(401).json({ error: "Invalid email or password." });
    }

    const passwordValid = await auth.comparePassword(password, user.password_hash);
    if (!passwordValid) {
      const failStatus = await store.recordFailedLogin(normEmail);
      if (failStatus.locked) {
        return res.status(423).json({
          error: "Account has been locked for 15 minutes due to 10 consecutive failed login attempts."
        });
      }
      return res.status(401).json({
        error: "Invalid email or password.",
        attemptsRemainingBeforeLock: failStatus.remaining
      });
    }

    // Reset failed login counter on valid password
    await store.resetFailedLogins(normEmail);

    // Issue 2FA OTP
    const { otp, expiryMinutes } = await otpService.issueOtp(normEmail);
    const mailResult = await mailer.sendOtpEmail(normEmail, otp, expiryMinutes);

    const showPreview = mailResult.devMode || process.env.NODE_ENV === "test" || process.env.ENVIRONMENT === "development";
    return res.status(200).json({
      message: "Password verified. One-time passcode (OTP) dispatched to your registered email.",
      email: normEmail,
      dev_otp_preview: showPreview ? otp : undefined
    });
  })
);

/**
 * POST /verify-otp
 * Second factor verification -> issues signed JWT session token.
 */
router.post(
  "/verify-otp",
  verifyOtpLimiter,
  asyncHandler(async (req, res) => {
    const { email, otp } = req.body;
    if (!email || !otp) {
      return res.status(400).json({ error: "Email and OTP code are required." });
    }

    const normEmail = store.normalizeEmail(email);
    const result = await otpService.verifyOtp(normEmail, otp);

    if (!result.success) {
      return res.status(400).json({ error: result.error });
    }

    const user = await store.getUserByEmail(normEmail);
    if (!user) {
      return res.status(404).json({ error: "User account not found." });
    }

    const token = auth.signToken(user);

    return res.status(200).json({
      message: "Authentication successful.",
      token,
      token_type: "Bearer",
      expires_in: auth.JWT_EXPIRES_IN,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        is_verified: true
      }
    });
  })
);

/**
 * POST /resend-otp
 * Re-issues OTP with rate limit cooldown.
 */
router.post(
  "/resend-otp",
  resendOtpLimiter,
  asyncHandler(async (req, res) => {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: "Email is required." });
    }

    const normEmail = store.normalizeEmail(email);
    const user = await store.getUserByEmail(normEmail);
    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    try {
      const { otp, expiryMinutes } = await otpService.issueOtp(normEmail, true);
      const mailResult = await mailer.sendOtpEmail(normEmail, otp, expiryMinutes);

      const showPreview = mailResult.devMode || process.env.NODE_ENV === "test" || process.env.ENVIRONMENT === "development";
      return res.status(200).json({
        message: "New OTP dispatched to registered email.",
        email: normEmail,
        dev_otp_preview: showPreview ? otp : undefined
      });
    } catch (err) {
      if (err.statusCode === 429) {
        return res.status(429).json({ error: err.message, retryAfter: err.retryAfter });
      }
      throw err;
    }
  })
);

/**
 * GET /me
 * Returns the currently authenticated user's profile and permissions.
 */
router.get(
  "/me",
  auth.requireAuth,
  asyncHandler(async (req, res) => {
    return res.status(200).json({
      user: req.user
    });
  })
);

/**
 * GET /admin/users
 * Admin-only: Lists or inspects user status.
 */
router.get(
  "/admin/users",
  auth.requireAuth,
  auth.requireRole("ADMINISTRATOR"),
  asyncHandler(async (req, res) => {
    return res.status(200).json({
      message: "Admin access verified.",
      admin_user: req.user.email
    });
  })
);

/**
 * Global error handling middleware for auth routes.
 */
router.use((err, req, res, next) => {
  console.error("[AUTH ROUTE ERROR]", err);
  const status = err.statusCode || (err.status >= 400 && err.status < 600 ? err.status : 500);
  res.status(status).json({
    error: err.message || "Internal Server Error"
  });
});

module.exports = {
  router,
  asyncHandler,
  createRateLimiter,
  resetRateLimits
};
