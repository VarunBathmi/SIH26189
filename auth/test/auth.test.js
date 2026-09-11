process.env.JWT_SECRET = "sih_master_secret_key_jwt_2026_investigation_platform_secure";
process.env.JWT_EXPIRES_IN = "1h";
process.env.OTP_RESEND_COOLDOWN_SECONDS = "2"; // fast for testing

const request = require("supertest");
const { app } = require("../server");
const store = require("../store");
const auth = require("../auth");
const otpService = require("../otp");
const mailer = require("../mailer");
const { resetRateLimits } = require("../routes");

describe("SIH Email-OTP MFA Authentication Service Tests", () => {
  let mailerSpy;

  beforeAll(async () => {
    mailerSpy = jest.spyOn(mailer, "sendOtpEmail").mockImplementation(async (to, otp) => {
      console.log(`[TEST MOCK MAIL] OTP for ${to}: ${otp}`);
      return { delivered: true, preview: otp };
    });
    await store.initStore();
  });

  beforeEach(async () => {
    await store.clearAll();
    resetRateLimits();
  });

  afterAll(async () => {
    if (mailerSpy) mailerSpy.mockRestore();
    await store.close();
  });

  // 1. Signup -> OTP issued -> wrong code rejected with attempts-left -> correct code accepted -> JWT with role
  test("1. Complete Signup -> OTP Issue -> Wrong Code (attempts left) -> Correct Code -> JWT with 'INVESTIGATOR' role", async () => {
    const signupRes = await request(app)
      .post("/signup")
      .send({ email: "officer.sharma@investigation.gov.in", password: "Password@1234" })
      .expect(201);

    expect(signupRes.body.message).toContain("Registration successful");
    expect(signupRes.body.role).toBe("INVESTIGATOR");
    expect(signupRes.body.email).toBe("officer.sharma@investigation.gov.in");

    const otpRecord = await store.getOtp("officer.sharma@investigation.gov.in");
    expect(otpRecord).toBeDefined();
    expect(otpRecord.attempts_left).toBe(3);

    // Wrong OTP attempt 1
    const wrongRes1 = await request(app)
      .post("/verify-otp")
      .send({ email: "officer.sharma@investigation.gov.in", otp: "999999" })
      .expect(400);

    expect(wrongRes1.body.error).toContain("2 attempt(s) remaining");

    // Retrieve active OTP code directly from memory or verify with issued OTP
    // For test verification, we issue an OTP or use preview if available
    const activeOtpCode = signupRes.body.dev_otp_preview;
    expect(activeOtpCode).toBeDefined();

    // Verify with correct OTP
    const verifyRes = await request(app)
      .post("/verify-otp")
      .send({ email: "officer.sharma@investigation.gov.in", otp: activeOtpCode })
      .expect(200);

    expect(verifyRes.body.token).toBeDefined();
    expect(verifyRes.body.user.role).toBe("INVESTIGATOR");
    expect(verifyRes.body.user.is_verified).toBe(true);

    // Verify token claims
    const decoded = auth.verifyToken(verifyRes.body.token);
    expect(decoded.email).toBe("officer.sharma@investigation.gov.in");
    expect(decoded.role).toBe("INVESTIGATOR");

    // Check GET /me with token
    const meRes = await request(app)
      .get("/me")
      .set("Authorization", `Bearer ${verifyRes.body.token}`)
      .expect(200);

    expect(meRes.body.user.email).toBe("officer.sharma@investigation.gov.in");
    expect(meRes.body.user.role).toBe("INVESTIGATOR");
  });

  // 2. Login with correct password but no/expired OTP entry -> proper error on verify
  test("2. Login with valid password -> verify OTP with expired/invalid OTP -> returns proper error", async () => {
    // Signup first
    await request(app)
      .post("/signup")
      .send({ email: "investigator.verma@investigation.gov.in", password: "Password@1234" })
      .expect(201);

    // Login (issues new OTP)
    const loginRes = await request(app)
      .post("/login")
      .send({ email: "investigator.verma@investigation.gov.in", password: "Password@1234" })
      .expect(200);

    expect(loginRes.body.message).toContain("Password verified");

    // Manually clear OTP to simulate missing/expired OTP
    await store.clearOtp("investigator.verma@investigation.gov.in");

    // Verify attempt with no active OTP in store
    const verifyExpired = await request(app)
      .post("/verify-otp")
      .send({ email: "investigator.verma@investigation.gov.in", otp: "123456" })
      .expect(400);

    expect(verifyExpired.body.error).toContain("No active OTP found");
  });

  // 3. Rate limiter actually blocks (N+1)th attempt with HTTP 429
  test("3. Rate limiter blocks (N+1)th attempt with HTTP 429 on /login and /verify-otp", async () => {
    const targetEmail = "ratelimit.target@investigation.gov.in";

    // Repeated logins (limit is 10 per window)
    for (let i = 0; i < 10; i++) {
      await request(app)
        .post("/login")
        .send({ email: targetEmail, password: "WrongPassword123" });
    }

    // 11th attempt must be blocked by rate limiter with 429
    const blockedLogin = await request(app)
      .post("/login")
      .send({ email: targetEmail, password: "WrongPassword123" })
      .expect(429);

    expect(blockedLogin.body.error).toContain("Too many");

    // Test verify-otp rate limit (limit is 10 per window)
    for (let i = 0; i < 10; i++) {
      await request(app)
        .post("/verify-otp")
        .send({ email: targetEmail, otp: "000000" });
    }

    const blockedVerify = await request(app)
      .post("/verify-otp")
      .send({ email: targetEmail, otp: "000000" })
      .expect(429);

    expect(blockedVerify.body.error).toContain("Too many attempts");
  });

  // 4. Email normalization: signing up with Test@X.com then logging in with test@x.com
  test("4. Email normalization: Sign up with MixedCase 'Officer.Case@Gov.In' and login with lowercase 'officer.case@gov.in'", async () => {
    const mixedEmail = "Officer.Case@Gov.In";
    const lowerEmail = "officer.case@gov.in";

    await request(app)
      .post("/signup")
      .send({ email: mixedEmail, password: "SecurePassword123!" })
      .expect(201);

    // Login using lowercase
    const loginRes = await request(app)
      .post("/login")
      .send({ email: lowerEmail, password: "SecurePassword123!" })
      .expect(200);

    expect(loginRes.body.email).toBe(lowerEmail);

    // Verify OTP using uppercase
    const devOtp = loginRes.body.dev_otp_preview;
    const verifyRes = await request(app)
      .post("/verify-otp")
      .send({ email: "OFFICER.CASE@GOV.IN", otp: devOtp })
      .expect(200);

    expect(verifyRes.body.user.email).toBe(lowerEmail);
  });

  // 5. requireRole("ADMINISTRATOR") correctly 403s INVESTIGATOR and allows ADMINISTRATOR
  test("5. Role guards: requireRole('ADMINISTRATOR') blocks INVESTIGATOR (403) and permits ADMINISTRATOR (200)", async () => {
    // 1. Investigator token
    const investigatorUser = { id: 101, email: "agent@gov.in", role: "INVESTIGATOR" };
    const investigatorToken = auth.signToken(investigatorUser);

    const blockedRes = await request(app)
      .get("/admin/users")
      .set("Authorization", `Bearer ${investigatorToken}`)
      .expect(403);

    expect(blockedRes.body.error).toContain("Insufficient permissions");

    // 2. Administrator token
    const adminUser = { id: 1, email: "superadmin@gov.in", role: "ADMINISTRATOR" };
    const adminToken = auth.signToken(adminUser);

    const allowedRes = await request(app)
      .get("/admin/users")
      .set("Authorization", `Bearer ${adminToken}`)
      .expect(200);

    expect(allowedRes.body.message).toBe("Admin access verified.");
    expect(allowedRes.body.admin_user).toBe("superadmin@gov.in");
  });

  // 6. Account lockout after 10 failed login attempts
  test("6. Basic account lockout after 10 consecutive failed password attempts on /login", async () => {
    const lockedTarget = "lockout.target@gov.in";
    const passwordHash = await auth.hashPassword("CorrectPass1234");
    await store.createUser(lockedTarget, passwordHash, "INVESTIGATOR");

    // Perform 10 failed password attempts directly on store
    for (let i = 1; i <= 9; i++) {
      const fail = await store.recordFailedLogin(lockedTarget);
      expect(fail.locked).toBe(false);
      expect(fail.attempts).toBe(i);
    }

    // 10th failed attempt triggers lock
    const tenthFail = await store.recordFailedLogin(lockedTarget);
    expect(tenthFail.locked).toBe(true);

    // Check account status
    const status = await store.isAccountLocked(lockedTarget);
    expect(status.locked).toBe(true);
    expect(status.minutesLeft).toBeGreaterThan(0);
  });

  // 7. Startup secret validation: fails fast if JWT_SECRET is missing or < 32 chars
  test("7. Startup validation: fails fast if JWT_SECRET is missing or under 32 characters", () => {
    const originalSecret = process.env.JWT_SECRET;
    try {
      process.env.JWT_SECRET = "short_secret";
      expect(() => auth.validateJwtSecret()).toThrow("too short");

      delete process.env.JWT_SECRET;
      expect(() => auth.validateJwtSecret()).toThrow("missing");
    } finally {
      process.env.JWT_SECRET = originalSecret;
    }
  });

  // 8. Startup validation: fails fast on incomplete SMTP config
  test("8. Startup validation: fails fast on incomplete SMTP config", () => {
    const originalHost = process.env.SMTP_HOST;
    const originalUser = process.env.SMTP_USER;
    try {
      process.env.SMTP_HOST = "smtp.example.com";
      delete process.env.SMTP_USER;
      expect(() => mailer.validateSmtpConfig()).toThrow("Incomplete SMTP configuration");
    } finally {
      process.env.SMTP_HOST = originalHost;
      process.env.SMTP_USER = originalUser;
    }
  });

  // 9. Resend OTP cooldown test: immediate resend returns HTTP 429
  test("9. POST /resend-otp enforces cooldown and returns 429 with retryAfter if requested too quickly", async () => {
    const testEmail = "resend.test@investigation.gov.in";
    const passwordHash = await auth.hashPassword("SecurePass123!");
    await store.createUser(testEmail, passwordHash, "INVESTIGATOR");

    // First resend request succeeds
    const firstResend = await request(app)
      .post("/resend-otp")
      .send({ email: testEmail })
      .expect(200);

    expect(firstResend.body.message).toContain("New OTP dispatched");

    // Immediate second resend triggers cooldown (cooldown is set to 2s in test env)
    const secondResend = await request(app)
      .post("/resend-otp")
      .send({ email: testEmail })
      .expect(429);

    expect(secondResend.body.error).toContain("Please wait");
    expect(secondResend.body.retryAfter).toBeDefined();
  });

  // 10. Password hashing: plaintext passwords are cryptographically salted and hashed
  test("10. Password hashing and verification", async () => {
    const rawPass = "InvestigatorSecret#2026";
    const hash = await auth.hashPassword(rawPass);

    expect(hash).not.toBe(rawPass);
    expect(hash.startsWith("$2b$") || hash.startsWith("$2a$")).toBe(true);

    const isValid = await auth.comparePassword(rawPass, hash);
    expect(isValid).toBe(true);

    const isInvalid = await auth.comparePassword("WrongPassword", hash);
    expect(isInvalid).toBe(false);
  });
});
