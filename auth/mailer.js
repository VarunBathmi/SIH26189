const nodemailer = require("nodemailer");

/**
 * Validates SMTP configuration at boot time.
 * Fails fast if SMTP is in a broken partial state.
 */
function validateSmtpConfig() {
  const host = process.env.SMTP_HOST;
  const port = process.env.SMTP_PORT;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const from = process.env.SMTP_FROM;

  const vars = { SMTP_HOST: host, SMTP_PORT: port, SMTP_USER: user, SMTP_PASS: pass, SMTP_FROM: from };
  const definedCount = Object.values(vars).filter(v => v !== undefined && v !== "").length;

  if (definedCount > 0 && definedCount < 5) {
    const missing = Object.entries(vars).filter(([, v]) => !v).map(([k]) => k);
    throw new Error(
      `FATAL: Incomplete SMTP configuration detected. Missing variables: ${missing.join(", ")}. ` +
      `Either provide all 5 SMTP variables (SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM) or leave them unset for dev mode.`
    );
  }

  const isConfigured = definedCount === 5;
  return { isConfigured, host, port: parseInt(port, 10) || 587, user, pass, from };
}

const smtpConfig = validateSmtpConfig();
let transporter = null;

if (smtpConfig.isConfigured) {
  transporter = nodemailer.createTransport({
    host: smtpConfig.host,
    port: smtpConfig.port,
    secure: smtpConfig.port === 465,
    auth: {
      user: smtpConfig.user,
      pass: smtpConfig.pass ? smtpConfig.pass.replace(/\s+/g, "") : ""
    }
  });
}

/**
 * Sends a one-time passcode (OTP) email to the target recipient.
 * If SMTP is not configured, logs the OTP to console for frictionless local development.
 *
 * @param {string} to - Recipient email address
 * @param {string} otp - 6-digit one-time password
 * @param {number} expiryMinutes - OTP lifetime in minutes
 * @returns {Promise<{ delivered: boolean, devMode?: boolean, preview?: string }>}
 */
async function sendOtpEmail(to, otp, expiryMinutes = 10) {
  if (!to || typeof to !== "string") {
    throw new Error("Recipient email is required.");
  }

  const subject = "SIH Investigation Portal - Your Login Verification Code";
  const textBody = `Your single-use verification code for the SIH Criminal Investigation Network Platform is: ${otp}\n\nThis code expires in ${expiryMinutes} minutes.\n\nIf you did not attempt this action, notify your system administrator immediately.`;
  const htmlBody = `
    <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
      <h2 style="color: #1a365d; margin-top: 0;">SIH Investigation Platform</h2>
      <p style="color: #4a5568; font-size: 14px;">Use the verification code below to complete your authentication.</p>
      <div style="background-color: #edf2f7; padding: 15px; border-radius: 6px; text-align: center; margin: 20px 0;">
        <span style="font-size: 28px; font-weight: bold; letter-spacing: 6px; color: #2b6cb0;">${otp}</span>
      </div>
      <p style="color: #718096; font-size: 12px;">This one-time passcode will expire in <strong>${expiryMinutes} minutes</strong>.</p>
      <hr style="border: 0; border-top: 1px solid #e2e8f0; margin: 20px 0;" />
      <p style="color: #a0aec0; font-size: 11px;">If you did not request this code, please ignore this email or contact the forensic admin team immediately.</p>
    </div>
  `;

  if (!transporter) {
    // Dev-mode fallback: intentional console log
    console.log(`[DEV MAIL] OTP for ${to.trim().toLowerCase()}: ${otp} (valid for ${expiryMinutes}m)`);
    return { delivered: false, devMode: true, preview: otp };
  }

  try {
    const info = await transporter.sendMail({
      from: smtpConfig.from,
      to: to.trim().toLowerCase(),
      subject,
      text: textBody,
      html: htmlBody
    });
    return { delivered: true, messageId: info.messageId };
  } catch (err) {
    console.error(`[SMTP ERROR] Failed to send email to ${to}:`, err.message);
    const smtpError = new Error(`SMTP Dispatch Failed: ${err.message}`);
    smtpError.statusCode = 502;
    throw smtpError;
  }
}

module.exports = {
  sendOtpEmail,
  validateSmtpConfig
};
