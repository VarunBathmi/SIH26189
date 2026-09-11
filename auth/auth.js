const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

/**
 * Startup Validation: Validate JWT Secret.
 * Enforce minimum 32 characters to prevent weak signatures.
 */
function validateJwtSecret() {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error(
      "FATAL: JWT_SECRET environment variable is missing. Authentication service cannot start securely."
    );
  }
  if (secret.length < 32) {
    throw new Error(
      `FATAL: JWT_SECRET is too short (${secret.length} chars). Minimum length is 32 characters for HS256 security.`
    );
  }
  return secret;
}

const JWT_SECRET = validateJwtSecret();
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "1h";
const BCRYPT_SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS, 10) || 10;

/**
 * Hashes a plain-text password using bcrypt.
 */
async function hashPassword(password) {
  if (!password || typeof password !== "string" || password.length < 8) {
    throw new Error("Password must be at least 8 characters long.");
  }
  return await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
}

/**
 * Compares a plain-text password with a bcrypt hash.
 */
async function comparePassword(password, hash) {
  if (!password || !hash) return false;
  return await bcrypt.compare(password, hash);
}

/**
 * Signs a JWT access token containing identity and role claims.
 */
function signToken(user) {
  if (!user || !user.email) {
    throw new Error("Cannot sign token without user identity.");
  }

  const role = user.role || "INVESTIGATOR";
  const payload = {
    sub: user.email.toLowerCase(),
    email: user.email.toLowerCase(),
    role: role,
    id: user.id || 1,
    is_verified: user.is_verified ?? true
  };

  return jwt.sign(payload, JWT_SECRET, {
    algorithm: "HS256",
    expiresIn: JWT_EXPIRES_IN
  });
}

/**
 * Verifies and decodes a signed JWT token.
 */
function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET, {
    algorithms: ["HS256"]
  });
}

/**
 * Express middleware to authenticate requests using JWT Bearer headers.
 */
function requireAuth(req, res, next) {
  const authHeader = req.headers["authorization"] || req.headers["Authorization"];
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Unauthorized: Missing or malformed Authorization header. Format: 'Bearer <token>'"
    });
  }

  const token = authHeader.split(" ")[1];
  try {
    const decoded = verifyToken(token);
    req.user = decoded;
    next();
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({
        error: "Token expired. Please re-authenticate."
      });
    }
    return res.status(401).json({
      error: "Invalid token signature."
    });
  }
}

/**
 * Express middleware to enforce Role-Based Access Control (RBAC).
 * Supports a single role string or an array of allowed roles.
 */
function requireRole(allowedRoles) {
  const roles = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];
  return (req, res, next) => {
    if (!req.user || !req.user.role) {
      return res.status(401).json({ error: "Unauthorized: Authentication required." });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        error: `Insufficient permissions. Access requires one of: [${roles.join(", ")}]. Current role: '${req.user.role}'`
      });
    }

    next();
  };
}

module.exports = {
  validateJwtSecret,
  hashPassword,
  comparePassword,
  signToken,
  verifyToken,
  requireAuth,
  requireRole,
  JWT_EXPIRES_IN
};
