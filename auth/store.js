const { Pool } = require("pg");

/**
 * Normalizes email address to trimmed lowercase at the single store boundary.
 */
function normalizeEmail(email) {
  if (!email || typeof email !== "string") return "";
  return email.trim().toLowerCase();
}

let pool = null;
let useMemoryStore = false;

// In-memory fallback structures for testing or when DB is not reachable
const memUsers = new Map(); // email -> user object
const memOtps = new Map();  // email -> otp object
let memAutoId = 1;

/**
 * Initializes the database connection pool and ensures required tables exist.
 */
async function initStore() {
  let connectionString = process.env.DATABASE_URL_AUTH;
  if (!connectionString) {
    if (process.env.DATABASE_URL) {
      connectionString = process.env.DATABASE_URL;
      // If running on host and host is not inside docker network, replace docker internal hostname
      if (connectionString.includes("@postgres:") && !process.env.DOCKER_CONTAINER) {
        connectionString = connectionString.replace("@postgres:", "@localhost:");
      }
    } else {
      connectionString = `postgresql://${process.env.PGUSER || "sih_user"}:${process.env.PGPASSWORD || "sih_pass"}@${process.env.PGHOST || "localhost"}:${process.env.PGPORT || "5432"}/${process.env.PGDATABASE || "crime_network_db"}`;
    }
  }

  try {
    pool = new Pool({
      connectionString,
      connectionTimeoutMillis: 3000,
      max: 10
    });

    // Test connection
    const client = await pool.connect();
    try {
      await client.query(`
        CREATE TABLE IF NOT EXISTS auth_users (
          id SERIAL PRIMARY KEY,
          email VARCHAR(255) UNIQUE NOT NULL,
          password_hash VARCHAR(255) NOT NULL,
          role VARCHAR(50) DEFAULT 'INVESTIGATOR' NOT NULL,
          is_verified BOOLEAN DEFAULT FALSE NOT NULL,
          failed_login_attempts INT DEFAULT 0 NOT NULL,
          locked_until BIGINT DEFAULT 0,
          created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS auth_otps (
          email VARCHAR(255) PRIMARY KEY,
          otp_hash VARCHAR(255) NOT NULL,
          expires_at BIGINT NOT NULL,
          attempts_left INT DEFAULT 3 NOT NULL,
          last_sent_at BIGINT DEFAULT 0 NOT NULL,
          created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );
      `);
      useMemoryStore = false;
    } finally {
      client.release();
    }
  } catch (err) {
    console.warn(`[STORE WARNING] PostgreSQL connection failed (${err.message}). Using persistent memory store for active process.`);
    useMemoryStore = true;
  }
}

/**
 * Create a new user in the persistent store.
 * Role defaults to 'INVESTIGATOR' and cannot be overridden by public callers.
 */
async function createUser(email, passwordHash, role = "INVESTIGATOR") {
  const normEmail = normalizeEmail(email);
  if (!normEmail) throw new Error("Email cannot be empty.");
  if (!passwordHash) throw new Error("Password hash cannot be empty.");

  const validRole = (role === "ADMINISTRATOR") ? "ADMINISTRATOR" : "INVESTIGATOR";

  if (useMemoryStore || !pool) {
    if (memUsers.has(normEmail)) {
      const err = new Error("User already exists.");
      err.code = "23505";
      throw err;
    }
    const user = {
      id: memAutoId++,
      email: normEmail,
      password_hash: passwordHash,
      role: validRole,
      is_verified: false,
      failed_login_attempts: 0,
      locked_until: 0,
      created_at: new Date()
    };
    memUsers.set(normEmail, user);
    return { ...user };
  }

  const query = `
    INSERT INTO auth_users (email, password_hash, role, is_verified, failed_login_attempts, locked_until)
    VALUES ($1, $2, $3, FALSE, 0, 0)
    RETURNING id, email, password_hash, role, is_verified, failed_login_attempts, locked_until, created_at;
  `;
  const res = await pool.query(query, [normEmail, passwordHash, validRole]);
  return res.rows[0];
}

/**
 * Retrieve user by normalized email.
 */
async function getUserByEmail(email) {
  const normEmail = normalizeEmail(email);
  if (!normEmail) return null;

  if (useMemoryStore || !pool) {
    const user = memUsers.get(normEmail);
    return user ? { ...user } : null;
  }

  const res = await pool.query("SELECT * FROM auth_users WHERE email = $1 LIMIT 1;", [normEmail]);
  return res.rows[0] || null;
}

/**
 * Mark a user as verified after successful OTP verification.
 */
async function markUserVerified(email) {
  const normEmail = normalizeEmail(email);
  if (!normEmail) return false;

  if (useMemoryStore || !pool) {
    const user = memUsers.get(normEmail);
    if (user) {
      user.is_verified = true;
      user.failed_login_attempts = 0;
      user.locked_until = 0;
      return true;
    }
    return false;
  }

  await pool.query(
    "UPDATE auth_users SET is_verified = TRUE, failed_login_attempts = 0, locked_until = 0 WHERE email = $1;",
    [normEmail]
  );
  return true;
}

/**
 * Store an active OTP hash with expiry, attempt quota, and cooldown tracking.
 */
async function setOtp(email, otpHash, expiresAt, attemptsLeft = 3, lastSentAt = Date.now()) {
  const normEmail = normalizeEmail(email);
  if (!normEmail) throw new Error("Email cannot be empty.");

  const exp = typeof expiresAt === "number" ? expiresAt : new Date(expiresAt).getTime();
  const sent = typeof lastSentAt === "number" ? lastSentAt : new Date(lastSentAt).getTime();

  if (useMemoryStore || !pool) {
    memOtps.set(normEmail, {
      email: normEmail,
      otp_hash: otpHash,
      expires_at: exp,
      attempts_left: attemptsLeft,
      last_sent_at: sent
    });
    return true;
  }

  const query = `
    INSERT INTO auth_otps (email, otp_hash, expires_at, attempts_left, last_sent_at)
    VALUES ($1, $2, $3, $4, $5)
    ON CONFLICT (email) DO UPDATE
    SET otp_hash = EXCLUDED.otp_hash,
        expires_at = EXCLUDED.expires_at,
        attempts_left = EXCLUDED.attempts_left,
        last_sent_at = EXCLUDED.last_sent_at;
  `;
  await pool.query(query, [normEmail, otpHash, exp, attemptsLeft, sent]);
  return true;
}

/**
 * Retrieve active OTP metadata for an email.
 */
async function getOtp(email) {
  const normEmail = normalizeEmail(email);
  if (!normEmail) return null;

  if (useMemoryStore || !pool) {
    const otpObj = memOtps.get(normEmail);
    return otpObj ? { ...otpObj } : null;
  }

  const res = await pool.query("SELECT * FROM auth_otps WHERE email = $1 LIMIT 1;", [normEmail]);
  if (!res.rows[0]) return null;
  const row = res.rows[0];
  return {
    email: row.email,
    otp_hash: row.otp_hash,
    expires_at: Number(row.expires_at),
    attempts_left: Number(row.attempts_left),
    last_sent_at: Number(row.last_sent_at)
  };
}

/**
 * Remove OTP after successful use or expiration.
 */
async function clearOtp(email) {
  const normEmail = normalizeEmail(email);
  if (!normEmail) return;

  if (useMemoryStore || !pool) {
    memOtps.delete(normEmail);
    return;
  }

  await pool.query("DELETE FROM auth_otps WHERE email = $1;", [normEmail]);
}

/**
 * Decrement attempts left for an active OTP.
 */
async function decrementOtpAttempts(email) {
  const normEmail = normalizeEmail(email);
  if (!normEmail) return 0;

  if (useMemoryStore || !pool) {
    const record = memOtps.get(normEmail);
    if (record) {
      record.attempts_left = Math.max(0, record.attempts_left - 1);
      return record.attempts_left;
    }
    return 0;
  }

  const res = await pool.query(
    "UPDATE auth_otps SET attempts_left = GREATEST(0, attempts_left - 1) WHERE email = $1 RETURNING attempts_left;",
    [normEmail]
  );
  return res.rows[0] ? Number(res.rows[0].attempts_left) : 0;
}

/**
 * Record a failed password attempt on login. Locks account if attempts >= maxAttempts.
 */
async function recordFailedLogin(email, maxAttempts = 10, lockoutMinutes = 15) {
  const normEmail = normalizeEmail(email);
  if (!normEmail) return { locked: false, attempts: 0 };

  const now = Date.now();
  const lockoutUntil = now + lockoutMinutes * 60 * 1000;

  if (useMemoryStore || !pool) {
    const user = memUsers.get(normEmail);
    if (!user) return { locked: false, attempts: 0 };
    user.failed_login_attempts = (user.failed_login_attempts || 0) + 1;
    if (user.failed_login_attempts >= maxAttempts) {
      user.locked_until = lockoutUntil;
      return { locked: true, attempts: user.failed_login_attempts, lockedUntil: lockoutUntil };
    }
    return { locked: false, attempts: user.failed_login_attempts, remaining: maxAttempts - user.failed_login_attempts };
  }

  const res = await pool.query(
    `UPDATE auth_users
     SET failed_login_attempts = failed_login_attempts + 1,
         locked_until = CASE WHEN failed_login_attempts + 1 >= $2 THEN $3 ELSE locked_until END
     WHERE email = $1
     RETURNING failed_login_attempts, locked_until;`,
    [normEmail, maxAttempts, lockoutUntil]
  );

  if (!res.rows[0]) return { locked: false, attempts: 0 };
  const attempts = Number(res.rows[0].failed_login_attempts);
  const locked = attempts >= maxAttempts;
  return {
    locked,
    attempts,
    remaining: Math.max(0, maxAttempts - attempts),
    lockedUntil: Number(res.rows[0].locked_until)
  };
}

/**
 * Reset failed login count upon successful password verification.
 */
async function resetFailedLogins(email) {
  const normEmail = normalizeEmail(email);
  if (!normEmail) return;

  if (useMemoryStore || !pool) {
    const user = memUsers.get(normEmail);
    if (user) {
      user.failed_login_attempts = 0;
      user.locked_until = 0;
    }
    return;
  }

  await pool.query("UPDATE auth_users SET failed_login_attempts = 0, locked_until = 0 WHERE email = $1;", [normEmail]);
}

/**
 * Check if the user's account is currently locked.
 */
async function isAccountLocked(email) {
  const normEmail = normalizeEmail(email);
  if (!normEmail) return { locked: false };

  const user = await getUserByEmail(normEmail);
  if (!user) return { locked: false };

  const now = Date.now();
  const lockedUntil = Number(user.locked_until || 0);

  if (lockedUntil > now) {
    const minutesLeft = Math.ceil((lockedUntil - now) / 60000);
    return { locked: true, minutesLeft, lockedUntil };
  }

  // Lock expired, reset if needed
  if (lockedUntil > 0 && lockedUntil <= now) {
    await resetFailedLogins(normEmail);
  }

  return { locked: false };
}

/**
 * Clear all records (useful for test suites).
 */
async function clearAll() {
  memUsers.clear();
  memOtps.clear();
  memAutoId = 1;
  if (pool && !useMemoryStore) {
    await pool.query("DELETE FROM auth_otps; DELETE FROM auth_users;");
  }
}

/**
 * Close database pool on shutdown.
 */
async function close() {
  if (pool) {
    await pool.end();
    pool = null;
  }
}

module.exports = {
  initStore,
  createUser,
  getUserByEmail,
  markUserVerified,
  setOtp,
  getOtp,
  clearOtp,
  decrementOtpAttempts,
  recordFailedLogin,
  resetFailedLogins,
  isAccountLocked,
  clearAll,
  close,
  normalizeEmail
};
