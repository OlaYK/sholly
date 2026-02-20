const fs = require("fs/promises");
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const multer = require("multer");
const { Pool } = require("pg");
const { v2: cloudinary } = require("cloudinary");
require("dotenv").config();

const app = express();
const port = Number(process.env.PORT) || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.DATABASE_URL && !process.env.DATABASE_URL.includes("localhost")
      ? { rejectUnauthorized: false }
      : false,
});

const BRAND_VALUES = new Set(["sholly-home", "apex-apparel"]);
const SESSION_COOKIE_NAME = "admin_session";
const SESSION_TTL_SECONDS = Number(process.env.ADMIN_SESSION_TTL_SECONDS || 60 * 60 * 12);
const CUSTOMER_SESSION_COOKIE_NAME = "customer_session";
const CUSTOMER_SESSION_TTL_SECONDS = Number(process.env.CUSTOMER_SESSION_TTL_SECONDS || 60 * 60 * 24 * 14);
const PAYSTACK_BASE_URL = "https://api.paystack.co";
const MONIEPOINT_BASE_URL = String(process.env.MONIEPOINT_BASE_URL || "https://api.monnify.com").replace(/\/+$/, "");
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const ADMIN_BOOTSTRAP_ROLE = process.env.ADMIN_BOOTSTRAP_ROLE || "owner";
const DEFAULT_SHIPPING_FEE_KOBO = Number.parseInt(process.env.DEFAULT_SHIPPING_FEE_KOBO || "550000", 10);
const FREE_SHIPPING_THRESHOLD_KOBO = Number.parseInt(process.env.FREE_SHIPPING_THRESHOLD_KOBO || "0", 10);
const ADMIN_LOGIN_MAX_ATTEMPTS = Number.parseInt(process.env.ADMIN_LOGIN_MAX_ATTEMPTS || "8", 10);
const ADMIN_LOGIN_WINDOW_SECONDS = Number.parseInt(process.env.ADMIN_LOGIN_WINDOW_SECONDS || "900", 10);
const ADMIN_LOGIN_BLOCK_SECONDS = Number.parseInt(process.env.ADMIN_LOGIN_BLOCK_SECONDS || "900", 10);
const ROLE_LEVEL = {
  viewer: 1,
  editor: 2,
  manager: 3,
  owner: 4,
};
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 },
});

const cloudinaryConfig = {
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
};

function isCloudinaryConfigured() {
  return Boolean(
    cloudinaryConfig.cloud_name &&
      cloudinaryConfig.api_key &&
      cloudinaryConfig.api_secret
  );
}

if (isCloudinaryConfigured()) {
  cloudinary.config(cloudinaryConfig);
}

const moniepointTokenCache = {
  token: "",
  expiresAtMs: 0,
};

const adminLoginAttempts = new Map();

function getSessionSecret() {
  // Backward compatible fallback to ADMIN_API_KEY if SESSION_SECRET is not set.
  return process.env.SESSION_SECRET || process.env.ADMIN_API_KEY || "";
}

function safeEqualText(a, b) {
  const ah = crypto.createHash("sha256").update(String(a)).digest();
  const bh = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(ah, bh);
}

function parseCookieHeader(cookieHeader) {
  const out = {};
  if (!cookieHeader) return out;
  const parts = String(cookieHeader).split(";");
  for (const rawPart of parts) {
    const part = rawPart.trim();
    const index = part.indexOf("=");
    if (index < 1) continue;
    const key = part.slice(0, index).trim();
    let value;
    try {
      value = decodeURIComponent(part.slice(index + 1).trim());
    } catch (_error) {
      value = part.slice(index + 1).trim();
    }
    out[key] = value;
  }
  return out;
}

function createAdminSessionToken({
  username,
  role = "owner",
  userId = null,
  source = "env",
  sessionId = crypto.randomUUID(),
  csrfToken = crypto.randomBytes(24).toString("hex"),
}) {
  const payloadObj = {
    u: String(username),
    r: String(role || "owner"),
    id: userId === null || userId === undefined ? null : Number(userId),
    s: String(source || "env"),
    sid: String(sessionId),
    csrf: String(csrfToken),
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
  };
  const payload = Buffer.from(JSON.stringify(payloadObj)).toString("base64url");
  const signature = crypto
    .createHmac("sha256", getSessionSecret())
    .update(payload)
    .digest("base64url");
  return `${payload}.${signature}`;
}

function verifyAdminSessionToken(token) {
  try {
    if (!getSessionSecret()) return null;
    if (!token || !token.includes(".")) return null;
    const [payload, incomingSignature] = token.split(".", 2);
    const expectedSignature = crypto
      .createHmac("sha256", getSessionSecret())
      .update(payload)
      .digest("base64url");
    if (!safeEqualText(incomingSignature, expectedSignature)) {
      return null;
    }
    const parsed = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (!parsed || typeof parsed !== "object") return null;
    if (!parsed.exp || parsed.exp < Math.floor(Date.now() / 1000)) return null;
    if (!parsed.u) return null;
    const role = String(parsed.r || "owner");
    return {
      userId: parsed.id === null || parsed.id === undefined ? null : Number(parsed.id),
      username: String(parsed.u),
      role,
      source: String(parsed.s || "env"),
      sessionId: parsed.sid ? String(parsed.sid) : "",
      csrfToken: parsed.csrf ? String(parsed.csrf) : "",
      exp: Number(parsed.exp),
    };
  } catch (_error) {
    return null;
  }
}

function getAdminSession(req) {
  const cookies = parseCookieHeader(req.headers.cookie || "");
  return verifyAdminSessionToken(cookies[SESSION_COOKIE_NAME]);
}

function createCustomerSessionToken({
  customerId,
  email,
  sessionId = crypto.randomUUID(),
  csrfToken = crypto.randomBytes(24).toString("hex"),
}) {
  const payloadObj = {
    cid: Number(customerId),
    em: String(email || ""),
    sid: String(sessionId),
    csrf: String(csrfToken),
    exp: Math.floor(Date.now() / 1000) + CUSTOMER_SESSION_TTL_SECONDS,
  };
  const payload = Buffer.from(JSON.stringify(payloadObj)).toString("base64url");
  const signature = crypto
    .createHmac("sha256", getSessionSecret())
    .update(payload)
    .digest("base64url");
  return `${payload}.${signature}`;
}

function verifyCustomerSessionToken(token) {
  try {
    if (!getSessionSecret()) return null;
    if (!token || !token.includes(".")) return null;
    const [payload, incomingSignature] = token.split(".", 2);
    const expectedSignature = crypto
      .createHmac("sha256", getSessionSecret())
      .update(payload)
      .digest("base64url");
    if (!safeEqualText(incomingSignature, expectedSignature)) {
      return null;
    }
    const parsed = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (!parsed || typeof parsed !== "object") return null;
    if (!parsed.exp || parsed.exp < Math.floor(Date.now() / 1000)) return null;
    if (!parsed.cid || !parsed.sid || !parsed.csrf) return null;
    return {
      customerId: Number(parsed.cid),
      email: String(parsed.em || ""),
      sessionId: String(parsed.sid),
      csrfToken: String(parsed.csrf),
      exp: Number(parsed.exp),
    };
  } catch (_error) {
    return null;
  }
}

function getCustomerSession(req) {
  const cookies = parseCookieHeader(req.headers.cookie || "");
  return verifyCustomerSessionToken(cookies[CUSTOMER_SESSION_COOKIE_NAME]);
}

async function issueCustomerSession(req, res, { customerId, email }) {
  if (!getSessionSecret()) {
    throw new Error("Session signing secret missing. Set SESSION_SECRET (or ADMIN_API_KEY) in .env.");
  }
  const sessionId = crypto.randomUUID();
  const csrfToken = crypto.randomBytes(24).toString("hex");
  const token = createCustomerSessionToken({
    customerId,
    email,
    sessionId,
    csrfToken,
  });
  const isSecure = req.secure || req.headers["x-forwarded-proto"] === "https";
  await pool.query(
    `INSERT INTO customer_sessions
      (session_id, customer_id, user_agent, ip_address, csrf_token, expires_at, revoked)
     VALUES
      ($1, $2, $3, $4, $5, NOW() + ($6::text || ' seconds')::interval, FALSE)`,
    [
      sessionId,
      Number(customerId),
      String(req.headers["user-agent"] || ""),
      getRequestIp(req),
      csrfToken,
      String(CUSTOMER_SESSION_TTL_SECONDS),
    ]
  );
  res.cookie(CUSTOMER_SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: Boolean(isSecure),
    maxAge: CUSTOMER_SESSION_TTL_SECONDS * 1000,
    path: "/",
  });
  return { sessionId, csrfToken, expiresInSeconds: CUSTOMER_SESSION_TTL_SECONDS };
}

function isPaystackConfigured() {
  return Boolean(process.env.PAYSTACK_SECRET_KEY && process.env.PAYSTACK_PUBLIC_KEY);
}

function isMoniepointConfigured() {
  return Boolean(
    process.env.MONIEPOINT_API_KEY &&
      process.env.MONIEPOINT_SECRET_KEY &&
      process.env.MONIEPOINT_CONTRACT_CODE
  );
}

function normalizeWhatsAppNumber(value) {
  return String(value || "")
    .replace(/[^\d]/g, "")
    .trim();
}

function normalizeRegionText(value) {
  return String(value || "")
    .trim()
    .replace(/\s+/g, " ");
}

function shippingRuleForState(stateRaw) {
  const state = String(stateRaw || "").trim().toLowerCase();
  if (!state) return { feeKobo: Math.max(DEFAULT_SHIPPING_FEE_KOBO, 0) };
  if (state.includes("lagos")) return { feeKobo: 300000 };
  if (state.includes("abuja") || state.includes("fct")) return { feeKobo: 400000 };
  if (state.includes("rivers")) return { feeKobo: 450000 };
  if (state.includes("oyo") || state.includes("kano") || state.includes("kaduna")) return { feeKobo: 500000 };
  return { feeKobo: Math.max(DEFAULT_SHIPPING_FEE_KOBO, 0) };
}

function computeShippingFeeKobo(stateRaw, cityRaw, subtotalKobo = 0) {
  const shippingState = normalizeRegionText(stateRaw);
  const shippingCity = normalizeRegionText(cityRaw);
  const subtotal = toKobo(subtotalKobo);

  if (FREE_SHIPPING_THRESHOLD_KOBO > 0 && subtotal >= FREE_SHIPPING_THRESHOLD_KOBO) {
    return {
      shippingFeeKobo: 0,
      shippingState,
      shippingCity,
      freeShippingApplied: true,
    };
  }

  const stateRule = shippingRuleForState(shippingState);
  let shippingFeeKobo = Number(stateRule.feeKobo || 0);
  const city = shippingCity.toLowerCase();
  if (shippingState.toLowerCase().includes("lagos") && city) {
    const islandKeywords = ["lekki", "ikoyi", "victoria island", "vi", "ajah"];
    const mainlandKeywords = ["ikeja", "yaba", "surulere", "maryland", "ogba"];
    if (islandKeywords.some((key) => city.includes(key))) {
      shippingFeeKobo = 350000;
    } else if (mainlandKeywords.some((key) => city.includes(key))) {
      shippingFeeKobo = 280000;
    }
  }

  return {
    shippingFeeKobo: Math.max(Number(shippingFeeKobo || 0), 0),
    shippingState,
    shippingCity,
    freeShippingApplied: false,
  };
}

async function getShippingSettingsFromDb(client = pool) {
  try {
    const result = await client.query(
      `SELECT
        default_fee_kobo, free_shipping_threshold_kobo, eta_min_days, eta_max_days, updated_at
       FROM shipping_settings
       WHERE id = 1
       LIMIT 1`
    );
    if (!result.rowCount) {
      return {
        defaultFeeKobo: Math.max(DEFAULT_SHIPPING_FEE_KOBO, 0),
        freeShippingThresholdKobo: Math.max(FREE_SHIPPING_THRESHOLD_KOBO, 0),
        etaMinDays: 1,
        etaMaxDays: 5,
        updatedAt: null,
      };
    }
    const row = result.rows[0];
    return {
      defaultFeeKobo: Math.max(Number(row.default_fee_kobo || DEFAULT_SHIPPING_FEE_KOBO), 0),
      freeShippingThresholdKobo: Math.max(
        Number(row.free_shipping_threshold_kobo || FREE_SHIPPING_THRESHOLD_KOBO),
        0
      ),
      etaMinDays: Math.max(Number(row.eta_min_days || 1), 0),
      etaMaxDays: Math.max(Number(row.eta_max_days || 5), 0),
      updatedAt: row.updated_at || null,
    };
  } catch (_error) {
    return {
      defaultFeeKobo: Math.max(DEFAULT_SHIPPING_FEE_KOBO, 0),
      freeShippingThresholdKobo: Math.max(FREE_SHIPPING_THRESHOLD_KOBO, 0),
      etaMinDays: 1,
      etaMaxDays: 5,
      updatedAt: null,
    };
  }
}

async function computeShippingQuote(client, stateRaw, cityRaw, subtotalKobo = 0) {
  const shippingState = normalizeRegionText(stateRaw);
  const shippingCity = normalizeRegionText(cityRaw);
  const subtotal = toKobo(subtotalKobo);

  if (!shippingState) {
    return {
      shippingState: "",
      shippingCity,
      shippingFeeKobo: 0,
      freeShippingApplied: false,
      etaMinDays: null,
      etaMaxDays: null,
      isBlackout: false,
      blackoutNote: "",
      ruleId: null,
      ruleLabel: "",
    };
  }

  const settings = await getShippingSettingsFromDb(client);

  let blackout = null;
  try {
    const blackoutResult = await client.query(
      `SELECT id, note
       FROM shipping_blackout_dates
       WHERE is_active = TRUE
         AND starts_at <= NOW()
         AND ends_at >= NOW()
       ORDER BY starts_at ASC
       LIMIT 1`
    );
    blackout = blackoutResult.rows[0] || null;
  } catch (_error) {
    blackout = null;
  }

  let matchedRule = null;
  try {
    const ruleResult = await client.query(
      `SELECT
        id, state_text, city_text, fee_kobo, eta_min_days, eta_max_days, priority
       FROM shipping_rules
       WHERE is_active = TRUE
         AND (
           LOWER(state_text) = LOWER($1)
           OR state_text = '*'
         )
         AND (
           city_text IS NULL
           OR city_text = ''
           OR LOWER(city_text) = LOWER($2)
         )
       ORDER BY
         CASE
           WHEN LOWER(state_text) = LOWER($1) THEN 0
           ELSE 1
         END ASC,
         CASE
           WHEN city_text IS NOT NULL AND city_text <> '' AND LOWER(city_text) = LOWER($2) THEN 0
           ELSE 1
         END ASC,
         priority ASC,
         id ASC
       LIMIT 1`,
      [shippingState, shippingCity]
    );
    matchedRule = ruleResult.rows[0] || null;
  } catch (_error) {
    matchedRule = null;
  }

  const freeThreshold = Math.max(Number(settings.freeShippingThresholdKobo || 0), 0);
  const freeShippingApplied = freeThreshold > 0 && subtotal >= freeThreshold;
  const fallback = computeShippingFeeKobo(shippingState, shippingCity, subtotal);
  const feeKobo = freeShippingApplied
    ? 0
    : matchedRule
      ? Math.max(Number(matchedRule.fee_kobo || 0), 0)
      : fallback.shippingFeeKobo;
  const etaMinDays = matchedRule
    ? (matchedRule.eta_min_days === null ? settings.etaMinDays : Number(matchedRule.eta_min_days))
    : Number(settings.etaMinDays || 0);
  const etaMaxDays = matchedRule
    ? (matchedRule.eta_max_days === null ? settings.etaMaxDays : Number(matchedRule.eta_max_days))
    : Number(settings.etaMaxDays || 0);

  return {
    shippingState,
    shippingCity,
    shippingFeeKobo: Math.max(Number(feeKobo || 0), 0),
    freeShippingApplied,
    etaMinDays: Number.isFinite(etaMinDays) ? Math.max(etaMinDays, 0) : null,
    etaMaxDays: Number.isFinite(etaMaxDays) ? Math.max(etaMaxDays, 0) : null,
    isBlackout: Boolean(blackout),
    blackoutNote: blackout?.note || "",
    blackoutId: blackout ? Number(blackout.id) : null,
    ruleId: matchedRule ? Number(matchedRule.id) : null,
    ruleLabel: matchedRule
      ? `${matchedRule.state_text}${matchedRule.city_text ? ` / ${matchedRule.city_text}` : ""}`
      : "default",
    defaultShippingFeeKobo: Math.max(Number(settings.defaultFeeKobo || 0), 0),
    freeShippingThresholdKobo: freeThreshold,
  };
}

function normalizeUsername(value) {
  return String(value || "").trim().toLowerCase();
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function roleLevel(role) {
  return ROLE_LEVEL[role] || 0;
}

function canAssignRole(actorRole, targetRole) {
  return roleLevel(actorRole) > roleLevel(targetRole);
}

function getRawRequestBody(req) {
  return req.rawBody || "";
}

function hashPassword(password, saltHex = crypto.randomBytes(16).toString("hex")) {
  const iterations = 310000;
  const hash = crypto
    .pbkdf2Sync(String(password), Buffer.from(saltHex, "hex"), iterations, 32, "sha256")
    .toString("hex");
  return `pbkdf2_sha256$${iterations}$${saltHex}$${hash}`;
}

function verifyPassword(password, encoded) {
  try {
    if (!encoded || !encoded.includes("$")) return false;
    const parts = String(encoded).split("$");
    if (parts.length !== 4 || parts[0] !== "pbkdf2_sha256") return false;
    const iterations = Number(parts[1]);
    const saltHex = parts[2];
    const expectedHash = parts[3];
    if (!Number.isFinite(iterations) || iterations < 10000) return false;
    const candidateHash = crypto
      .pbkdf2Sync(String(password), Buffer.from(saltHex, "hex"), iterations, 32, "sha256")
      .toString("hex");
    return safeEqualText(candidateHash, expectedHash);
  } catch (_error) {
    return false;
  }
}

function isSafeMethod(method) {
  const safe = new Set(["GET", "HEAD", "OPTIONS"]);
  return safe.has(String(method || "").toUpperCase());
}

function base32Encode(buffer) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }
  return output;
}

function base32Decode(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = String(input || "").toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = 0;
  let value = 0;
  const out = [];
  for (const char of clean) {
    const idx = alphabet.indexOf(char);
    if (idx < 0) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function generateTotpSecret() {
  return base32Encode(crypto.randomBytes(20));
}

function computeTotp(secret, timestampMs = Date.now(), stepSeconds = 30, digits = 6) {
  const key = base32Decode(secret);
  if (!key.length) return null;
  const counter = Math.floor(timestampMs / 1000 / stepSeconds);
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac("sha1", key).update(counterBuffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  const token = String(code % 10 ** digits).padStart(digits, "0");
  return token;
}

function verifyTotpCode(secret, codeInput, windowSteps = 1) {
  const code = String(codeInput || "").replace(/[^\d]/g, "");
  if (code.length !== 6) return false;
  for (let offset = -windowSteps; offset <= windowSteps; offset += 1) {
    const generated = computeTotp(secret, Date.now() + offset * 30 * 1000);
    if (generated && safeEqualText(code, generated)) {
      return true;
    }
  }
  return false;
}

function loginAttemptKey(ip, username) {
  return `${String(ip || "").trim().toLowerCase()}|${String(username || "").trim().toLowerCase()}`;
}

function checkAdminLoginThrottle(ip, username) {
  const key = loginAttemptKey(ip, username);
  const now = Date.now();
  const entry = adminLoginAttempts.get(key);
  if (!entry) {
    return { blocked: false, retryAfterSeconds: 0 };
  }
  if (entry.blockedUntilMs && entry.blockedUntilMs > now) {
    return {
      blocked: true,
      retryAfterSeconds: Math.max(Math.ceil((entry.blockedUntilMs - now) / 1000), 1),
    };
  }
  if (entry.windowStartedMs + ADMIN_LOGIN_WINDOW_SECONDS * 1000 < now) {
    adminLoginAttempts.delete(key);
    return { blocked: false, retryAfterSeconds: 0 };
  }
  return { blocked: false, retryAfterSeconds: 0 };
}

function recordAdminLoginFailure(ip, username) {
  const key = loginAttemptKey(ip, username);
  const now = Date.now();
  const existing = adminLoginAttempts.get(key);
  if (!existing || existing.windowStartedMs + ADMIN_LOGIN_WINDOW_SECONDS * 1000 < now) {
    adminLoginAttempts.set(key, {
      count: 1,
      windowStartedMs: now,
      blockedUntilMs: 0,
    });
    return;
  }
  existing.count += 1;
  if (existing.count >= ADMIN_LOGIN_MAX_ATTEMPTS) {
    existing.blockedUntilMs = now + ADMIN_LOGIN_BLOCK_SECONDS * 1000;
  }
  adminLoginAttempts.set(key, existing);
}

function clearAdminLoginFailures(ip, username) {
  adminLoginAttempts.delete(loginAttemptKey(ip, username));
}

async function getValidatedAdminSession(req, { touch = true } = {}) {
  const session = getAdminSession(req);
  if (!session) return null;
  if (!session.sessionId) return session;

  try {
    const result = await pool.query(
      `SELECT
        session_id, admin_user_id, admin_username, role, source, csrf_token, expires_at, revoked
       FROM admin_sessions
       WHERE session_id = $1
       LIMIT 1`,
      [session.sessionId]
    );
    if (!result.rowCount) return null;
    const row = result.rows[0];
    if (row.revoked) return null;
    if (!row.expires_at || new Date(row.expires_at).getTime() <= Date.now()) return null;
    if (session.csrfToken && row.csrf_token && !safeEqualText(session.csrfToken, row.csrf_token)) return null;

    if (touch) {
      await pool.query(
        `UPDATE admin_sessions
         SET last_seen_at = NOW()
         WHERE session_id = $1`,
        [session.sessionId]
      );
    }
    return {
      userId: row.admin_user_id === null ? null : Number(row.admin_user_id),
      username: row.admin_username,
      role: row.role || session.role || "owner",
      source: row.source || session.source || "session",
      sessionId: session.sessionId,
      csrfToken: row.csrf_token || session.csrfToken || "",
      exp: session.exp,
    };
  } catch (_error) {
    return null;
  }
}

async function getValidatedCustomerSession(req, { touch = true } = {}) {
  const session = getCustomerSession(req);
  if (!session) return null;
  try {
    const result = await pool.query(
      `SELECT
        session_id, customer_id, csrf_token, expires_at, revoked
       FROM customer_sessions
       WHERE session_id = $1
       LIMIT 1`,
      [session.sessionId]
    );
    if (!result.rowCount) return null;
    const row = result.rows[0];
    if (row.revoked) return null;
    if (!row.expires_at || new Date(row.expires_at).getTime() <= Date.now()) return null;
    if (row.customer_id === null || Number(row.customer_id) !== Number(session.customerId)) return null;
    if (session.csrfToken && row.csrf_token && !safeEqualText(session.csrfToken, row.csrf_token)) return null;
    if (touch) {
      await pool.query(
        `UPDATE customer_sessions
         SET last_seen_at = NOW()
         WHERE session_id = $1`,
        [session.sessionId]
      );
    }
    return {
      customerId: Number(row.customer_id),
      email: session.email || "",
      sessionId: session.sessionId,
      csrfToken: row.csrf_token || session.csrfToken || "",
      exp: session.exp,
    };
  } catch (_error) {
    return null;
  }
}

function toKobo(amountValue) {
  const amount = Number(amountValue || 0);
  return Number.isFinite(amount) ? Math.max(Math.round(amount), 0) : 0;
}

app.use(
  express.json({
    limit: "1mb",
    verify: (req, _res, buffer) => {
      req.rawBody = buffer.toString("utf8");
    },
  })
);
app.use(express.static(path.join(__dirname, "public")));

const productFields = `
  id,
  name,
  slug,
  brand,
  category,
  description,
  price_kobo,
  compare_at_kobo,
  stock_qty,
  reorder_threshold,
  has_variants,
  image_url,
  gallery_urls,
  is_featured,
  created_at,
  updated_at
`;

function isCloudinaryUrl(url) {
  const value = String(url || "").trim();
  return value.includes("res.cloudinary.com") && value.includes("/upload/");
}

function cloudinaryOptimizedUrl(url, width = null) {
  const value = String(url || "").trim();
  if (!isCloudinaryUrl(value)) return value;
  const transforms = ["f_auto", "q_auto"];
  if (width && Number(width) > 0) {
    transforms.push(`w_${Math.round(Number(width))}`);
  }
  const token = `/upload/${transforms.join(",")}/`;
  return value.replace("/upload/", token);
}

function cloudinarySrcSet(url, widths = [320, 480, 640, 768, 960, 1200]) {
  if (!isCloudinaryUrl(url)) return null;
  return widths
    .map((width) => `${cloudinaryOptimizedUrl(url, width)} ${width}w`)
    .join(", ");
}

function buildVariantLabelFromValues(optionSize, optionColor, optionStyle) {
  const parts = [optionSize, optionColor, optionStyle]
    .map((value) => String(value || "").trim())
    .filter(Boolean);
  return parts.join(" / ");
}

function toProduct(row) {
  const imageUrl = row.image_url;
  return {
    id: Number(row.id),
    name: row.name,
    slug: row.slug,
    brand: row.brand,
    category: row.category,
    description: row.description,
    priceKobo: Number(row.price_kobo),
    compareAtKobo: row.compare_at_kobo === null ? null : Number(row.compare_at_kobo),
    stockQty: Number(row.stock_qty),
    reorderThreshold: Number(row.reorder_threshold || 0),
    hasVariants: Boolean(row.has_variants),
    imageUrl,
    imageUrlOptimized: cloudinaryOptimizedUrl(imageUrl),
    imageUrlThumb: cloudinaryOptimizedUrl(imageUrl, 480),
    imageSrcSet: cloudinarySrcSet(imageUrl),
    galleryUrls: row.gallery_urls || [],
    isFeatured: row.is_featured,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function toVariant(row) {
  const imageUrl = row.image_url || "";
  return {
    id: Number(row.id),
    productId: Number(row.product_id),
    sku: row.sku || "",
    optionSize: row.option_size || "",
    optionColor: row.option_color || "",
    optionStyle: row.option_style || "",
    label: buildVariantLabelFromValues(row.option_size, row.option_color, row.option_style),
    priceOverrideKobo:
      row.price_override_kobo === null || row.price_override_kobo === undefined
        ? null
        : Number(row.price_override_kobo),
    stockQty: Number(row.stock_qty || 0),
    reorderThreshold: Number(row.reorder_threshold || 0),
    imageUrl,
    imageUrlOptimized: cloudinaryOptimizedUrl(imageUrl),
    imageUrlThumb: cloudinaryOptimizedUrl(imageUrl, 480),
    imageSrcSet: cloudinarySrcSet(imageUrl),
    isActive: Boolean(row.is_active),
    createdAt: row.created_at || null,
    updatedAt: row.updated_at || null,
  };
}

function parseBoolean(value) {
  if (value === undefined) return undefined;
  if (value === "true" || value === true) return true;
  if (value === "false" || value === false) return false;
  return undefined;
}

function parseIntOrUndefined(value) {
  if (value === undefined || value === null || value === "") return undefined;
  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) ? undefined : parsed;
}

function parsePositiveInt(value) {
  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) || parsed <= 0 ? undefined : parsed;
}

function normalizeProductPayload(payload, { partial = false } = {}) {
  const errors = [];
  const data = {};

  const maybeSetText = (sourceKey, targetKey = sourceKey) => {
    if (payload[sourceKey] !== undefined) {
      const value = String(payload[sourceKey]).trim();
      if (!value) {
        errors.push(`${sourceKey} cannot be empty`);
      } else {
        data[targetKey] = value;
      }
    } else if (!partial) {
      errors.push(`${sourceKey} is required`);
    }
  };

  maybeSetText("name");
  maybeSetText("slug");
  maybeSetText("brand");
  maybeSetText("category");
  maybeSetText("imageUrl", "image_url");

  if (payload.description !== undefined) {
    data.description = String(payload.description).trim();
  } else if (!partial) {
    data.description = "";
  }

  if (payload.priceKobo !== undefined) {
    const price = parseIntOrUndefined(payload.priceKobo);
    if (price === undefined || price < 0) {
      errors.push("priceKobo must be a non-negative integer");
    } else {
      data.price_kobo = price;
    }
  } else if (!partial) {
    errors.push("priceKobo is required");
  }

  if (
    payload.compareAtKobo !== undefined &&
    payload.compareAtKobo !== null &&
    payload.compareAtKobo !== ""
  ) {
    const compare = parseIntOrUndefined(payload.compareAtKobo);
    if (compare === undefined || compare < 0) {
      errors.push("compareAtKobo must be null or a non-negative integer");
    } else {
      data.compare_at_kobo = compare;
    }
  } else if (payload.compareAtKobo === null || payload.compareAtKobo === "") {
    data.compare_at_kobo = null;
  } else if (!partial) {
    data.compare_at_kobo = null;
  }

  if (payload.stockQty !== undefined) {
    const stock = parseIntOrUndefined(payload.stockQty);
    if (stock === undefined || stock < 0) {
      errors.push("stockQty must be a non-negative integer");
    } else {
      data.stock_qty = stock;
    }
  } else if (!partial) {
    errors.push("stockQty is required");
  }

  if (payload.reorderThreshold !== undefined) {
    const threshold = parseIntOrUndefined(payload.reorderThreshold);
    if (threshold === undefined || threshold < 0) {
      errors.push("reorderThreshold must be a non-negative integer");
    } else {
      data.reorder_threshold = threshold;
    }
  } else if (!partial) {
    data.reorder_threshold = 5;
  }

  if (payload.isFeatured !== undefined) {
    const featured = parseBoolean(payload.isFeatured);
    if (featured === undefined) {
      errors.push("isFeatured must be true or false");
    } else {
      data.is_featured = featured;
    }
  } else if (!partial) {
    data.is_featured = false;
  }

  if (payload.galleryUrls !== undefined) {
    if (!Array.isArray(payload.galleryUrls)) {
      errors.push("galleryUrls must be an array of URLs");
    } else {
      data.gallery_urls = payload.galleryUrls
        .map((url) => String(url).trim())
        .filter(Boolean);
    }
  } else if (!partial) {
    data.gallery_urls = [];
  }

  if (payload.hasVariants !== undefined) {
    const hasVariants = parseBoolean(payload.hasVariants);
    if (hasVariants === undefined) {
      errors.push("hasVariants must be true or false");
    } else {
      data.has_variants = hasVariants;
    }
  } else if (!partial) {
    data.has_variants = false;
  }

  if (data.brand && !BRAND_VALUES.has(data.brand)) {
    errors.push("brand must be one of: sholly-home, apex-apparel");
  }

  if (
    data.compare_at_kobo !== undefined &&
    data.compare_at_kobo !== null &&
    data.price_kobo !== undefined &&
    data.compare_at_kobo < data.price_kobo
  ) {
    errors.push("compareAtKobo must be greater than or equal to priceKobo");
  }

  return { errors, data };
}

async function requireAdmin(req, res, next) {
  const session = await getValidatedAdminSession(req);
  if (session) {
    if (!isSafeMethod(req.method)) {
      const csrfHeader = String(req.get("x-csrf-token") || "").trim();
      if (!session.csrfToken || !csrfHeader || !safeEqualText(csrfHeader, session.csrfToken)) {
        return res.status(403).json({ error: "Invalid CSRF token." });
      }
    }
    req.admin = {
      userId: session.userId,
      username: session.username,
      role: session.role || "owner",
      source: session.source || "session",
      sessionId: session.sessionId || "",
      csrfToken: session.csrfToken || "",
    };
    return next();
  }

  const incomingKey = req.get("x-admin-key");
  const expectedKey = process.env.ADMIN_API_KEY;
  if (expectedKey && incomingKey && safeEqualText(incomingKey, expectedKey)) {
    req.admin = {
      userId: null,
      username: "api-key-admin",
      role: "owner",
      source: "api-key",
      sessionId: "",
      csrfToken: "",
    };
    return next();
  }

  return res.status(401).json({ error: "Unauthorized admin access." });
}

function requireRole(...roles) {
  const allowed = new Set(roles);
  return (req, res, next) => {
    const role = req.admin?.role || "viewer";
    if (!allowed.has(role)) {
      return res.status(403).json({ error: "Insufficient admin permissions." });
    }
    return next();
  };
}

async function requireCustomer(req, res, next) {
  const session = await getValidatedCustomerSession(req);
  if (!session) {
    return res.status(401).json({ error: "Customer authentication required." });
  }
  if (!isSafeMethod(req.method)) {
    const csrfHeader = String(req.get("x-customer-csrf-token") || "").trim();
    if (!session.csrfToken || !csrfHeader || !safeEqualText(csrfHeader, session.csrfToken)) {
      return res.status(403).json({ error: "Invalid customer CSRF token." });
    }
  }
  req.customer = {
    customerId: session.customerId,
    email: session.email || "",
    sessionId: session.sessionId,
    csrfToken: session.csrfToken || "",
  };
  return next();
}

function generateOrderNumber() {
  const now = new Date();
  const y = String(now.getFullYear()).slice(-2);
  const m = String(now.getMonth() + 1).padStart(2, "0");
  const d = String(now.getDate()).padStart(2, "0");
  const suffix = Math.floor(Math.random() * 9000 + 1000);
  return `SS-${y}${m}${d}-${suffix}`;
}

function sendPgError(res, error, fallbackMessage) {
  if (error.code === "23505") {
    return res.status(409).json({ error: "A record with this unique value already exists." });
  }
  if (error.code === "23514" || error.code === "22P02") {
    return res.status(400).json({ error: "Invalid values for database constraints." });
  }
  if (error.code === "23503") {
    return res.status(409).json({ error: "This record is referenced by other data." });
  }
  return res.status(500).json({ error: fallbackMessage });
}

async function paystackRequest(pathname, method = "GET", body = null) {
  const response = await fetch(`${PAYSTACK_BASE_URL}${pathname}`, {
    method,
    headers: {
      Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
      "Content-Type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  const parsed = await response.json().catch(() => ({}));
  if (!response.ok || !parsed.status) {
    const message =
      parsed.message ||
      parsed.error ||
      `Paystack request failed (${response.status})`;
    throw new Error(message);
  }
  return parsed.data;
}

async function getMoniepointAuthToken() {
  if (moniepointTokenCache.token && moniepointTokenCache.expiresAtMs > Date.now() + 30 * 1000) {
    return moniepointTokenCache.token;
  }

  const apiKey = String(process.env.MONIEPOINT_API_KEY || "").trim();
  const secretKey = String(process.env.MONIEPOINT_SECRET_KEY || "").trim();
  if (!apiKey || !secretKey) {
    throw new Error("Moniepoint credentials are missing.");
  }

  const basicToken = Buffer.from(`${apiKey}:${secretKey}`).toString("base64");
  const response = await fetch(`${MONIEPOINT_BASE_URL}/api/v1/auth/login`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basicToken}`,
      "Content-Type": "application/json",
    },
  });
  const parsed = await response.json().catch(() => ({}));
  const responseBody = parsed.responseBody || {};

  if (!response.ok || parsed.requestSuccessful === false || !responseBody.accessToken) {
    const message =
      parsed.responseMessage ||
      parsed.message ||
      `Moniepoint auth failed (${response.status})`;
    throw new Error(message);
  }

  const expiresInSeconds = Number(responseBody.expiresIn || 3590);
  moniepointTokenCache.token = String(responseBody.accessToken);
  moniepointTokenCache.expiresAtMs = Date.now() + Math.max(expiresInSeconds, 60) * 1000;
  return moniepointTokenCache.token;
}

async function moniepointRequest(pathname, method = "GET", body = null) {
  const token = await getMoniepointAuthToken();
  const response = await fetch(`${MONIEPOINT_BASE_URL}${pathname}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  const parsed = await response.json().catch(() => ({}));
  const responseBody = parsed.responseBody || parsed.data || null;
  const requestFailed =
    parsed.requestSuccessful === false ||
    (parsed.responseCode && String(parsed.responseCode) !== "0");

  if (!response.ok || requestFailed || !responseBody) {
    const message =
      parsed.responseMessage ||
      parsed.message ||
      `Moniepoint request failed (${response.status})`;
    throw new Error(message);
  }

  return responseBody;
}

function getMoniepointWebhookSecret() {
  return String(
    process.env.MONIEPOINT_WEBHOOK_SECRET ||
      process.env.MONNIFY_WEBHOOK_SECRET ||
      process.env.MONIEPOINT_SECRET_KEY ||
      ""
  ).trim();
}

function verifyMoniepointWebhookSignature(req) {
  const signature =
    String(req.headers["monnify-signature"] || "").trim() ||
    String(req.headers["x-monnify-signature"] || "").trim() ||
    String(req.headers["x-moniepoint-signature"] || "").trim();
  const secret = getMoniepointWebhookSecret();
  if (!signature || !secret) return false;
  const expected = crypto
    .createHmac("sha512", secret)
    .update(getRawRequestBody(req))
    .digest("hex");
  return safeEqualText(signature.toLowerCase(), expected.toLowerCase());
}

function getRequestIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) {
    return String(forwarded).split(",")[0].trim();
  }
  return req.socket?.remoteAddress || "";
}

async function writeAuditLog(req, action, entityType, entityId = null, metadata = {}) {
  try {
    await pool.query(
      `INSERT INTO audit_logs
        (admin_user_id, admin_username, action, entity_type, entity_id, metadata, ip_address, user_agent)
       VALUES
        ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)`,
      [
        req.admin?.userId || null,
        req.admin?.username || "system",
        String(action || ""),
        String(entityType || ""),
        entityId === null || entityId === undefined ? null : String(entityId),
        JSON.stringify(metadata || {}),
        getRequestIp(req),
        String(req.headers["user-agent"] || ""),
      ]
    );
  } catch (error) {
    console.error("audit-log-failed", error);
  }
}

async function appendOrderStatusHistory(
  client,
  orderId,
  previousStatus,
  newStatus,
  note = "",
  actor = { userId: null, username: "system" }
) {
  await client.query(
    `INSERT INTO order_status_history
      (order_id, previous_status, new_status, note, changed_by_user_id, changed_by_username)
     VALUES
      ($1, $2, $3, $4, $5, $6)`,
    [
      Number(orderId),
      previousStatus || null,
      String(newStatus),
      String(note || ""),
      actor.userId || null,
      String(actor.username || "system"),
    ]
  );
}

function computeCouponDiscount(coupon, subtotalKobo) {
  if (!coupon || subtotalKobo <= 0) return 0;
  if (coupon.discount_type === "percent") {
    const percent = Math.min(Math.max(Number(coupon.discount_value || 0), 0), 100);
    return Math.round((subtotalKobo * percent) / 100);
  }
  return Math.min(subtotalKobo, Number(coupon.discount_value || 0));
}

async function validateCouponForCart(client, codeRaw, subtotalKobo, brands = []) {
  const code = String(codeRaw || "").trim().toUpperCase();
  if (!code) {
    return { valid: false, error: "Coupon code is required." };
  }

  const result = await client.query(
    `SELECT
      id, code, description, discount_type, discount_value, min_order_kobo,
      max_discount_kobo, brand, is_active, usage_limit, used_count, starts_at, expires_at
     FROM coupons
     WHERE UPPER(code) = UPPER($1)
     LIMIT 1`,
    [code]
  );

  if (!result.rowCount) {
    return { valid: false, error: "Coupon not found." };
  }

  const coupon = result.rows[0];
  const now = new Date();

  if (!coupon.is_active) {
    return { valid: false, error: "Coupon is inactive." };
  }

  if (coupon.starts_at && new Date(coupon.starts_at) > now) {
    return { valid: false, error: "Coupon is not active yet." };
  }

  if (coupon.expires_at && new Date(coupon.expires_at) < now) {
    return { valid: false, error: "Coupon has expired." };
  }

  if (Number(coupon.min_order_kobo || 0) > subtotalKobo) {
    return { valid: false, error: "Cart total does not meet coupon minimum order value." };
  }

  if (coupon.usage_limit !== null && Number(coupon.used_count || 0) >= Number(coupon.usage_limit)) {
    return { valid: false, error: "Coupon usage limit has been reached." };
  }

  if (coupon.brand) {
    const hasBrand = brands.includes(String(coupon.brand));
    if (!hasBrand) {
      return { valid: false, error: `Coupon only applies to ${coupon.brand}.` };
    }
  }

  let discountKobo = computeCouponDiscount(coupon, subtotalKobo);
  if (coupon.max_discount_kobo !== null && coupon.max_discount_kobo !== undefined) {
    discountKobo = Math.min(discountKobo, Number(coupon.max_discount_kobo));
  }
  discountKobo = Math.max(0, Math.min(discountKobo, subtotalKobo));

  return {
    valid: true,
    coupon: {
      id: Number(coupon.id),
      code: String(coupon.code).toUpperCase(),
      description: coupon.description || "",
      discountType: coupon.discount_type,
      discountValue: Number(coupon.discount_value),
      minOrderKobo: Number(coupon.min_order_kobo || 0),
      maxDiscountKobo:
        coupon.max_discount_kobo === null || coupon.max_discount_kobo === undefined
          ? null
          : Number(coupon.max_discount_kobo),
      brand: coupon.brand || null,
      usageLimit:
        coupon.usage_limit === null || coupon.usage_limit === undefined
          ? null
          : Number(coupon.usage_limit),
      usedCount: Number(coupon.used_count || 0),
      expiresAt: coupon.expires_at || null,
    },
    discountKobo,
  };
}

function buildVariantLabel(variant) {
  return buildVariantLabelFromValues(variant.option_size, variant.option_color, variant.option_style);
}

function normalizeCartItemsWithVariants(itemsRaw) {
  const input = Array.isArray(itemsRaw) ? itemsRaw : [];
  const merged = new Map();
  for (const raw of input) {
    const productId = parsePositiveInt(raw.productId);
    const qty = parsePositiveInt(raw.qty);
    const variantId =
      raw.variantId === undefined || raw.variantId === null || raw.variantId === ""
        ? null
        : parsePositiveInt(raw.variantId);
    if (!productId || !qty) {
      return { valid: false, error: "Each item must include valid productId and qty." };
    }
    if (raw.variantId !== undefined && raw.variantId !== null && raw.variantId !== "" && !variantId) {
      return { valid: false, error: "variantId must be a positive integer when provided." };
    }
    const key = `${productId}:${variantId || 0}`;
    const existing = merged.get(key) || { productId, variantId, qty: 0 };
    existing.qty += qty;
    merged.set(key, existing);
  }
  return { valid: true, items: Array.from(merged.values()) };
}

async function fetchCatalogForCartItems(client, normalizedItems, { lockRows = false } = {}) {
  const productIds = Array.from(new Set(normalizedItems.map((item) => item.productId)));
  const variantIds = Array.from(
    new Set(
      normalizedItems
        .map((item) => (item.variantId === null ? null : Number(item.variantId)))
        .filter((value) => Number.isFinite(value) && value > 0)
    )
  );

  const productSql = `SELECT id, name, brand, price_kobo, stock_qty, has_variants, image_url
    FROM products
    WHERE id = ANY($1::bigint[])
    ${lockRows ? "FOR UPDATE" : ""}`;
  const productsResult = await client.query(productSql, [productIds]);
  const productMap = new Map(
    productsResult.rows.map((row) => [
      Number(row.id),
      {
        id: Number(row.id),
        name: row.name,
        brand: row.brand,
        priceKobo: Number(row.price_kobo),
        stockQty: Number(row.stock_qty),
        hasVariants: Boolean(row.has_variants),
        imageUrl: row.image_url || "",
      },
    ])
  );

  if (productMap.size !== productIds.length) {
    return { valid: false, error: "One or more cart items are no longer available." };
  }

  const variantMap = new Map();
  if (variantIds.length) {
    const variantSql = `SELECT
      id, product_id, sku, option_size, option_color, option_style,
      price_override_kobo, stock_qty, reorder_threshold, image_url, is_active
      FROM product_variants
      WHERE id = ANY($1::bigint[])
      ${lockRows ? "FOR UPDATE" : ""}`;
    const variantsResult = await client.query(variantSql, [variantIds]);
    for (const row of variantsResult.rows) {
      variantMap.set(Number(row.id), {
        id: Number(row.id),
        productId: Number(row.product_id),
        sku: row.sku,
        option_size: row.option_size || "",
        option_color: row.option_color || "",
        option_style: row.option_style || "",
        label: buildVariantLabel(row),
        priceOverrideKobo:
          row.price_override_kobo === null ? null : Number(row.price_override_kobo),
        stockQty: Number(row.stock_qty),
        reorderThreshold: Number(row.reorder_threshold || 0),
        imageUrl: row.image_url || "",
        isActive: Boolean(row.is_active),
      });
    }
    if (variantMap.size !== variantIds.length) {
      return { valid: false, error: "One or more selected product variants are unavailable." };
    }
  }

  for (const item of normalizedItems) {
    const product = productMap.get(item.productId);
    if (!product) continue;
    if (product.hasVariants && (item.variantId === null || item.variantId === undefined)) {
      return { valid: false, error: `Select a variant for "${product.name}".` };
    }
  }

  return {
    valid: true,
    productMap,
    variantMap,
  };
}

async function insertStockMovement(
  client,
  {
    productId = null,
    variantId = null,
    movementType = "manual",
    deltaQty = 0,
    reason = "",
    referenceType = null,
    referenceId = null,
    adminUserId = null,
    adminUsername = "system",
  } = {}
) {
  if (!productId && !variantId) return;
  await client.query(
    `INSERT INTO stock_movements
      (product_id, variant_id, movement_type, delta_qty, reason, reference_type, reference_id, admin_user_id, admin_username)
     VALUES
      ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
    [
      productId ? Number(productId) : null,
      variantId ? Number(variantId) : null,
      String(movementType || "manual"),
      Number(deltaQty || 0),
      String(reason || ""),
      referenceType ? String(referenceType) : null,
      referenceId === null || referenceId === undefined ? null : String(referenceId),
      adminUserId === null || adminUserId === undefined ? null : Number(adminUserId),
      String(adminUsername || "system"),
    ]
  );
}

async function finalizePaidOrderByReference(
  reference,
  { paidAmountKobo = null, actor = null, note = "", referenceColumn = "paystack_reference", paymentChannel = null } = {}
) {
  const allowedColumns = new Set(["paystack_reference", "moniepoint_reference"]);
  const lookupColumn = allowedColumns.has(referenceColumn) ? referenceColumn : "paystack_reference";
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const orderResult = await client.query(
      `SELECT id, order_number, subtotal_kobo, total_kobo, coupon_code, coupon_discount_kobo, status
       FROM orders
       WHERE ${lookupColumn} = $1
       FOR UPDATE`,
      [reference]
    );
    if (!orderResult.rowCount) {
      await client.query("ROLLBACK");
      return { notFound: true };
    }

    const order = orderResult.rows[0];
    const totalKobo = Number(order.total_kobo || order.subtotal_kobo || 0);

    if (["paid", "processing", "shipped", "delivered"].includes(order.status)) {
      await client.query("COMMIT");
      return {
        alreadyPaid: true,
        order: {
          id: Number(order.id),
          orderNumber: order.order_number,
          subtotalKobo: Number(order.subtotal_kobo),
          totalKobo,
          status: order.status,
        },
      };
    }

    if (paidAmountKobo !== null && Number(paidAmountKobo) < totalKobo) {
      await client.query("ROLLBACK");
      return { invalidAmount: true, expectedAmountKobo: totalKobo };
    }

    const itemsResult = await client.query(
      `SELECT product_id, variant_id, product_name, variant_sku, variant_label, qty
       FROM order_items
       WHERE order_id = $1`,
      [order.id]
    );
    if (!itemsResult.rowCount) {
      await client.query("ROLLBACK");
      return { invalidOrder: true, error: "Order has no line items." };
    }

    const productIds = Array.from(
      new Set(
        itemsResult.rows
          .filter((item) => item.variant_id === null || item.variant_id === undefined)
          .map((item) => Number(item.product_id))
          .filter((id) => Number.isFinite(id) && id > 0)
      )
    );
    const variantIds = Array.from(
      new Set(
        itemsResult.rows
          .map((item) => (item.variant_id === null ? null : Number(item.variant_id)))
          .filter((id) => Number.isFinite(id) && id > 0)
      )
    );

    const productsResult = productIds.length
      ? await client.query(
          `SELECT id, stock_qty
           FROM products
           WHERE id = ANY($1::bigint[])
           FOR UPDATE`,
          [productIds]
        )
      : { rows: [] };
    const variantsResult = variantIds.length
      ? await client.query(
          `SELECT id, product_id, sku, stock_qty, is_active
           FROM product_variants
           WHERE id = ANY($1::bigint[])
           FOR UPDATE`,
          [variantIds]
        )
      : { rows: [] };
    const stockMap = new Map(productsResult.rows.map((row) => [Number(row.id), Number(row.stock_qty)]));
    const variantStockMap = new Map(
      variantsResult.rows.map((row) => [
        Number(row.id),
        {
          productId: Number(row.product_id),
          sku: row.sku || "",
          stockQty: Number(row.stock_qty),
          isActive: Boolean(row.is_active),
        },
      ])
    );

    for (const item of itemsResult.rows) {
      const variantId =
        item.variant_id === null || item.variant_id === undefined ? null : Number(item.variant_id);
      const qty = Number(item.qty);
      if (variantId) {
        const variant = variantStockMap.get(variantId);
        if (
          !variant ||
          !variant.isActive ||
          variant.stockQty < qty ||
          Number(item.product_id) !== Number(variant.productId)
        ) {
          await client.query("ROLLBACK");
          return {
            stockConflict: true,
            error: `Stock conflict for "${item.product_name}" variant.`,
          };
        }
      } else {
        const productId = Number(item.product_id);
        const stock = stockMap.get(productId);
        if (stock === undefined || stock < qty) {
          await client.query("ROLLBACK");
          return {
            stockConflict: true,
            error: `Stock conflict for "${item.product_name}".`,
          };
        }
      }
    }

    for (const item of itemsResult.rows) {
      const variantId =
        item.variant_id === null || item.variant_id === undefined ? null : Number(item.variant_id);
      const qty = Number(item.qty);
      if (variantId) {
        await client.query(
          `UPDATE product_variants
           SET stock_qty = stock_qty - $1, updated_at = NOW()
           WHERE id = $2`,
          [qty, variantId]
        );
        await insertStockMovement(client, {
          productId: Number(item.product_id),
          variantId,
          movementType: "sale",
          deltaQty: -qty,
          reason: "Order payment finalized",
          referenceType: "order",
          referenceId: order.order_number,
          adminUserId: actor?.userId || null,
          adminUsername: actor?.username || "system",
        });
      } else {
        await client.query(
          `UPDATE products
           SET stock_qty = stock_qty - $1, updated_at = NOW()
           WHERE id = $2`,
          [qty, Number(item.product_id)]
        );
        await insertStockMovement(client, {
          productId: Number(item.product_id),
          movementType: "sale",
          deltaQty: -qty,
          reason: "Order payment finalized",
          referenceType: "order",
          referenceId: order.order_number,
          adminUserId: actor?.userId || null,
          adminUsername: actor?.username || "system",
        });
      }
    }

    await client.query(
      `UPDATE orders
       SET status = 'paid',
           paid_at = COALESCE(paid_at, NOW()),
           payment_channel = COALESCE(payment_channel, $2),
           payment_proof_status = CASE
             WHEN payment_proof_status = 'pending_review' THEN 'approved'
             ELSE payment_proof_status
           END,
           payment_reviewed_at = CASE
             WHEN payment_proof_status = 'pending_review' THEN COALESCE(payment_reviewed_at, NOW())
             ELSE payment_reviewed_at
           END,
           payment_reviewed_by = CASE
             WHEN payment_proof_status = 'pending_review' THEN COALESCE(payment_reviewed_by, $3)
             ELSE payment_reviewed_by
           END,
           payment_verified_at = COALESCE(payment_verified_at, NOW()),
           payment_verified_by = COALESCE(payment_verified_by, $3),
           updated_at = NOW()
       WHERE id = $1`,
      [
        order.id,
        paymentChannel || (lookupColumn === "moniepoint_reference" ? "moniepoint" : "paystack"),
        actor?.username || "system",
      ]
    );

    if (order.coupon_code) {
      const couponResult = await client.query(
        `SELECT id FROM coupons WHERE UPPER(code) = UPPER($1) LIMIT 1`,
        [order.coupon_code]
      );
      if (couponResult.rowCount) {
        const couponId = Number(couponResult.rows[0].id);
        const existingRedemption = await client.query(
          `SELECT 1 FROM coupon_redemptions WHERE coupon_id = $1 AND order_id = $2 LIMIT 1`,
          [couponId, order.id]
        );
        if (!existingRedemption.rowCount) {
          await client.query(
            `INSERT INTO coupon_redemptions (coupon_id, order_id, code, discount_kobo)
             VALUES ($1, $2, $3, $4)`,
            [couponId, order.id, order.coupon_code, Number(order.coupon_discount_kobo || 0)]
          );
          await client.query(
            `UPDATE coupons
             SET used_count = used_count + 1, updated_at = NOW()
             WHERE id = $1`,
            [couponId]
          );
        }
      }
    }

    await appendOrderStatusHistory(
      client,
      order.id,
      order.status,
      "paid",
      note || "Payment verified",
      actor || { userId: null, username: "system" }
    );

    await client.query("COMMIT");
    return {
      paid: true,
      order: {
        id: Number(order.id),
        orderNumber: order.order_number,
        subtotalKobo: Number(order.subtotal_kobo),
        totalKobo,
        status: "paid",
      },
    };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, timestamp: new Date().toISOString() });
});

app.get("/health", (_req, res) => {
  res.json({ ok: true, timestamp: new Date().toISOString() });
});

app.get("/api/public-config", async (_req, res) => {
  const shippingSettings = await getShippingSettingsFromDb(pool);
  res.json({
    paystackPublicKey: process.env.PAYSTACK_PUBLIC_KEY || "",
    paystackEnabled: isPaystackConfigured(),
    moniepointEnabled: isMoniepointConfigured(),
    instagramShollyUrl: process.env.INSTAGRAM_SHOLLY_URL || "",
    instagramApexUrl: process.env.INSTAGRAM_APEX_URL || "",
    whatsappNumber: normalizeWhatsAppNumber(process.env.WHATSAPP_NUMBER || "2348101653634"),
    bankName: String(process.env.BANK_NAME || "").trim(),
    bankAccountName: String(process.env.BANK_ACCOUNT_NAME || "").trim(),
    bankAccountNumber: String(process.env.BANK_ACCOUNT_NUMBER || "").trim(),
    bankTransferInstructions:
      String(
        process.env.BANK_TRANSFER_INSTRUCTIONS ||
          "Complete transfer, then send your order number on WhatsApp for confirmation."
      ).trim(),
    defaultShippingFeeKobo: Math.max(Number(shippingSettings.defaultFeeKobo || DEFAULT_SHIPPING_FEE_KOBO), 0),
    freeShippingThresholdKobo: Math.max(
      Number(shippingSettings.freeShippingThresholdKobo || FREE_SHIPPING_THRESHOLD_KOBO),
      0
    ),
    shippingEtaMinDays: Math.max(Number(shippingSettings.etaMinDays || 1), 0),
    shippingEtaMaxDays: Math.max(Number(shippingSettings.etaMaxDays || 5), 0),
    cloudinaryOptimizationEnabled: true,
  });
});

app.get("/api/admin/me", async (req, res) => {
  const session = await getValidatedAdminSession(req);
  if (!session) {
    return res.status(401).json({ authenticated: false });
  }
  let twoFactorEnabled = false;
  if (session.userId) {
    try {
      const userResult = await pool.query(
        `SELECT totp_enabled FROM admin_users WHERE id = $1 LIMIT 1`,
        [session.userId]
      );
      twoFactorEnabled = Boolean(userResult.rows[0]?.totp_enabled);
    } catch (_error) {
      twoFactorEnabled = false;
    }
  }
  return res.json({
    authenticated: true,
    userId: session.userId,
    username: session.username,
    role: session.role || "owner",
    source: session.source || "session",
    csrfToken: session.csrfToken || "",
    sessionId: session.sessionId || "",
    twoFactorEnabled,
    expiresAt: session.exp,
  });
});

app.post("/api/admin/login", async (req, res) => {
  const payload = req.body || {};
  const username = normalizeUsername(payload.username || "");
  const password = String(payload.password || "");
  const totpCode = String(payload.totpCode || "").trim();
  const requestIp = getRequestIp(req);

  if (!getSessionSecret()) {
    return res.status(500).json({
      error: "Session signing secret missing. Set SESSION_SECRET (or ADMIN_API_KEY) in .env.",
    });
  }

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required." });
  }

  const throttle = checkAdminLoginThrottle(requestIp, username);
  if (throttle.blocked) {
    res.set("Retry-After", String(throttle.retryAfterSeconds));
    return res.status(429).json({
      error: `Too many failed login attempts. Retry in ${throttle.retryAfterSeconds}s.`,
      retryAfterSeconds: throttle.retryAfterSeconds,
    });
  }

  try {
    let authUser = null;
    let needsTotp = false;

    // Prefer DB-based admin users.
    const dbUserResult = await pool.query(
      `SELECT id, username, password_hash, role, is_active, totp_enabled, totp_secret
       FROM admin_users
       WHERE LOWER(username) = LOWER($1)
       LIMIT 1`,
      [username]
    );

    if (dbUserResult.rowCount) {
      const dbUser = dbUserResult.rows[0];
      if (!dbUser.is_active) {
        recordAdminLoginFailure(requestIp, username);
        return res.status(403).json({ error: "Admin user is inactive." });
      }
      const passwordOk = verifyPassword(password, dbUser.password_hash);
      if (!passwordOk) {
        recordAdminLoginFailure(requestIp, username);
        return res.status(401).json({ error: "Invalid admin credentials." });
      }
      needsTotp = Boolean(dbUser.totp_enabled);
      if (needsTotp) {
        if (!totpCode) {
          return res.status(401).json({ error: "Two-factor code is required." });
        }
        if (!verifyTotpCode(String(dbUser.totp_secret || ""), totpCode)) {
          recordAdminLoginFailure(requestIp, username);
          return res.status(401).json({ error: "Invalid two-factor code." });
        }
      }
      authUser = {
        userId: Number(dbUser.id),
        username: String(dbUser.username),
        role: String(dbUser.role || "viewer"),
        source: "db",
      };
      await pool.query(
        `UPDATE admin_users SET last_login_at = NOW(), updated_at = NOW() WHERE id = $1`,
        [authUser.userId]
      );
    } else {
      // Backward-compatible env login fallback.
      if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
        return res.status(500).json({
          error:
            "Admin credentials not configured. Set ADMIN_USERNAME/ADMIN_PASSWORD or create admin_users records.",
        });
      }
      const validUser = safeEqualText(username, normalizeUsername(ADMIN_USERNAME));
      const validPassword = safeEqualText(password, ADMIN_PASSWORD);
      if (!validUser || !validPassword) {
        recordAdminLoginFailure(requestIp, username);
        return res.status(401).json({ error: "Invalid admin credentials." });
      }
      authUser = {
        userId: null,
        username: ADMIN_USERNAME,
        role: ADMIN_BOOTSTRAP_ROLE,
        source: "env",
      };
    }

    clearAdminLoginFailures(requestIp, username);

    const sessionId = crypto.randomUUID();
    const csrfToken = crypto.randomBytes(24).toString("hex");
    const token = createAdminSessionToken({
      ...authUser,
      sessionId,
      csrfToken,
    });
    const isSecure = req.secure || req.headers["x-forwarded-proto"] === "https";

    await pool.query(
      `INSERT INTO admin_sessions
        (session_id, admin_user_id, admin_username, role, source, user_agent, ip_address, csrf_token, expires_at, revoked)
       VALUES
        ($1, $2, $3, $4, $5, $6, $7, $8, NOW() + ($9::text || ' seconds')::interval, FALSE)`,
      [
        sessionId,
        authUser.userId,
        authUser.username,
        authUser.role,
        authUser.source || "session",
        String(req.headers["user-agent"] || ""),
        requestIp,
        csrfToken,
        String(SESSION_TTL_SECONDS),
      ]
    );

    res.cookie(SESSION_COOKIE_NAME, token, {
      httpOnly: true,
      sameSite: "lax",
      secure: Boolean(isSecure),
      maxAge: SESSION_TTL_SECONDS * 1000,
      path: "/",
    });

    await writeAuditLog(req, "admin.login", "admin_user", authUser.userId || authUser.username, {
      source: authUser.source,
      role: authUser.role,
      username: authUser.username,
    });

    return res.json({
      authenticated: true,
      userId: authUser.userId,
      username: authUser.username,
      role: authUser.role,
      source: authUser.source,
      csrfToken,
      sessionId,
      twoFactorEnabled: needsTotp,
      expiresInSeconds: SESSION_TTL_SECONDS,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Admin login failed." });
  }
});

app.post("/api/admin/logout", async (req, res) => {
  const session = await getValidatedAdminSession(req, { touch: false });
  if (session?.sessionId) {
    await pool.query(
      `UPDATE admin_sessions
       SET revoked = TRUE, revoked_at = NOW(), last_seen_at = NOW()
       WHERE session_id = $1`,
      [session.sessionId]
    );
  }
  await writeAuditLog(req, "admin.logout", "admin_user", session?.userId || session?.username || null, {
    username: session?.username || null,
    sessionId: session?.sessionId || null,
  });
  res.clearCookie(SESSION_COOKIE_NAME, { path: "/" });
  res.json({ ok: true });
});

app.get("/api/admin/sessions", requireAdmin, async (req, res) => {
  try {
    const includeAll = parseBoolean(req.query.all) === true;
    const canViewAll = includeAll && req.admin?.role === "owner";
    const values = [];
    let where = "";
    if (!canViewAll) {
      values.push(String(req.admin?.username || ""));
      where = `WHERE admin_username = $1`;
    }
    const result = await pool.query(
      `SELECT
        session_id, admin_user_id, admin_username, role, source, user_agent, ip_address,
        created_at, last_seen_at, expires_at, revoked, revoked_at
       FROM admin_sessions
       ${where}
       ORDER BY created_at DESC
       LIMIT 300`,
      values
    );
    return res.json({
      sessions: result.rows.map((row) => ({
        sessionId: row.session_id,
        adminUserId: row.admin_user_id === null ? null : Number(row.admin_user_id),
        adminUsername: row.admin_username,
        role: row.role,
        source: row.source,
        userAgent: row.user_agent,
        ipAddress: row.ip_address,
        createdAt: row.created_at,
        lastSeenAt: row.last_seen_at,
        expiresAt: row.expires_at,
        revoked: Boolean(row.revoked),
        revokedAt: row.revoked_at || null,
        current: row.session_id === (req.admin?.sessionId || ""),
      })),
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to fetch admin sessions." });
  }
});

app.post("/api/admin/sessions/:sessionId/revoke", requireAdmin, async (req, res) => {
  try {
    const sessionId = String(req.params.sessionId || "").trim();
    if (!sessionId) return res.status(400).json({ error: "Invalid session id." });
    if (req.admin?.role !== "owner" && sessionId !== req.admin?.sessionId) {
      return res.status(403).json({ error: "You can only revoke your own session." });
    }
    const result = await pool.query(
      `UPDATE admin_sessions
       SET revoked = TRUE, revoked_at = NOW(), last_seen_at = NOW()
       WHERE session_id = $1
       RETURNING session_id, admin_username`,
      [sessionId]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Session not found." });
    await writeAuditLog(req, "admin.session.revoke", "admin_session", sessionId, {
      targetSessionId: sessionId,
      targetUsername: result.rows[0].admin_username,
    });
    return res.json({ revoked: true, sessionId });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to revoke session." });
  }
});

app.post("/api/admin/2fa/setup", requireAdmin, async (req, res) => {
  try {
    if (!req.admin?.userId) {
      return res.status(400).json({ error: "2FA setup requires a database-backed admin account." });
    }
    const secret = generateTotpSecret();
    const issuer = encodeURIComponent(process.env.APP_2FA_ISSUER || "Sholly Store");
    const account = encodeURIComponent(String(req.admin.username || ""));
    const otpauthUrl = `otpauth://totp/${issuer}:${account}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;

    await pool.query(
      `UPDATE admin_users
       SET totp_secret = $1,
           totp_enabled = FALSE,
           totp_confirmed_at = NULL,
           updated_at = NOW()
       WHERE id = $2`,
      [secret, req.admin.userId]
    );

    await writeAuditLog(req, "admin.2fa.setup_started", "admin_user", req.admin.userId, {
      username: req.admin.username,
    });

    return res.json({
      secret,
      otpauthUrl,
      message: "Scan QR/URL in your authenticator app, then verify with a 6-digit code.",
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to start 2FA setup." });
  }
});

app.post("/api/admin/2fa/verify-setup", requireAdmin, async (req, res) => {
  try {
    if (!req.admin?.userId) {
      return res.status(400).json({ error: "2FA setup requires a database-backed admin account." });
    }
    const code = String((req.body || {}).code || "").trim();
    if (!code) return res.status(400).json({ error: "Verification code is required." });

    const userResult = await pool.query(
      `SELECT totp_secret FROM admin_users WHERE id = $1 LIMIT 1`,
      [req.admin.userId]
    );
    if (!userResult.rowCount || !userResult.rows[0].totp_secret) {
      return res.status(400).json({ error: "No pending 2FA setup found." });
    }
    const secret = String(userResult.rows[0].totp_secret);
    if (!verifyTotpCode(secret, code, 1)) {
      return res.status(400).json({ error: "Invalid verification code." });
    }

    await pool.query(
      `UPDATE admin_users
       SET totp_enabled = TRUE,
           totp_confirmed_at = NOW(),
           updated_at = NOW()
       WHERE id = $1`,
      [req.admin.userId]
    );

    await writeAuditLog(req, "admin.2fa.enabled", "admin_user", req.admin.userId, {
      username: req.admin.username,
    });

    return res.json({ enabled: true });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to verify 2FA setup." });
  }
});

app.post("/api/admin/2fa/disable", requireAdmin, async (req, res) => {
  try {
    if (!req.admin?.userId) {
      return res.status(400).json({ error: "2FA disable requires a database-backed admin account." });
    }
    const code = String((req.body || {}).code || "").trim();
    const userResult = await pool.query(
      `SELECT totp_enabled, totp_secret FROM admin_users WHERE id = $1 LIMIT 1`,
      [req.admin.userId]
    );
    if (!userResult.rowCount) {
      return res.status(404).json({ error: "Admin user not found." });
    }
    const row = userResult.rows[0];
    if (row.totp_enabled) {
      if (!code || !verifyTotpCode(String(row.totp_secret || ""), code, 1)) {
        return res.status(400).json({ error: "Valid 2FA code is required to disable." });
      }
    }

    await pool.query(
      `UPDATE admin_users
       SET totp_enabled = FALSE,
           totp_secret = NULL,
           totp_confirmed_at = NULL,
           updated_at = NOW()
       WHERE id = $1`,
      [req.admin.userId]
    );

    await writeAuditLog(req, "admin.2fa.disabled", "admin_user", req.admin.userId, {
      username: req.admin.username,
    });

    return res.json({ enabled: false });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to disable 2FA." });
  }
});

app.get("/api/admin/users", requireAdmin, requireRole("owner"), async (_req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, role, is_active, totp_enabled, last_login_at, created_at, updated_at
       FROM admin_users
       ORDER BY role DESC, username ASC`
    );
    res.json({
      users: result.rows.map((row) => ({
        id: Number(row.id),
        username: row.username,
        role: row.role,
        isActive: row.is_active,
        twoFactorEnabled: Boolean(row.totp_enabled),
        lastLoginAt: row.last_login_at,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      })),
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to fetch admin users." });
  }
});

app.post("/api/admin/users", requireAdmin, requireRole("owner"), async (req, res) => {
  try {
    const payload = req.body || {};
    const username = normalizeUsername(payload.username || "");
    const password = String(payload.password || "");
    const role = String(payload.role || "viewer").toLowerCase();

    if (!username) return res.status(400).json({ error: "username is required." });
    if (!password || password.length < 8) {
      return res.status(400).json({ error: "password must be at least 8 characters." });
    }
    if (!ROLE_LEVEL[role]) return res.status(400).json({ error: "Invalid role value." });

    const hash = hashPassword(password);
    const result = await pool.query(
      `INSERT INTO admin_users (username, password_hash, role, is_active)
       VALUES ($1, $2, $3, TRUE)
       RETURNING id, username, role, is_active, totp_enabled, created_at, updated_at`,
      [username, hash, role]
    );

    const row = result.rows[0];
    await writeAuditLog(req, "admin_user.create", "admin_user", row.id, {
      username: row.username,
      role: row.role,
    });

    res.status(201).json({
      user: {
        id: Number(row.id),
        username: row.username,
        role: row.role,
        isActive: row.is_active,
        twoFactorEnabled: Boolean(row.totp_enabled),
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      },
    });
  } catch (error) {
    console.error(error);
    return sendPgError(res, error, "Failed to create admin user.");
  }
});

app.patch("/api/admin/users/:id", requireAdmin, requireRole("owner"), async (req, res) => {
  try {
    const id = parseIntOrUndefined(req.params.id);
    if (!id) return res.status(400).json({ error: "Invalid admin user id." });

    const payload = req.body || {};
    const updates = [];
    const values = [];

    if (payload.role !== undefined) {
      const role = String(payload.role || "").toLowerCase();
      if (!ROLE_LEVEL[role]) return res.status(400).json({ error: "Invalid role value." });
      updates.push(`role = $${values.length + 1}`);
      values.push(role);
    }
    if (payload.isActive !== undefined) {
      const isActive = parseBoolean(payload.isActive);
      if (isActive === undefined) return res.status(400).json({ error: "isActive must be true or false." });
      updates.push(`is_active = $${values.length + 1}`);
      values.push(isActive);
    }
    if (payload.password !== undefined && String(payload.password).trim() !== "") {
      const password = String(payload.password);
      if (password.length < 8) {
        return res.status(400).json({ error: "password must be at least 8 characters." });
      }
      updates.push(`password_hash = $${values.length + 1}`);
      values.push(hashPassword(password));
    }

    if (!updates.length) return res.status(400).json({ error: "No valid fields to update." });

    values.push(id);
    const result = await pool.query(
      `UPDATE admin_users
       SET ${updates.join(", ")}, updated_at = NOW()
       WHERE id = $${values.length}
       RETURNING id, username, role, is_active, totp_enabled, last_login_at, created_at, updated_at`,
      values
    );
    if (!result.rowCount) return res.status(404).json({ error: "Admin user not found." });

    const row = result.rows[0];
    await writeAuditLog(req, "admin_user.update", "admin_user", row.id, {
      role: row.role,
      isActive: row.is_active,
      passwordChanged: payload.password !== undefined && String(payload.password).trim() !== "",
    });

    res.json({
      user: {
        id: Number(row.id),
        username: row.username,
        role: row.role,
        isActive: row.is_active,
        twoFactorEnabled: Boolean(row.totp_enabled),
        lastLoginAt: row.last_login_at,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      },
    });
  } catch (error) {
    console.error(error);
    return sendPgError(res, error, "Failed to update admin user.");
  }
});

app.post("/api/customer/register", async (req, res) => {
  try {
    const payload = req.body || {};
    const email = normalizeEmail(payload.email || "");
    const password = String(payload.password || "");
    const fullName = String(payload.fullName || "").trim();
    const phone = String(payload.phone || "").trim() || null;

    if (!email || !email.includes("@")) {
      return res.status(400).json({ error: "A valid email is required." });
    }
    if (!password || password.length < 8) {
      return res.status(400).json({ error: "password must be at least 8 characters." });
    }

    const existing = await pool.query(`SELECT id FROM customers WHERE LOWER(email) = LOWER($1) LIMIT 1`, [email]);
    if (existing.rowCount) {
      return res.status(409).json({ error: "An account with this email already exists." });
    }

    const passwordHash = hashPassword(password);
    const result = await pool.query(
      `INSERT INTO customers (email, password_hash, full_name, phone, is_active)
       VALUES ($1, $2, $3, $4, TRUE)
       RETURNING id, email, full_name, phone, created_at, updated_at`,
      [email, passwordHash, fullName, phone]
    );
    const customer = result.rows[0];
    await pool.query(
      `INSERT INTO wishlists (customer_id)
       VALUES ($1)
       ON CONFLICT (customer_id) DO NOTHING`,
      [Number(customer.id)]
    );

    const session = await issueCustomerSession(req, res, {
      customerId: Number(customer.id),
      email,
    });

    return res.status(201).json({
      authenticated: true,
      csrfToken: session.csrfToken,
      sessionId: session.sessionId,
      expiresInSeconds: session.expiresInSeconds,
      customer: {
        id: Number(customer.id),
        email: customer.email,
        fullName: customer.full_name || "",
        phone: customer.phone || "",
        createdAt: customer.created_at,
        updatedAt: customer.updated_at,
      },
    });
  } catch (error) {
    console.error(error);
    return sendPgError(res, error, "Failed to create customer account.");
  }
});

app.post("/api/customer/login", async (req, res) => {
  try {
    const payload = req.body || {};
    const email = normalizeEmail(payload.email || "");
    const password = String(payload.password || "");
    if (!email || !password) {
      return res.status(400).json({ error: "email and password are required." });
    }

    const result = await pool.query(
      `SELECT id, email, password_hash, full_name, phone, is_active, created_at, updated_at
       FROM customers
       WHERE LOWER(email) = LOWER($1)
       LIMIT 1`,
      [email]
    );
    if (!result.rowCount) {
      return res.status(401).json({ error: "Invalid email or password." });
    }
    const customer = result.rows[0];
    if (!customer.is_active) {
      return res.status(403).json({ error: "Customer account is inactive." });
    }
    if (!verifyPassword(password, customer.password_hash)) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    await pool.query(
      `UPDATE customers
       SET last_login_at = NOW(), updated_at = NOW()
       WHERE id = $1`,
      [Number(customer.id)]
    );

    const session = await issueCustomerSession(req, res, {
      customerId: Number(customer.id),
      email: customer.email,
    });

    return res.json({
      authenticated: true,
      csrfToken: session.csrfToken,
      sessionId: session.sessionId,
      expiresInSeconds: session.expiresInSeconds,
      customer: {
        id: Number(customer.id),
        email: customer.email,
        fullName: customer.full_name || "",
        phone: customer.phone || "",
        createdAt: customer.created_at,
        updatedAt: customer.updated_at,
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Customer login failed." });
  }
});

app.post("/api/customer/logout", async (req, res) => {
  try {
    const session = await getValidatedCustomerSession(req, { touch: false });
    if (session?.sessionId) {
      await pool.query(
        `UPDATE customer_sessions
         SET revoked = TRUE, revoked_at = NOW(), last_seen_at = NOW()
         WHERE session_id = $1`,
        [session.sessionId]
      );
    }
    res.clearCookie(CUSTOMER_SESSION_COOKIE_NAME, { path: "/" });
    return res.json({ ok: true });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to logout customer." });
  }
});

app.get("/api/customer/me", requireCustomer, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, email, full_name, phone, is_active, email_verified, last_login_at, created_at, updated_at
       FROM customers
       WHERE id = $1
       LIMIT 1`,
      [req.customer.customerId]
    );
    if (!result.rowCount) {
      return res.status(404).json({ error: "Customer not found." });
    }
    const row = result.rows[0];
    return res.json({
      authenticated: true,
      csrfToken: req.customer.csrfToken || "",
      sessionId: req.customer.sessionId,
      customer: {
        id: Number(row.id),
        email: row.email,
        fullName: row.full_name || "",
        phone: row.phone || "",
        isActive: Boolean(row.is_active),
        emailVerified: Boolean(row.email_verified),
        lastLoginAt: row.last_login_at,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to fetch customer profile." });
  }
});

app.get("/api/customer/orders", requireCustomer, async (req, res) => {
  try {
    const limit = Math.min(Math.max(parseIntOrUndefined(req.query.limit) || 50, 1), 200);
    const result = await pool.query(
      `SELECT
        id, order_number, customer_name, customer_phone, customer_email,
        subtotal_kobo, shipping_fee_kobo, coupon_code, coupon_discount_kobo, total_kobo,
        status, payment_channel, paystack_reference, moniepoint_reference,
        payment_proof_status, payment_verified_at, payment_verified_by,
        created_at, updated_at
       FROM orders
       WHERE customer_id = $1
          OR LOWER(COALESCE(customer_email, '')) = LOWER($2)
       ORDER BY created_at DESC
       LIMIT $3`,
      [req.customer.customerId, req.customer.email || "", limit]
    );
    return res.json({
      orders: result.rows.map((row) => ({
        id: Number(row.id),
        orderNumber: row.order_number,
        customerName: row.customer_name,
        customerPhone: row.customer_phone,
        customerEmail: row.customer_email || null,
        subtotalKobo: Number(row.subtotal_kobo || 0),
        shippingFeeKobo: Number(row.shipping_fee_kobo || 0),
        couponCode: row.coupon_code || null,
        couponDiscountKobo: Number(row.coupon_discount_kobo || 0),
        totalKobo: Number(row.total_kobo || 0),
        status: row.status,
        paymentChannel: row.payment_channel || null,
        reference: row.paystack_reference || row.moniepoint_reference || null,
        paymentProofStatus: row.payment_proof_status || "none",
        paymentVerifiedAt: row.payment_verified_at,
        paymentVerifiedBy: row.payment_verified_by || null,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      })),
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to fetch customer orders." });
  }
});

app.get("/api/customer/addresses", requireCustomer, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
        id, label, recipient_name, recipient_phone, line1, line2, city, state, country, postal_code,
        is_default, created_at, updated_at
       FROM customer_addresses
       WHERE customer_id = $1
       ORDER BY is_default DESC, updated_at DESC`,
      [req.customer.customerId]
    );
    return res.json({
      addresses: result.rows.map((row) => ({
        id: Number(row.id),
        label: row.label || "Home",
        recipientName: row.recipient_name,
        recipientPhone: row.recipient_phone,
        line1: row.line1,
        line2: row.line2 || "",
        city: row.city,
        state: row.state,
        country: row.country || "Nigeria",
        postalCode: row.postal_code || "",
        isDefault: Boolean(row.is_default),
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      })),
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to fetch customer addresses." });
  }
});

app.post("/api/customer/addresses", requireCustomer, async (req, res) => {
  try {
    const payload = req.body || {};
    const label = String(payload.label || "").trim() || "Home";
    const recipientName = String(payload.recipientName || "").trim();
    const recipientPhone = String(payload.recipientPhone || "").trim();
    const line1 = String(payload.line1 || "").trim();
    const line2 = String(payload.line2 || "").trim() || null;
    const city = String(payload.city || "").trim();
    const stateText = String(payload.state || "").trim();
    const country = String(payload.country || "").trim() || "Nigeria";
    const postalCode = String(payload.postalCode || "").trim() || null;
    const isDefault = payload.isDefault === undefined ? false : parseBoolean(payload.isDefault);

    if (!recipientName || !recipientPhone || !line1 || !city || !stateText) {
      return res.status(400).json({ error: "recipientName, recipientPhone, line1, city and state are required." });
    }
    if (isDefault === undefined) return res.status(400).json({ error: "isDefault must be true or false." });

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      if (isDefault) {
        await client.query(
          `UPDATE customer_addresses
           SET is_default = FALSE, updated_at = NOW()
           WHERE customer_id = $1`,
          [req.customer.customerId]
        );
      }
      const existingCountResult = await client.query(
        `SELECT COUNT(*)::int AS count FROM customer_addresses WHERE customer_id = $1`,
        [req.customer.customerId]
      );
      const firstAddress = Number(existingCountResult.rows[0]?.count || 0) === 0;
      const result = await client.query(
        `INSERT INTO customer_addresses
          (customer_id, label, recipient_name, recipient_phone, line1, line2, city, state, country, postal_code, is_default)
         VALUES
          ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         RETURNING
          id, label, recipient_name, recipient_phone, line1, line2, city, state, country, postal_code, is_default, created_at, updated_at`,
        [
          req.customer.customerId,
          label,
          recipientName,
          recipientPhone,
          line1,
          line2,
          city,
          stateText,
          country,
          postalCode,
          firstAddress ? true : Boolean(isDefault),
        ]
      );
      await client.query("COMMIT");
      const row = result.rows[0];
      return res.status(201).json({
        address: {
          id: Number(row.id),
          label: row.label || "Home",
          recipientName: row.recipient_name,
          recipientPhone: row.recipient_phone,
          line1: row.line1,
          line2: row.line2 || "",
          city: row.city,
          state: row.state,
          country: row.country || "Nigeria",
          postalCode: row.postal_code || "",
          isDefault: Boolean(row.is_default),
          createdAt: row.created_at,
          updatedAt: row.updated_at,
        },
      });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error(error);
    return sendPgError(res, error, "Failed to add customer address.");
  }
});

app.put("/api/customer/addresses/:id", requireCustomer, async (req, res) => {
  try {
    const id = parseIntOrUndefined(req.params.id);
    if (!id) return res.status(400).json({ error: "Invalid address id." });
    const payload = req.body || {};
    const updates = [];
    const values = [];
    const textFields = [
      ["label", "label"],
      ["recipientName", "recipient_name"],
      ["recipientPhone", "recipient_phone"],
      ["line1", "line1"],
      ["line2", "line2"],
      ["city", "city"],
      ["state", "state"],
      ["country", "country"],
      ["postalCode", "postal_code"],
    ];
    for (const [inputKey, column] of textFields) {
      if (payload[inputKey] !== undefined) {
        values.push(String(payload[inputKey] || "").trim() || null);
        updates.push(`${column} = $${values.length}`);
      }
    }
    let defaultOverride = null;
    if (payload.isDefault !== undefined) {
      const parsed = parseBoolean(payload.isDefault);
      if (parsed === undefined) return res.status(400).json({ error: "isDefault must be true or false." });
      defaultOverride = parsed;
      values.push(parsed);
      updates.push(`is_default = $${values.length}`);
    }
    if (!updates.length) return res.status(400).json({ error: "No fields to update." });

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      if (defaultOverride === true) {
        await client.query(
          `UPDATE customer_addresses
           SET is_default = FALSE, updated_at = NOW()
           WHERE customer_id = $1`,
          [req.customer.customerId]
        );
      }
      values.push(id);
      values.push(req.customer.customerId);
      const result = await client.query(
        `UPDATE customer_addresses
         SET ${updates.join(", ")}, updated_at = NOW()
         WHERE id = $${values.length - 1} AND customer_id = $${values.length}
         RETURNING
          id, label, recipient_name, recipient_phone, line1, line2, city, state, country, postal_code, is_default, created_at, updated_at`,
        values
      );
      if (!result.rowCount) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "Address not found." });
      }
      await client.query("COMMIT");
      const row = result.rows[0];
      return res.json({
        address: {
          id: Number(row.id),
          label: row.label || "Home",
          recipientName: row.recipient_name || "",
          recipientPhone: row.recipient_phone || "",
          line1: row.line1 || "",
          line2: row.line2 || "",
          city: row.city || "",
          state: row.state || "",
          country: row.country || "Nigeria",
          postalCode: row.postal_code || "",
          isDefault: Boolean(row.is_default),
          createdAt: row.created_at,
          updatedAt: row.updated_at,
        },
      });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error(error);
    return sendPgError(res, error, "Failed to update customer address.");
  }
});

app.delete("/api/customer/addresses/:id", requireCustomer, async (req, res) => {
  try {
    const id = parseIntOrUndefined(req.params.id);
    if (!id) return res.status(400).json({ error: "Invalid address id." });
    const result = await pool.query(
      `DELETE FROM customer_addresses
       WHERE id = $1 AND customer_id = $2
       RETURNING id`,
      [id, req.customer.customerId]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Address not found." });
    return res.json({ deleted: true, id: Number(result.rows[0].id) });
  } catch (error) {
    console.error(error);
    return sendPgError(res, error, "Failed to delete customer address.");
  }
});

app.get("/api/customer/wishlist", requireCustomer, async (req, res) => {
  try {
    await pool.query(
      `INSERT INTO wishlists (customer_id)
       VALUES ($1)
       ON CONFLICT (customer_id) DO NOTHING`,
      [req.customer.customerId]
    );
    const result = await pool.query(
      `SELECT
        wi.id AS wishlist_item_id,
        wi.product_id,
        wi.variant_id,
        wi.created_at AS added_at,
        p.id AS product_id_ref, p.name, p.slug, p.brand, p.category, p.description, p.price_kobo, p.compare_at_kobo,
        p.stock_qty, p.reorder_threshold, p.has_variants, p.image_url, p.gallery_urls, p.is_featured, p.created_at AS product_created_at, p.updated_at AS product_updated_at,
        v.id AS variant_ref_id, v.sku AS variant_sku, v.option_size, v.option_color, v.option_style, v.price_override_kobo,
        v.stock_qty AS variant_stock_qty, v.reorder_threshold AS variant_reorder_threshold, v.image_url AS variant_image_url,
        v.is_active AS variant_is_active, v.created_at AS variant_created_at, v.updated_at AS variant_updated_at
       FROM wishlists w
       INNER JOIN wishlist_items wi ON wi.wishlist_id = w.id
       INNER JOIN products p ON p.id = wi.product_id
       LEFT JOIN product_variants v ON v.id = wi.variant_id
       WHERE w.customer_id = $1
       ORDER BY wi.created_at DESC`,
      [req.customer.customerId]
    );
    return res.json({
      items: result.rows.map((row) => ({
        id: Number(row.wishlist_item_id),
        productId: Number(row.product_id),
        variantId: row.variant_id === null ? null : Number(row.variant_id),
        addedAt: row.added_at,
        product: toProduct({
          id: row.product_id_ref,
          name: row.name,
          slug: row.slug,
          brand: row.brand,
          category: row.category,
          description: row.description,
          price_kobo: row.price_kobo,
          compare_at_kobo: row.compare_at_kobo,
          stock_qty: row.stock_qty,
          reorder_threshold: row.reorder_threshold,
          has_variants: row.has_variants,
          image_url: row.image_url,
          gallery_urls: row.gallery_urls,
          is_featured: row.is_featured,
          created_at: row.product_created_at,
          updated_at: row.product_updated_at,
        }),
        variant:
          row.variant_ref_id === null
            ? null
            : toVariant({
                id: row.variant_ref_id,
                product_id: row.product_id,
                sku: row.variant_sku,
                option_size: row.option_size,
                option_color: row.option_color,
                option_style: row.option_style,
                price_override_kobo: row.price_override_kobo,
                stock_qty: row.variant_stock_qty,
                reorder_threshold: row.variant_reorder_threshold,
                image_url: row.variant_image_url,
                is_active: row.variant_is_active,
                created_at: row.variant_created_at,
                updated_at: row.variant_updated_at,
              }),
      })),
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to fetch wishlist." });
  }
});

app.post("/api/customer/wishlist/items", requireCustomer, async (req, res) => {
  try {
    const payload = req.body || {};
    const productId = parsePositiveInt(payload.productId);
    const variantIdRaw = payload.variantId;
    const variantId =
      variantIdRaw === undefined || variantIdRaw === null || variantIdRaw === ""
        ? null
        : parsePositiveInt(variantIdRaw);
    if (!productId) return res.status(400).json({ error: "productId is required." });
    if (variantIdRaw !== undefined && variantIdRaw !== null && variantIdRaw !== "" && !variantId) {
      return res.status(400).json({ error: "variantId must be a positive integer when provided." });
    }

    const productResult = await pool.query(`SELECT id FROM products WHERE id = $1 LIMIT 1`, [productId]);
    if (!productResult.rowCount) return res.status(404).json({ error: "Product not found." });
    if (variantId) {
      const variantResult = await pool.query(
        `SELECT id, product_id FROM product_variants WHERE id = $1 LIMIT 1`,
        [variantId]
      );
      if (!variantResult.rowCount || Number(variantResult.rows[0].product_id) !== productId) {
        return res.status(400).json({ error: "Invalid variant for product." });
      }
    }

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const wishlistResult = await client.query(
        `INSERT INTO wishlists (customer_id)
         VALUES ($1)
         ON CONFLICT (customer_id) DO UPDATE SET updated_at = NOW()
         RETURNING id`,
        [req.customer.customerId]
      );
      const wishlistId = Number(wishlistResult.rows[0].id);
      const existing = await client.query(
        `SELECT id
         FROM wishlist_items
         WHERE wishlist_id = $1
           AND product_id = $2
           AND COALESCE(variant_id, 0) = COALESCE($3, 0)
         LIMIT 1`,
        [wishlistId, productId, variantId]
      );
      let itemId = null;
      if (existing.rowCount) {
        itemId = Number(existing.rows[0].id);
      } else {
        const inserted = await client.query(
          `INSERT INTO wishlist_items (wishlist_id, product_id, variant_id)
           VALUES ($1, $2, $3)
           RETURNING id`,
          [wishlistId, productId, variantId]
        );
        itemId = Number(inserted.rows[0].id);
      }
      await client.query("COMMIT");
      return res.status(201).json({ added: true, itemId });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error(error);
    return sendPgError(res, error, "Failed to add wishlist item.");
  }
});

app.delete("/api/customer/wishlist/items/:id", requireCustomer, async (req, res) => {
  try {
    const id = parseIntOrUndefined(req.params.id);
    if (!id) return res.status(400).json({ error: "Invalid wishlist item id." });
    const result = await pool.query(
      `DELETE FROM wishlist_items wi
       USING wishlists w
       WHERE wi.id = $1
         AND wi.wishlist_id = w.id
         AND w.customer_id = $2
       RETURNING wi.id`,
      [id, req.customer.customerId]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Wishlist item not found." });
    return res.json({ deleted: true, id: Number(result.rows[0].id) });
  } catch (error) {
    console.error(error);
    return sendPgError(res, error, "Failed to delete wishlist item.");
  }
});

app.post("/api/customer/orders/:orderId/reorder", requireCustomer, async (req, res) => {
  try {
    const orderId = parseIntOrUndefined(req.params.orderId);
    if (!orderId) return res.status(400).json({ error: "Invalid order id." });

    const itemsResult = await pool.query(
      `SELECT
        o.id AS order_id, o.order_number, o.customer_email,
        oi.product_id, oi.variant_id, oi.qty
       FROM orders o
       INNER JOIN order_items oi ON oi.order_id = o.id
       WHERE o.id = $1
         AND (
          o.customer_id = $2
          OR LOWER(COALESCE(o.customer_email, '')) = LOWER($3)
         )
       ORDER BY oi.id ASC`,
      [orderId, req.customer.customerId, req.customer.email || ""]
    );
    if (!itemsResult.rowCount) {
      return res.status(404).json({ error: "Order not found for this customer." });
    }

    const candidateItems = itemsResult.rows
      .map((row) => ({
        productId: row.product_id === null ? null : Number(row.product_id),
        variantId: row.variant_id === null ? null : Number(row.variant_id),
        qty: Number(row.qty || 0),
      }))
      .filter((item) => item.productId && item.qty > 0);
    const normalized = normalizeCartItemsWithVariants(candidateItems);
    if (!normalized.valid || !normalized.items.length) {
      return res.status(400).json({ error: "Order has no valid reorder items." });
    }

    const catalog = await fetchCatalogForCartItems(pool, normalized.items, { lockRows: false });
    if (!catalog.valid) {
      return res.status(409).json({ error: catalog.error || "Some order items are unavailable now." });
    }
    const { productMap, variantMap } = catalog;

    const items = [];
    for (const item of normalized.items) {
      const product = productMap.get(item.productId);
      if (!product) continue;
      const variant = item.variantId ? variantMap.get(item.variantId) : null;
      const maxQty = variant ? Number(variant.stockQty || 0) : Number(product.stockQty || 0);
      if (maxQty <= 0) continue;
      items.push({
        productId: item.productId,
        variantId: item.variantId || null,
        qty: Math.min(item.qty, maxQty),
        availableQty: maxQty,
      });
    }

    return res.json({
      orderId,
      orderNumber: itemsResult.rows[0].order_number,
      items,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to prepare reorder items." });
  }
});

app.get("/api/brands", async (_req, res) => {
  try {
    const result = await pool.query(
      `SELECT brand, COUNT(*)::int AS products, COALESCE(SUM(stock_qty), 0)::int AS total_stock
       FROM products
       GROUP BY brand
       ORDER BY brand ASC`
    );
    res.json({ brands: result.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to fetch brands" });
  }
});

app.get("/api/inventory/summary", async (req, res) => {
  try {
    const brand = req.query.brand ? String(req.query.brand) : undefined;
    const values = [];
    let whereSql = "";
    if (brand) {
      if (!BRAND_VALUES.has(brand)) {
        return res.status(400).json({ error: "Invalid brand value" });
      }
      values.push(brand);
      whereSql = `WHERE brand = $${values.length}`;
    }

    const result = await pool.query(
      `SELECT
        COUNT(*)::int AS total_products,
        COALESCE(SUM(stock_qty), 0)::int AS total_units,
        COALESCE(SUM(price_kobo * stock_qty), 0)::bigint AS stock_value_kobo
       FROM products
       ${whereSql}`,
      values
    );
    res.json({ summary: result.rows[0] || null });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to fetch inventory summary" });
  }
});

app.get("/api/shipping/quote", async (req, res) => {
  try {
    const shippingState = normalizeRegionText(req.query.state || "");
    const shippingCity = normalizeRegionText(req.query.city || "");
    const subtotalKobo = toKobo(req.query.subtotalKobo || 0);

    if (!shippingState) {
      return res.json({
        shippingState: "",
        shippingCity,
        shippingFeeKobo: 0,
        freeShippingApplied: false,
        etaMinDays: null,
        etaMaxDays: null,
        isBlackout: false,
        blackoutNote: "",
      });
    }

    const quote = await computeShippingQuote(pool, shippingState, shippingCity, subtotalKobo);
    return res.json(quote);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to calculate shipping fee." });
  }
});

app.get("/api/admin/shipping/settings", requireAdmin, requireRole("owner", "manager"), async (_req, res) => {
  try {
    const settings = await getShippingSettingsFromDb(pool);
    return res.json({
      settings: {
        defaultFeeKobo: Number(settings.defaultFeeKobo || 0),
        freeShippingThresholdKobo: Number(settings.freeShippingThresholdKobo || 0),
        etaMinDays: Number(settings.etaMinDays || 0),
        etaMaxDays: Number(settings.etaMaxDays || 0),
        updatedAt: settings.updatedAt || null,
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to fetch shipping settings." });
  }
});

app.patch("/api/admin/shipping/settings", requireAdmin, requireRole("owner", "manager"), async (req, res) => {
  try {
    const payload = req.body || {};
    const defaultFeeKobo = parseIntOrUndefined(payload.defaultFeeKobo);
    const freeShippingThresholdKobo = parseIntOrUndefined(payload.freeShippingThresholdKobo);
    const etaMinDays = parseIntOrUndefined(payload.etaMinDays);
    const etaMaxDays = parseIntOrUndefined(payload.etaMaxDays);

    const updates = [];
    const values = [];
    if (defaultFeeKobo !== undefined) {
      if (defaultFeeKobo < 0) return res.status(400).json({ error: "defaultFeeKobo must be >= 0." });
      values.push(defaultFeeKobo);
      updates.push(`default_fee_kobo = $${values.length}`);
    }
    if (freeShippingThresholdKobo !== undefined) {
      if (freeShippingThresholdKobo < 0) {
        return res.status(400).json({ error: "freeShippingThresholdKobo must be >= 0." });
      }
      values.push(freeShippingThresholdKobo);
      updates.push(`free_shipping_threshold_kobo = $${values.length}`);
    }
    if (etaMinDays !== undefined) {
      if (etaMinDays < 0) return res.status(400).json({ error: "etaMinDays must be >= 0." });
      values.push(etaMinDays);
      updates.push(`eta_min_days = $${values.length}`);
    }
    if (etaMaxDays !== undefined) {
      if (etaMaxDays < 0) return res.status(400).json({ error: "etaMaxDays must be >= 0." });
      values.push(etaMaxDays);
      updates.push(`eta_max_days = $${values.length}`);
    }

    if (!updates.length) {
      return res.status(400).json({ error: "Provide at least one field to update." });
    }
    values.push(1);
    const result = await pool.query(
      `UPDATE shipping_settings
       SET ${updates.join(", ")}, updated_at = NOW()
       WHERE id = $${values.length}
       RETURNING default_fee_kobo, free_shipping_threshold_kobo, eta_min_days, eta_max_days, updated_at`,
      values
    );
    if (!result.rowCount) {
      return res.status(404).json({ error: "Shipping settings row not found." });
    }
    const row = result.rows[0];

    await writeAuditLog(req, "shipping.settings.update", "shipping_settings", "1", {
      changedFields: updates.map((entry) => entry.split("=")[0].trim()),
    });

    return res.json({
      settings: {
        defaultFeeKobo: Number(row.default_fee_kobo || 0),
        freeShippingThresholdKobo: Number(row.free_shipping_threshold_kobo || 0),
        etaMinDays: Number(row.eta_min_days || 0),
        etaMaxDays: Number(row.eta_max_days || 0),
        updatedAt: row.updated_at || null,
      },
    });
  } catch (error) {
    console.error(error);
    return sendPgError(res, error, "Failed to update shipping settings.");
  }
});

app.get("/api/admin/shipping/rules", requireAdmin, requireRole("owner", "manager"), async (req, res) => {
  try {
    const limit = Math.min(Math.max(parseIntOrUndefined(req.query.limit) || 300, 1), 500);
    const includeInactive = parseBoolean(req.query.includeInactive) === true;
    const values = [limit];
    const where = includeInactive ? "" : "WHERE is_active = TRUE";
    const result = await pool.query(
      `SELECT
        id, state_text, city_text, fee_kobo, eta_min_days, eta_max_days, priority, is_active, created_at, updated_at
       FROM shipping_rules
       ${where}
       ORDER BY priority ASC, state_text ASC, city_text ASC NULLS LAST, id ASC
       LIMIT $1`,
      values
    );
    return res.json({
      rules: result.rows.map((row) => ({
        id: Number(row.id),
        stateText: row.state_text,
        cityText: row.city_text || "",
        feeKobo: Number(row.fee_kobo || 0),
        etaMinDays: row.eta_min_days === null ? null : Number(row.eta_min_days),
        etaMaxDays: row.eta_max_days === null ? null : Number(row.eta_max_days),
        priority: Number(row.priority || 0),
        isActive: Boolean(row.is_active),
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      })),
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to fetch shipping rules." });
  }
});

app.post("/api/admin/shipping/rules", requireAdmin, requireRole("owner", "manager"), async (req, res) => {
  try {
    const payload = req.body || {};
    const stateText = normalizeRegionText(payload.stateText || "");
    const cityTextRaw = normalizeRegionText(payload.cityText || "");
    const cityText = cityTextRaw || null;
    const feeKobo = parseIntOrUndefined(payload.feeKobo);
    const etaMinDays = parseIntOrUndefined(payload.etaMinDays);
    const etaMaxDays = parseIntOrUndefined(payload.etaMaxDays);
    const priority = parseIntOrUndefined(payload.priority);
    const isActive = payload.isActive === undefined ? true : parseBoolean(payload.isActive);

    if (!stateText) return res.status(400).json({ error: "stateText is required." });
    if (feeKobo === undefined || feeKobo < 0) {
      return res.status(400).json({ error: "feeKobo must be a non-negative integer." });
    }
    if (etaMinDays !== undefined && etaMinDays < 0) {
      return res.status(400).json({ error: "etaMinDays must be >= 0." });
    }
    if (etaMaxDays !== undefined && etaMaxDays < 0) {
      return res.status(400).json({ error: "etaMaxDays must be >= 0." });
    }
    if (priority !== undefined && !Number.isFinite(priority)) {
      return res.status(400).json({ error: "priority must be an integer." });
    }
    if (isActive === undefined) {
      return res.status(400).json({ error: "isActive must be true or false." });
    }

    const result = await pool.query(
      `INSERT INTO shipping_rules
        (state_text, city_text, fee_kobo, eta_min_days, eta_max_days, priority, is_active)
       VALUES
        ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, state_text, city_text, fee_kobo, eta_min_days, eta_max_days, priority, is_active, created_at, updated_at`,
      [
        stateText,
        cityText,
        feeKobo,
        etaMinDays === undefined ? null : etaMinDays,
        etaMaxDays === undefined ? null : etaMaxDays,
        priority === undefined ? 100 : priority,
        Boolean(isActive),
      ]
    );
    const row = result.rows[0];
    await writeAuditLog(req, "shipping.rule.create", "shipping_rule", row.id, {
      stateText: row.state_text,
      cityText: row.city_text || "",
      feeKobo: Number(row.fee_kobo || 0),
    });
    return res.status(201).json({
      rule: {
        id: Number(row.id),
        stateText: row.state_text,
        cityText: row.city_text || "",
        feeKobo: Number(row.fee_kobo || 0),
        etaMinDays: row.eta_min_days === null ? null : Number(row.eta_min_days),
        etaMaxDays: row.eta_max_days === null ? null : Number(row.eta_max_days),
        priority: Number(row.priority || 0),
        isActive: Boolean(row.is_active),
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      },
    });
  } catch (error) {
    console.error(error);
    return sendPgError(res, error, "Failed to create shipping rule.");
  }
});

app.patch("/api/admin/shipping/rules/:id", requireAdmin, requireRole("owner", "manager"), async (req, res) => {
  try {
    const id = parseIntOrUndefined(req.params.id);
    if (!id) return res.status(400).json({ error: "Invalid shipping rule id." });
    const payload = req.body || {};

    const updates = [];
    const values = [];
    if (payload.stateText !== undefined) {
      const value = normalizeRegionText(payload.stateText || "");
      if (!value) return res.status(400).json({ error: "stateText cannot be empty." });
      values.push(value);
      updates.push(`state_text = $${values.length}`);
    }
    if (payload.cityText !== undefined) {
      const value = normalizeRegionText(payload.cityText || "");
      values.push(value || null);
      updates.push(`city_text = $${values.length}`);
    }
    if (payload.feeKobo !== undefined) {
      const value = parseIntOrUndefined(payload.feeKobo);
      if (value === undefined || value < 0) {
        return res.status(400).json({ error: "feeKobo must be a non-negative integer." });
      }
      values.push(value);
      updates.push(`fee_kobo = $${values.length}`);
    }
    if (payload.etaMinDays !== undefined) {
      const value = parseIntOrUndefined(payload.etaMinDays);
      if (value === undefined || value < 0) {
        return res.status(400).json({ error: "etaMinDays must be >= 0." });
      }
      values.push(value);
      updates.push(`eta_min_days = $${values.length}`);
    }
    if (payload.etaMaxDays !== undefined) {
      const value = parseIntOrUndefined(payload.etaMaxDays);
      if (value === undefined || value < 0) {
        return res.status(400).json({ error: "etaMaxDays must be >= 0." });
      }
      values.push(value);
      updates.push(`eta_max_days = $${values.length}`);
    }
    if (payload.priority !== undefined) {
      const value = parseIntOrUndefined(payload.priority);
      if (value === undefined) return res.status(400).json({ error: "priority must be an integer." });
      values.push(value);
      updates.push(`priority = $${values.length}`);
    }
    if (payload.isActive !== undefined) {
      const value = parseBoolean(payload.isActive);
      if (value === undefined) return res.status(400).json({ error: "isActive must be true or false." });
      values.push(value);
      updates.push(`is_active = $${values.length}`);
    }
    if (!updates.length) return res.status(400).json({ error: "No fields to update." });

    values.push(id);
    const result = await pool.query(
      `UPDATE shipping_rules
       SET ${updates.join(", ")}, updated_at = NOW()
       WHERE id = $${values.length}
       RETURNING id, state_text, city_text, fee_kobo, eta_min_days, eta_max_days, priority, is_active, created_at, updated_at`,
      values
    );
    if (!result.rowCount) return res.status(404).json({ error: "Shipping rule not found." });
    const row = result.rows[0];
    await writeAuditLog(req, "shipping.rule.update", "shipping_rule", id, {
      changedFields: updates.map((entry) => entry.split("=")[0].trim()),
    });
    return res.json({
      rule: {
        id: Number(row.id),
        stateText: row.state_text,
        cityText: row.city_text || "",
        feeKobo: Number(row.fee_kobo || 0),
        etaMinDays: row.eta_min_days === null ? null : Number(row.eta_min_days),
        etaMaxDays: row.eta_max_days === null ? null : Number(row.eta_max_days),
        priority: Number(row.priority || 0),
        isActive: Boolean(row.is_active),
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      },
    });
  } catch (error) {
    console.error(error);
    return sendPgError(res, error, "Failed to update shipping rule.");
  }
});

app.delete(
  "/api/admin/shipping/rules/:id",
  requireAdmin,
  requireRole("owner", "manager"),
  async (req, res) => {
    try {
      const id = parseIntOrUndefined(req.params.id);
      if (!id) return res.status(400).json({ error: "Invalid shipping rule id." });
      const result = await pool.query(
        `DELETE FROM shipping_rules
         WHERE id = $1
         RETURNING id, state_text, city_text, fee_kobo`,
        [id]
      );
      if (!result.rowCount) return res.status(404).json({ error: "Shipping rule not found." });
      await writeAuditLog(req, "shipping.rule.delete", "shipping_rule", id, {
        stateText: result.rows[0].state_text,
        cityText: result.rows[0].city_text || "",
      });
      return res.json({ deleted: true, id: Number(result.rows[0].id) });
    } catch (error) {
      console.error(error);
      return sendPgError(res, error, "Failed to delete shipping rule.");
    }
  }
);

app.get("/api/admin/shipping/blackouts", requireAdmin, requireRole("owner", "manager"), async (req, res) => {
  try {
    const limit = Math.min(Math.max(parseIntOrUndefined(req.query.limit) || 200, 1), 500);
    const includeInactive = parseBoolean(req.query.includeInactive) === true;
    const where = includeInactive ? "" : "WHERE is_active = TRUE";
    const result = await pool.query(
      `SELECT
        id, starts_at, ends_at, note, is_active, created_at, updated_at
       FROM shipping_blackout_dates
       ${where}
       ORDER BY starts_at DESC, id DESC
       LIMIT $1`,
      [limit]
    );
    return res.json({
      blackouts: result.rows.map((row) => ({
        id: Number(row.id),
        startsAt: row.starts_at,
        endsAt: row.ends_at,
        note: row.note || "",
        isActive: Boolean(row.is_active),
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      })),
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to fetch shipping blackouts." });
  }
});

app.post("/api/admin/shipping/blackouts", requireAdmin, requireRole("owner", "manager"), async (req, res) => {
  try {
    const payload = req.body || {};
    const startsAt = new Date(String(payload.startsAt || ""));
    const endsAt = new Date(String(payload.endsAt || ""));
    const note = String(payload.note || "").trim();
    const isActive = payload.isActive === undefined ? true : parseBoolean(payload.isActive);
    if (Number.isNaN(startsAt.getTime()) || Number.isNaN(endsAt.getTime())) {
      return res.status(400).json({ error: "startsAt and endsAt must be valid dates." });
    }
    if (endsAt <= startsAt) {
      return res.status(400).json({ error: "endsAt must be greater than startsAt." });
    }
    if (isActive === undefined) return res.status(400).json({ error: "isActive must be true or false." });
    const result = await pool.query(
      `INSERT INTO shipping_blackout_dates
        (starts_at, ends_at, note, is_active)
       VALUES
        ($1, $2, $3, $4)
       RETURNING id, starts_at, ends_at, note, is_active, created_at, updated_at`,
      [startsAt.toISOString(), endsAt.toISOString(), note, Boolean(isActive)]
    );
    const row = result.rows[0];
    await writeAuditLog(req, "shipping.blackout.create", "shipping_blackout", row.id, {
      startsAt: row.starts_at,
      endsAt: row.ends_at,
      isActive: Boolean(row.is_active),
    });
    return res.status(201).json({
      blackout: {
        id: Number(row.id),
        startsAt: row.starts_at,
        endsAt: row.ends_at,
        note: row.note || "",
        isActive: Boolean(row.is_active),
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      },
    });
  } catch (error) {
    console.error(error);
    return sendPgError(res, error, "Failed to create shipping blackout.");
  }
});

app.patch(
  "/api/admin/shipping/blackouts/:id",
  requireAdmin,
  requireRole("owner", "manager"),
  async (req, res) => {
    try {
      const id = parseIntOrUndefined(req.params.id);
      if (!id) return res.status(400).json({ error: "Invalid blackout id." });
      const payload = req.body || {};
      const updates = [];
      const values = [];
      if (payload.startsAt !== undefined) {
        const startsAt = new Date(String(payload.startsAt || ""));
        if (Number.isNaN(startsAt.getTime())) return res.status(400).json({ error: "startsAt is invalid." });
        values.push(startsAt.toISOString());
        updates.push(`starts_at = $${values.length}`);
      }
      if (payload.endsAt !== undefined) {
        const endsAt = new Date(String(payload.endsAt || ""));
        if (Number.isNaN(endsAt.getTime())) return res.status(400).json({ error: "endsAt is invalid." });
        values.push(endsAt.toISOString());
        updates.push(`ends_at = $${values.length}`);
      }
      if (payload.note !== undefined) {
        values.push(String(payload.note || "").trim());
        updates.push(`note = $${values.length}`);
      }
      if (payload.isActive !== undefined) {
        const isActive = parseBoolean(payload.isActive);
        if (isActive === undefined) return res.status(400).json({ error: "isActive must be true or false." });
        values.push(Boolean(isActive));
        updates.push(`is_active = $${values.length}`);
      }
      if (!updates.length) return res.status(400).json({ error: "No fields to update." });
      values.push(id);
      const result = await pool.query(
        `UPDATE shipping_blackout_dates
         SET ${updates.join(", ")}, updated_at = NOW()
         WHERE id = $${values.length}
         RETURNING id, starts_at, ends_at, note, is_active, created_at, updated_at`,
        values
      );
      if (!result.rowCount) return res.status(404).json({ error: "Blackout not found." });
      const row = result.rows[0];
      await writeAuditLog(req, "shipping.blackout.update", "shipping_blackout", id, {
        changedFields: updates.map((entry) => entry.split("=")[0].trim()),
      });
      return res.json({
        blackout: {
          id: Number(row.id),
          startsAt: row.starts_at,
          endsAt: row.ends_at,
          note: row.note || "",
          isActive: Boolean(row.is_active),
          createdAt: row.created_at,
          updatedAt: row.updated_at,
        },
      });
    } catch (error) {
      console.error(error);
      return sendPgError(res, error, "Failed to update shipping blackout.");
    }
  }
);

app.delete(
  "/api/admin/shipping/blackouts/:id",
  requireAdmin,
  requireRole("owner", "manager"),
  async (req, res) => {
    try {
      const id = parseIntOrUndefined(req.params.id);
      if (!id) return res.status(400).json({ error: "Invalid blackout id." });
      const result = await pool.query(
        `DELETE FROM shipping_blackout_dates
         WHERE id = $1
         RETURNING id`,
        [id]
      );
      if (!result.rowCount) return res.status(404).json({ error: "Blackout not found." });
      await writeAuditLog(req, "shipping.blackout.delete", "shipping_blackout", id, {});
      return res.json({ deleted: true, id: Number(result.rows[0].id) });
    } catch (error) {
      console.error(error);
      return sendPgError(res, error, "Failed to delete shipping blackout.");
    }
  }
);

app.get("/api/products", async (req, res) => {
  try {
    const { brand, q } = req.query;
    const featured = parseBoolean(req.query.featured);
    const limit = parseIntOrUndefined(req.query.limit) ?? 100;

    const where = [];
    const values = [];

    if (brand) {
      if (!BRAND_VALUES.has(String(brand))) {
        return res.status(400).json({ error: "Invalid brand value" });
      }
      values.push(String(brand));
      where.push(`brand = $${values.length}`);
    }

    if (featured !== undefined) {
      values.push(featured);
      where.push(`is_featured = $${values.length}`);
    }

    if (q) {
      values.push(`%${String(q).trim()}%`);
      where.push(
        `(name ILIKE $${values.length} OR category ILIKE $${values.length} OR description ILIKE $${values.length})`
      );
    }

    values.push(Math.min(Math.max(limit, 1), 500));

    const result = await pool.query(
      `SELECT ${productFields}
       FROM products
       ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
       ORDER BY is_featured DESC, created_at DESC
       LIMIT $${values.length}`,
      values
    );

    res.json({ products: result.rows.map(toProduct) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to fetch products" });
  }
});

app.get("/api/products/:id", async (req, res) => {
  try {
    const id = parseIntOrUndefined(req.params.id);
    if (id === undefined) {
      return res.status(400).json({ error: "Invalid product id" });
    }

    const result = await pool.query(`SELECT ${productFields} FROM products WHERE id = $1`, [id]);
    if (!result.rowCount) {
      return res.status(404).json({ error: "Product not found" });
    }

    return res.json({ product: toProduct(result.rows[0]) });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to fetch product" });
  }
});

app.get("/api/products/:id/variants", async (req, res) => {
  try {
    const id = parseIntOrUndefined(req.params.id);
    if (!id) return res.status(400).json({ error: "Invalid product id." });
    const includeInactive = parseBoolean(req.query.includeInactive) === true;
    const values = [id];
    const where = includeInactive ? "" : "AND is_active = TRUE";
    const result = await pool.query(
      `SELECT
        id, product_id, sku, option_size, option_color, option_style, price_override_kobo,
        stock_qty, reorder_threshold, image_url, is_active, created_at, updated_at
       FROM product_variants
       WHERE product_id = $1
       ${where}
       ORDER BY option_size ASC NULLS LAST, option_color ASC NULLS LAST, option_style ASC NULLS LAST, id ASC`,
      values
    );
    return res.json({ variants: result.rows.map(toVariant) });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to fetch product variants." });
  }
});

app.post("/api/products", requireAdmin, requireRole("owner", "manager", "editor"), async (req, res) => {
  try {
    const { errors, data } = normalizeProductPayload(req.body);
    if (errors.length) {
      return res.status(400).json({ error: "Validation failed", details: errors });
    }

    const result = await pool.query(
      `INSERT INTO products
        (name, slug, brand, category, description, price_kobo, compare_at_kobo, stock_qty, reorder_threshold, image_url, gallery_urls, is_featured)
       VALUES
        ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::text[], $12)
       RETURNING ${productFields}`,
      [
        data.name,
        data.slug,
        data.brand,
        data.category,
        data.description,
        data.price_kobo,
        data.compare_at_kobo,
        data.stock_qty,
        data.reorder_threshold,
        data.image_url,
        data.gallery_urls,
        data.is_featured,
      ]
    );
    const created = toProduct(result.rows[0]);
    await writeAuditLog(req, "product.create", "product", created.id, {
      name: created.name,
      brand: created.brand,
      stockQty: created.stockQty,
      reorderThreshold: created.reorderThreshold,
    });

    return res.status(201).json({ product: created });
  } catch (error) {
    console.error(error);
    return sendPgError(res, error, "Failed to create product");
  }
});

app.put("/api/products/:id", requireAdmin, requireRole("owner", "manager", "editor"), async (req, res) => {
  try {
    const id = parseIntOrUndefined(req.params.id);
    if (id === undefined) {
      return res.status(400).json({ error: "Invalid product id" });
    }

    const { errors, data } = normalizeProductPayload(req.body, { partial: true });
    if (errors.length) {
      return res.status(400).json({ error: "Validation failed", details: errors });
    }

    const updates = Object.entries(data);
    if (!updates.length) {
      return res.status(400).json({ error: "No valid fields provided for update" });
    }

    const values = [];
    const sets = updates.map(([column, value], index) => {
      values.push(value);
      if (column === "gallery_urls") {
        return `${column} = $${index + 1}::text[]`;
      }
      return `${column} = $${index + 1}`;
    });

    values.push(id);

    const result = await pool.query(
      `UPDATE products
       SET ${sets.join(", ")}, updated_at = NOW()
       WHERE id = $${values.length}
       RETURNING ${productFields}`,
      values
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Product not found" });
    }

    const updated = toProduct(result.rows[0]);
    await writeAuditLog(req, "product.update", "product", updated.id, {
      changedFields: Object.keys(data),
      stockQty: updated.stockQty,
      reorderThreshold: updated.reorderThreshold,
    });
    return res.json({ product: updated });
  } catch (error) {
    console.error(error);
    return sendPgError(res, error, "Failed to update product");
  }
});

app.delete("/api/products/:id", requireAdmin, requireRole("owner", "manager"), async (req, res) => {
  try {
    const id = parseIntOrUndefined(req.params.id);
    if (id === undefined) {
      return res.status(400).json({ error: "Invalid product id" });
    }

    const result = await pool.query(
      `DELETE FROM products WHERE id = $1 RETURNING id, name, brand`,
      [id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Product not found" });
    }

    await writeAuditLog(req, "product.delete", "product", result.rows[0].id, {
      name: result.rows[0].name,
      brand: result.rows[0].brand,
    });
    return res.json({ deleted: result.rows[0] });
  } catch (error) {
    console.error(error);
    return sendPgError(res, error, "Failed to delete product");
  }
});

app.patch(
  "/api/products/:id/reorder-threshold",
  requireAdmin,
  requireRole("owner", "manager", "editor"),
  async (req, res) => {
    try {
      const id = parseIntOrUndefined(req.params.id);
      if (!id) return res.status(400).json({ error: "Invalid product id." });

      const threshold = parseIntOrUndefined((req.body || {}).reorderThreshold);
      if (threshold === undefined || threshold < 0) {
        return res.status(400).json({ error: "reorderThreshold must be a non-negative integer." });
      }

      const result = await pool.query(
        `UPDATE products
         SET reorder_threshold = $1, updated_at = NOW()
         WHERE id = $2
         RETURNING ${productFields}`,
        [threshold, id]
      );
      if (!result.rowCount) return res.status(404).json({ error: "Product not found." });

      const updated = toProduct(result.rows[0]);
      await writeAuditLog(req, "product.reorder_threshold.update", "product", updated.id, {
        reorderThreshold: updated.reorderThreshold,
      });
      return res.json({ product: updated });
    } catch (error) {
      console.error(error);
      return sendPgError(res, error, "Failed to update reorder threshold.");
    }
  }
);

app.get(
  "/api/admin/products/:id/variants",
  requireAdmin,
  requireRole("owner", "manager", "editor", "viewer"),
  async (req, res) => {
    try {
      const productId = parseIntOrUndefined(req.params.id);
      if (!productId) return res.status(400).json({ error: "Invalid product id." });
      const includeInactive = parseBoolean(req.query.includeInactive) === true;
      const where = includeInactive ? "" : "AND v.is_active = TRUE";
      const result = await pool.query(
        `SELECT
          v.id, v.product_id, v.sku, v.option_size, v.option_color, v.option_style, v.price_override_kobo,
          v.stock_qty, v.reorder_threshold, v.image_url, v.is_active, v.created_at, v.updated_at
         FROM product_variants v
         WHERE v.product_id = $1
         ${where}
         ORDER BY v.option_size ASC NULLS LAST, v.option_color ASC NULLS LAST, v.option_style ASC NULLS LAST, v.id ASC`,
        [productId]
      );
      return res.json({ variants: result.rows.map(toVariant) });
    } catch (error) {
      console.error(error);
      return res.status(500).json({ error: "Failed to fetch product variants." });
    }
  }
);

app.post(
  "/api/admin/products/:id/variants",
  requireAdmin,
  requireRole("owner", "manager", "editor"),
  async (req, res) => {
    try {
      const productId = parseIntOrUndefined(req.params.id);
      if (!productId) return res.status(400).json({ error: "Invalid product id." });
      const payload = req.body || {};
      const sku = String(payload.sku || "").trim();
      const optionSize = String(payload.optionSize || "").trim() || null;
      const optionColor = String(payload.optionColor || "").trim() || null;
      const optionStyle = String(payload.optionStyle || "").trim() || null;
      const priceOverrideKoboRaw = payload.priceOverrideKobo;
      const priceOverrideKobo =
        priceOverrideKoboRaw === undefined || priceOverrideKoboRaw === null || priceOverrideKoboRaw === ""
          ? null
          : parseIntOrUndefined(priceOverrideKoboRaw);
      const stockQty = parseIntOrUndefined(payload.stockQty);
      const reorderThreshold = parseIntOrUndefined(payload.reorderThreshold);
      const imageUrl = String(payload.imageUrl || "").trim() || null;
      const isActive = payload.isActive === undefined ? true : parseBoolean(payload.isActive);

      if (!sku) return res.status(400).json({ error: "sku is required." });
      if (priceOverrideKobo !== null && (priceOverrideKobo === undefined || priceOverrideKobo < 0)) {
        return res.status(400).json({ error: "priceOverrideKobo must be null or a non-negative integer." });
      }
      if (stockQty === undefined || stockQty < 0) {
        return res.status(400).json({ error: "stockQty must be a non-negative integer." });
      }
      if (reorderThreshold !== undefined && reorderThreshold < 0) {
        return res.status(400).json({ error: "reorderThreshold must be a non-negative integer." });
      }
      if (isActive === undefined) {
        return res.status(400).json({ error: "isActive must be true or false." });
      }

      const productResult = await pool.query(
        `SELECT id, name, has_variants FROM products WHERE id = $1 LIMIT 1`,
        [productId]
      );
      if (!productResult.rowCount) return res.status(404).json({ error: "Product not found." });

      const result = await pool.query(
        `INSERT INTO product_variants
          (product_id, sku, option_size, option_color, option_style, price_override_kobo, stock_qty, reorder_threshold, image_url, is_active)
         VALUES
          ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         RETURNING id, product_id, sku, option_size, option_color, option_style, price_override_kobo, stock_qty, reorder_threshold, image_url, is_active, created_at, updated_at`,
        [
          productId,
          sku,
          optionSize,
          optionColor,
          optionStyle,
          priceOverrideKobo,
          stockQty,
          reorderThreshold === undefined ? 2 : reorderThreshold,
          imageUrl,
          Boolean(isActive),
        ]
      );
      const row = result.rows[0];

      await pool.query(
        `UPDATE products
         SET has_variants = TRUE, updated_at = NOW()
         WHERE id = $1`,
        [productId]
      );

      await insertStockMovement(pool, {
        productId,
        variantId: Number(row.id),
        movementType: "restock",
        deltaQty: Number(row.stock_qty || 0),
        reason: "Variant created",
        referenceType: "variant",
        referenceId: String(row.id),
        adminUserId: req.admin?.userId || null,
        adminUsername: req.admin?.username || "system",
      });

      await writeAuditLog(req, "product.variant.create", "product_variant", row.id, {
        productId,
        sku: row.sku,
      });

      return res.status(201).json({ variant: toVariant(row) });
    } catch (error) {
      console.error(error);
      return sendPgError(res, error, "Failed to create product variant.");
    }
  }
);

app.put(
  "/api/admin/variants/:id",
  requireAdmin,
  requireRole("owner", "manager", "editor"),
  async (req, res) => {
    try {
      const id = parseIntOrUndefined(req.params.id);
      if (!id) return res.status(400).json({ error: "Invalid variant id." });
      const payload = req.body || {};

      const updates = [];
      const values = [];
      if (payload.sku !== undefined) {
        const value = String(payload.sku || "").trim();
        if (!value) return res.status(400).json({ error: "sku cannot be empty." });
        values.push(value);
        updates.push(`sku = $${values.length}`);
      }
      if (payload.optionSize !== undefined) {
        values.push(String(payload.optionSize || "").trim() || null);
        updates.push(`option_size = $${values.length}`);
      }
      if (payload.optionColor !== undefined) {
        values.push(String(payload.optionColor || "").trim() || null);
        updates.push(`option_color = $${values.length}`);
      }
      if (payload.optionStyle !== undefined) {
        values.push(String(payload.optionStyle || "").trim() || null);
        updates.push(`option_style = $${values.length}`);
      }
      if (payload.priceOverrideKobo !== undefined) {
        const raw = payload.priceOverrideKobo;
        const value =
          raw === null || raw === ""
            ? null
            : parseIntOrUndefined(raw);
        if (value !== null && (value === undefined || value < 0)) {
          return res.status(400).json({ error: "priceOverrideKobo must be null or a non-negative integer." });
        }
        values.push(value);
        updates.push(`price_override_kobo = $${values.length}`);
      }
      if (payload.stockQty !== undefined) {
        const value = parseIntOrUndefined(payload.stockQty);
        if (value === undefined || value < 0) {
          return res.status(400).json({ error: "stockQty must be a non-negative integer." });
        }
        values.push(value);
        updates.push(`stock_qty = $${values.length}`);
      }
      if (payload.reorderThreshold !== undefined) {
        const value = parseIntOrUndefined(payload.reorderThreshold);
        if (value === undefined || value < 0) {
          return res.status(400).json({ error: "reorderThreshold must be a non-negative integer." });
        }
        values.push(value);
        updates.push(`reorder_threshold = $${values.length}`);
      }
      if (payload.imageUrl !== undefined) {
        values.push(String(payload.imageUrl || "").trim() || null);
        updates.push(`image_url = $${values.length}`);
      }
      if (payload.isActive !== undefined) {
        const value = parseBoolean(payload.isActive);
        if (value === undefined) return res.status(400).json({ error: "isActive must be true or false." });
        values.push(value);
        updates.push(`is_active = $${values.length}`);
      }
      if (!updates.length) return res.status(400).json({ error: "No valid fields provided for update." });

      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const beforeResult = await client.query(
          `SELECT id, product_id, stock_qty FROM product_variants WHERE id = $1 FOR UPDATE`,
          [id]
        );
        if (!beforeResult.rowCount) {
          await client.query("ROLLBACK");
          return res.status(404).json({ error: "Variant not found." });
        }
        const before = beforeResult.rows[0];
        values.push(id);
        const updateResult = await client.query(
          `UPDATE product_variants
           SET ${updates.join(", ")}, updated_at = NOW()
           WHERE id = $${values.length}
           RETURNING id, product_id, sku, option_size, option_color, option_style, price_override_kobo, stock_qty, reorder_threshold, image_url, is_active, created_at, updated_at`,
          values
        );
        const row = updateResult.rows[0];
        const deltaQty = Number(row.stock_qty || 0) - Number(before.stock_qty || 0);
        if (deltaQty !== 0) {
          await insertStockMovement(client, {
            productId: Number(row.product_id),
            variantId: Number(row.id),
            movementType: deltaQty > 0 ? "restock" : "adjustment",
            deltaQty,
            reason: "Variant stock updated in admin",
            referenceType: "variant",
            referenceId: String(row.id),
            adminUserId: req.admin?.userId || null,
            adminUsername: req.admin?.username || "system",
          });
        }
        await client.query("COMMIT");
        await writeAuditLog(req, "product.variant.update", "product_variant", row.id, {
          changedFields: updates.map((entry) => entry.split("=")[0].trim()),
        });
        return res.json({ variant: toVariant(row) });
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
    } catch (error) {
      console.error(error);
      return sendPgError(res, error, "Failed to update product variant.");
    }
  }
);

app.patch(
  "/api/admin/variants/:id/stock",
  requireAdmin,
  requireRole("owner", "manager", "editor"),
  async (req, res) => {
    try {
      const id = parseIntOrUndefined(req.params.id);
      if (!id) return res.status(400).json({ error: "Invalid variant id." });
      const payload = req.body || {};
      const deltaQty = parseIntOrUndefined(payload.deltaQty);
      const reason = String(payload.reason || "").trim() || "Manual stock adjustment";
      if (deltaQty === undefined || deltaQty === 0) {
        return res.status(400).json({ error: "deltaQty must be a non-zero integer." });
      }

      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const variantResult = await client.query(
          `SELECT id, product_id, stock_qty FROM product_variants WHERE id = $1 FOR UPDATE`,
          [id]
        );
        if (!variantResult.rowCount) {
          await client.query("ROLLBACK");
          return res.status(404).json({ error: "Variant not found." });
        }
        const variant = variantResult.rows[0];
        const nextQty = Number(variant.stock_qty || 0) + Number(deltaQty);
        if (nextQty < 0) {
          await client.query("ROLLBACK");
          return res.status(409).json({ error: "Resulting stock cannot be negative." });
        }
        const updateResult = await client.query(
          `UPDATE product_variants
           SET stock_qty = $1, updated_at = NOW()
           WHERE id = $2
           RETURNING id, product_id, sku, option_size, option_color, option_style, price_override_kobo, stock_qty, reorder_threshold, image_url, is_active, created_at, updated_at`,
          [nextQty, id]
        );
        const row = updateResult.rows[0];
        await insertStockMovement(client, {
          productId: Number(row.product_id),
          variantId: Number(row.id),
          movementType: deltaQty > 0 ? "restock" : "adjustment",
          deltaQty,
          reason,
          referenceType: "variant",
          referenceId: String(row.id),
          adminUserId: req.admin?.userId || null,
          adminUsername: req.admin?.username || "system",
        });
        await client.query("COMMIT");
        await writeAuditLog(req, "product.variant.stock.adjust", "product_variant", row.id, {
          deltaQty,
          reason,
        });
        return res.json({ variant: toVariant(row) });
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
    } catch (error) {
      console.error(error);
      return sendPgError(res, error, "Failed to adjust variant stock.");
    }
  }
);

app.delete(
  "/api/admin/variants/:id",
  requireAdmin,
  requireRole("owner", "manager"),
  async (req, res) => {
    try {
      const id = parseIntOrUndefined(req.params.id);
      if (!id) return res.status(400).json({ error: "Invalid variant id." });
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const existing = await client.query(
          `SELECT id, product_id, stock_qty, sku FROM product_variants WHERE id = $1 FOR UPDATE`,
          [id]
        );
        if (!existing.rowCount) {
          await client.query("ROLLBACK");
          return res.status(404).json({ error: "Variant not found." });
        }
        const variant = existing.rows[0];
        await client.query(`DELETE FROM product_variants WHERE id = $1`, [id]);

        const remaining = await client.query(
          `SELECT 1 FROM product_variants WHERE product_id = $1 LIMIT 1`,
          [Number(variant.product_id)]
        );
        if (!remaining.rowCount) {
          await client.query(
            `UPDATE products
             SET has_variants = FALSE, updated_at = NOW()
             WHERE id = $1`,
            [Number(variant.product_id)]
          );
        }

        await insertStockMovement(client, {
          productId: Number(variant.product_id),
          variantId: Number(variant.id),
          movementType: "manual",
          deltaQty: -Number(variant.stock_qty || 0),
          reason: "Variant deleted",
          referenceType: "variant",
          referenceId: String(variant.id),
          adminUserId: req.admin?.userId || null,
          adminUsername: req.admin?.username || "system",
        });

        await client.query("COMMIT");
        await writeAuditLog(req, "product.variant.delete", "product_variant", id, {
          productId: Number(variant.product_id),
          sku: variant.sku,
        });
        return res.json({ deleted: true, id });
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
    } catch (error) {
      console.error(error);
      return sendPgError(res, error, "Failed to delete product variant.");
    }
  }
);

app.get("/api/admin/inventory/alerts", requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(Math.max(parseIntOrUndefined(req.query.limit) || 100, 1), 500);
    const [productResult, variantResult] = await Promise.all([
      pool.query(
        `SELECT ${productFields}
         FROM products
         WHERE stock_qty <= reorder_threshold
         ORDER BY stock_qty ASC, updated_at DESC
         LIMIT $1`,
        [limit]
      ),
      pool.query(
        `SELECT
          v.id, v.product_id, v.sku, v.option_size, v.option_color, v.option_style, v.price_override_kobo,
          v.stock_qty, v.reorder_threshold, v.image_url, v.is_active, v.created_at, v.updated_at,
          p.name AS product_name, p.brand AS product_brand
         FROM product_variants v
         INNER JOIN products p ON p.id = v.product_id
         WHERE v.is_active = TRUE
           AND v.stock_qty <= v.reorder_threshold
         ORDER BY v.stock_qty ASC, v.updated_at DESC
         LIMIT $1`,
        [limit]
      ),
    ]);

    res.json({
      alerts: productResult.rows.map((row) => ({
        ...toProduct(row),
        shortfall: Math.max(Number(row.reorder_threshold || 0) - Number(row.stock_qty || 0), 0),
      })),
      variantAlerts: variantResult.rows.map((row) => ({
        ...toVariant(row),
        productName: row.product_name,
        productBrand: row.product_brand,
        shortfall: Math.max(Number(row.reorder_threshold || 0) - Number(row.stock_qty || 0), 0),
      })),
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to fetch low-stock alerts." });
  }
});

app.get("/api/admin/inventory/stock-movements", requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(Math.max(parseIntOrUndefined(req.query.limit) || 200, 1), 500);
    const productId = parseIntOrUndefined(req.query.productId);
    const variantId = parseIntOrUndefined(req.query.variantId);
    const where = [];
    const values = [];
    if (productId) {
      values.push(productId);
      where.push(`sm.product_id = $${values.length}`);
    }
    if (variantId) {
      values.push(variantId);
      where.push(`sm.variant_id = $${values.length}`);
    }
    values.push(limit);
    const result = await pool.query(
      `SELECT
        sm.id, sm.product_id, sm.variant_id, sm.movement_type, sm.delta_qty, sm.reason,
        sm.reference_type, sm.reference_id, sm.admin_user_id, sm.admin_username, sm.created_at,
        p.name AS product_name, p.brand AS product_brand,
        v.sku AS variant_sku, v.option_size, v.option_color, v.option_style
       FROM stock_movements sm
       LEFT JOIN products p ON p.id = sm.product_id
       LEFT JOIN product_variants v ON v.id = sm.variant_id
       ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
       ORDER BY sm.created_at DESC, sm.id DESC
       LIMIT $${values.length}`,
      values
    );
    return res.json({
      movements: result.rows.map((row) => ({
        id: Number(row.id),
        productId: row.product_id === null ? null : Number(row.product_id),
        variantId: row.variant_id === null ? null : Number(row.variant_id),
        productName: row.product_name || null,
        productBrand: row.product_brand || null,
        variantSku: row.variant_sku || null,
        variantLabel: buildVariantLabelFromValues(row.option_size, row.option_color, row.option_style) || null,
        movementType: row.movement_type,
        deltaQty: Number(row.delta_qty || 0),
        reason: row.reason || "",
        referenceType: row.reference_type || null,
        referenceId: row.reference_id || null,
        adminUserId: row.admin_user_id === null ? null : Number(row.admin_user_id),
        adminUsername: row.admin_username || "system",
        createdAt: row.created_at,
      })),
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to fetch stock movements." });
  }
});

app.post("/api/coupons/validate", async (req, res) => {
  try {
    const payload = req.body || {};
    const code = String(payload.code || "").trim();
    const subtotalKobo = toKobo(payload.subtotalKobo);
    const brands = Array.isArray(payload.brands)
      ? payload.brands.map((brand) => String(brand))
      : [];

    if (!code) return res.status(400).json({ error: "Coupon code is required." });
    if (subtotalKobo <= 0) return res.status(400).json({ error: "subtotalKobo must be > 0." });

    const client = await pool.connect();
    try {
      const validated = await validateCouponForCart(client, code, subtotalKobo, brands);
      if (!validated.valid) {
        return res.status(400).json({ valid: false, error: validated.error });
      }
      return res.json({
        valid: true,
        coupon: validated.coupon,
        discountKobo: validated.discountKobo,
        totalKobo: Math.max(subtotalKobo - validated.discountKobo, 0),
      });
    } finally {
      client.release();
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Coupon validation failed." });
  }
});

app.get("/api/admin/coupons", requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(Math.max(parseIntOrUndefined(req.query.limit) || 100, 1), 500);
    const result = await pool.query(
      `SELECT
        id, code, description, discount_type, discount_value, min_order_kobo, max_discount_kobo,
        brand, is_active, usage_limit, used_count, starts_at, expires_at, created_at, updated_at
       FROM coupons
       ORDER BY created_at DESC
       LIMIT $1`,
      [limit]
    );
    res.json({
      coupons: result.rows.map((row) => ({
        id: Number(row.id),
        code: row.code,
        description: row.description,
        discountType: row.discount_type,
        discountValue: Number(row.discount_value),
        minOrderKobo: Number(row.min_order_kobo || 0),
        maxDiscountKobo:
          row.max_discount_kobo === null || row.max_discount_kobo === undefined
            ? null
            : Number(row.max_discount_kobo),
        brand: row.brand || null,
        isActive: row.is_active,
        usageLimit: row.usage_limit === null ? null : Number(row.usage_limit),
        usedCount: Number(row.used_count || 0),
        startsAt: row.starts_at,
        expiresAt: row.expires_at,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      })),
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to fetch coupons." });
  }
});

app.post("/api/admin/coupons", requireAdmin, requireRole("owner", "manager"), async (req, res) => {
  try {
    const payload = req.body || {};
    const code = String(payload.code || "").trim().toUpperCase();
    const description = String(payload.description || "").trim();
    const discountType = String(payload.discountType || "").trim().toLowerCase();
    const discountValue = parseIntOrUndefined(payload.discountValue);
    const minOrderKobo = toKobo(payload.minOrderKobo);
    const maxDiscountKobo =
      payload.maxDiscountKobo === undefined || payload.maxDiscountKobo === null || payload.maxDiscountKobo === ""
        ? null
        : toKobo(payload.maxDiscountKobo);
    const brandRaw = payload.brand;
    const brand =
      brandRaw === undefined || brandRaw === null || String(brandRaw).trim() === ""
        ? null
        : String(brandRaw).trim();
    const isActive = payload.isActive === undefined ? true : parseBoolean(payload.isActive);
    const usageLimit =
      payload.usageLimit === undefined || payload.usageLimit === null || payload.usageLimit === ""
        ? null
        : parseIntOrUndefined(payload.usageLimit);
    const startsAt =
      payload.startsAt === undefined || payload.startsAt === null || payload.startsAt === ""
        ? null
        : new Date(String(payload.startsAt));
    const expiresAt =
      payload.expiresAt === undefined || payload.expiresAt === null || payload.expiresAt === ""
        ? null
        : new Date(String(payload.expiresAt));

    if (!code) return res.status(400).json({ error: "code is required." });
    if (!["percent", "fixed"].includes(discountType)) {
      return res.status(400).json({ error: "discountType must be percent or fixed." });
    }
    if (discountValue === undefined || discountValue <= 0) {
      return res.status(400).json({ error: "discountValue must be > 0." });
    }
    if (discountType === "percent" && (discountValue < 1 || discountValue > 100)) {
      return res.status(400).json({ error: "Percent discount must be between 1 and 100." });
    }
    if (brand && !BRAND_VALUES.has(brand)) {
      return res.status(400).json({ error: "Invalid brand value for coupon." });
    }
    if (isActive === undefined) return res.status(400).json({ error: "isActive must be true or false." });
    if (usageLimit !== null && (usageLimit === undefined || usageLimit <= 0)) {
      return res.status(400).json({ error: "usageLimit must be a positive integer or null." });
    }
    if (startsAt && Number.isNaN(startsAt.getTime())) return res.status(400).json({ error: "Invalid startsAt date." });
    if (expiresAt && Number.isNaN(expiresAt.getTime())) return res.status(400).json({ error: "Invalid expiresAt date." });

    const result = await pool.query(
      `INSERT INTO coupons
        (code, description, discount_type, discount_value, min_order_kobo, max_discount_kobo, brand, is_active, usage_limit, starts_at, expires_at)
       VALUES
        ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       RETURNING
        id, code, description, discount_type, discount_value, min_order_kobo, max_discount_kobo,
        brand, is_active, usage_limit, used_count, starts_at, expires_at, created_at, updated_at`,
      [
        code,
        description,
        discountType,
        discountValue,
        minOrderKobo,
        maxDiscountKobo,
        brand,
        isActive,
        usageLimit,
        startsAt ? startsAt.toISOString() : null,
        expiresAt ? expiresAt.toISOString() : null,
      ]
    );

    const row = result.rows[0];
    await writeAuditLog(req, "coupon.create", "coupon", row.id, {
      code: row.code,
      discountType: row.discount_type,
      discountValue: Number(row.discount_value),
    });

    return res.status(201).json({
      coupon: {
        id: Number(row.id),
        code: row.code,
        description: row.description,
        discountType: row.discount_type,
        discountValue: Number(row.discount_value),
        minOrderKobo: Number(row.min_order_kobo || 0),
        maxDiscountKobo: row.max_discount_kobo === null ? null : Number(row.max_discount_kobo),
        brand: row.brand || null,
        isActive: row.is_active,
        usageLimit: row.usage_limit === null ? null : Number(row.usage_limit),
        usedCount: Number(row.used_count || 0),
        startsAt: row.starts_at,
        expiresAt: row.expires_at,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      },
    });
  } catch (error) {
    console.error(error);
    return sendPgError(res, error, "Failed to create coupon.");
  }
});

app.patch("/api/admin/coupons/:id", requireAdmin, requireRole("owner", "manager"), async (req, res) => {
  try {
    const id = parseIntOrUndefined(req.params.id);
    if (!id) return res.status(400).json({ error: "Invalid coupon id." });

    const payload = req.body || {};
    const updates = [];
    const values = [];

    if (payload.description !== undefined) {
      updates.push(`description = $${values.length + 1}`);
      values.push(String(payload.description || "").trim());
    }
    if (payload.discountType !== undefined) {
      const discountType = String(payload.discountType || "").trim().toLowerCase();
      if (!["percent", "fixed"].includes(discountType)) {
        return res.status(400).json({ error: "discountType must be percent or fixed." });
      }
      updates.push(`discount_type = $${values.length + 1}`);
      values.push(discountType);
    }
    if (payload.discountValue !== undefined) {
      const discountValue = parseIntOrUndefined(payload.discountValue);
      if (discountValue === undefined || discountValue <= 0) {
        return res.status(400).json({ error: "discountValue must be > 0." });
      }
      updates.push(`discount_value = $${values.length + 1}`);
      values.push(discountValue);
    }
    if (payload.minOrderKobo !== undefined) {
      updates.push(`min_order_kobo = $${values.length + 1}`);
      values.push(toKobo(payload.minOrderKobo));
    }
    if (payload.maxDiscountKobo !== undefined) {
      const maxVal =
        payload.maxDiscountKobo === null || payload.maxDiscountKobo === ""
          ? null
          : toKobo(payload.maxDiscountKobo);
      updates.push(`max_discount_kobo = $${values.length + 1}`);
      values.push(maxVal);
    }
    if (payload.brand !== undefined) {
      const brand =
        payload.brand === null || String(payload.brand).trim() === ""
          ? null
          : String(payload.brand).trim();
      if (brand && !BRAND_VALUES.has(brand)) {
        return res.status(400).json({ error: "Invalid brand value." });
      }
      updates.push(`brand = $${values.length + 1}`);
      values.push(brand);
    }
    if (payload.isActive !== undefined) {
      const isActive = parseBoolean(payload.isActive);
      if (isActive === undefined) return res.status(400).json({ error: "isActive must be true or false." });
      updates.push(`is_active = $${values.length + 1}`);
      values.push(isActive);
    }
    if (payload.usageLimit !== undefined) {
      const usageLimit =
        payload.usageLimit === null || payload.usageLimit === ""
          ? null
          : parseIntOrUndefined(payload.usageLimit);
      if (usageLimit !== null && (usageLimit === undefined || usageLimit <= 0)) {
        return res.status(400).json({ error: "usageLimit must be a positive integer or null." });
      }
      updates.push(`usage_limit = $${values.length + 1}`);
      values.push(usageLimit);
    }
    if (payload.startsAt !== undefined) {
      const startsAt =
        payload.startsAt === null || payload.startsAt === ""
          ? null
          : new Date(String(payload.startsAt));
      if (startsAt && Number.isNaN(startsAt.getTime())) {
        return res.status(400).json({ error: "Invalid startsAt date." });
      }
      updates.push(`starts_at = $${values.length + 1}`);
      values.push(startsAt ? startsAt.toISOString() : null);
    }
    if (payload.expiresAt !== undefined) {
      const expiresAt =
        payload.expiresAt === null || payload.expiresAt === ""
          ? null
          : new Date(String(payload.expiresAt));
      if (expiresAt && Number.isNaN(expiresAt.getTime())) {
        return res.status(400).json({ error: "Invalid expiresAt date." });
      }
      updates.push(`expires_at = $${values.length + 1}`);
      values.push(expiresAt ? expiresAt.toISOString() : null);
    }

    if (!updates.length) return res.status(400).json({ error: "No valid fields to update." });

    values.push(id);
    const result = await pool.query(
      `UPDATE coupons
       SET ${updates.join(", ")}, updated_at = NOW()
       WHERE id = $${values.length}
       RETURNING
        id, code, description, discount_type, discount_value, min_order_kobo, max_discount_kobo,
        brand, is_active, usage_limit, used_count, starts_at, expires_at, created_at, updated_at`,
      values
    );
    if (!result.rowCount) return res.status(404).json({ error: "Coupon not found." });

    const row = result.rows[0];
    await writeAuditLog(req, "coupon.update", "coupon", row.id, {
      changedFields: Object.keys(payload),
      code: row.code,
    });
    return res.json({
      coupon: {
        id: Number(row.id),
        code: row.code,
        description: row.description,
        discountType: row.discount_type,
        discountValue: Number(row.discount_value),
        minOrderKobo: Number(row.min_order_kobo || 0),
        maxDiscountKobo: row.max_discount_kobo === null ? null : Number(row.max_discount_kobo),
        brand: row.brand || null,
        isActive: row.is_active,
        usageLimit: row.usage_limit === null ? null : Number(row.usage_limit),
        usedCount: Number(row.used_count || 0),
        startsAt: row.starts_at,
        expiresAt: row.expires_at,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      },
    });
  } catch (error) {
    console.error(error);
    return sendPgError(res, error, "Failed to update coupon.");
  }
});

app.post("/api/paystack/initialize", async (req, res) => {
  if (!isPaystackConfigured()) {
    return res.status(503).json({
      error: "Paystack is not configured. Set PAYSTACK_PUBLIC_KEY and PAYSTACK_SECRET_KEY.",
    });
  }

  const payload = req.body || {};
  const customerName = String(payload.customerName || "").trim();
  const customerPhone = String(payload.customerPhone || "").trim();
  let customerEmail = String(payload.customerEmail || "").trim();
  const notes = String(payload.notes || "").trim();
  const shippingState = normalizeRegionText(payload.shippingState || "");
  const shippingCity = normalizeRegionText(payload.shippingCity || "");
  const couponCode = String(payload.couponCode || "").trim().toUpperCase();
  const items = Array.isArray(payload.items) ? payload.items : [];

  const customerSession = await getValidatedCustomerSession(req, { touch: false });
  const customerId = customerSession ? Number(customerSession.customerId) : null;
  const sessionEmail = normalizeEmail(customerSession?.email || "");
  if (!customerEmail && sessionEmail) {
    customerEmail = sessionEmail;
  }

  if (!customerName) return res.status(400).json({ error: "customerName is required" });
  if (!customerPhone) return res.status(400).json({ error: "customerPhone is required" });
  if (!customerEmail) return res.status(400).json({ error: "customerEmail is required for Paystack" });
  if (!shippingState) return res.status(400).json({ error: "shippingState is required" });
  if (!items.length) return res.status(400).json({ error: "Cart cannot be empty" });

  const normalized = normalizeCartItemsWithVariants(items);
  if (!normalized.valid) {
    return res.status(400).json({ error: normalized.error || "Invalid cart items." });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const catalog = await fetchCatalogForCartItems(client, normalized.items, { lockRows: false });
    if (!catalog.valid) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: catalog.error || "One or more cart items are unavailable." });
    }
    const { productMap, variantMap } = catalog;

    let subtotalKobo = 0;
    const orderItems = [];
    const brandsInCart = new Set();
    for (const item of normalized.items) {
      const product = productMap.get(item.productId);
      if (!product) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: "Invalid product in cart." });
      }
      const variant = item.variantId ? variantMap.get(item.variantId) : null;
      if (item.variantId) {
        if (!variant || !variant.isActive || variant.productId !== product.id) {
          await client.query("ROLLBACK");
          return res.status(400).json({ error: `Variant selected for "${product.name}" is invalid.` });
        }
        if (variant.stockQty < item.qty) {
          await client.query("ROLLBACK");
          return res.status(409).json({
            error: `Insufficient stock for "${product.name}" variant (${variant.label || variant.sku}). Available: ${variant.stockQty}`,
          });
        }
      } else if (product.stockQty < item.qty) {
        await client.query("ROLLBACK");
        return res.status(409).json({
          error: `Insufficient stock for "${product.name}". Available: ${product.stockQty}`,
        });
      }

      const unitPriceKobo =
        variant && variant.priceOverrideKobo !== null ? variant.priceOverrideKobo : product.priceKobo;
      const lineTotalKobo = unitPriceKobo * item.qty;
      subtotalKobo += lineTotalKobo;
      orderItems.push({
        productId: product.id,
        variantId: variant ? variant.id : null,
        variantSku: variant ? variant.sku : null,
        variantLabel: variant ? variant.label : null,
        productName: product.name,
        brand: product.brand,
        unitPriceKobo,
        qty: item.qty,
        lineTotalKobo,
      });
      brandsInCart.add(product.brand);
    }

    let coupon = null;
    let couponDiscountKobo = 0;
    if (couponCode) {
      const validated = await validateCouponForCart(
        client,
        couponCode,
        subtotalKobo,
        Array.from(brandsInCart)
      );
      if (!validated.valid) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: validated.error || "Invalid coupon." });
      }
      coupon = validated.coupon;
      couponDiscountKobo = validated.discountKobo;
    }
    const discountedSubtotalKobo = Math.max(subtotalKobo - couponDiscountKobo, 0);
    const shippingQuote = await computeShippingQuote(client, shippingState, shippingCity, discountedSubtotalKobo);
    const shippingFeeKobo = Number(shippingQuote.shippingFeeKobo || 0);
    const totalKobo = discountedSubtotalKobo + shippingFeeKobo;

    const orderNumber = generateOrderNumber();
    const reference = `SSPAY-${Date.now()}-${Math.floor(Math.random() * 1000000)}`;
    const orderResult = await client.query(
      `INSERT INTO orders
        (order_number, customer_id, customer_name, customer_phone, customer_email, notes, shipping_state, shipping_city, subtotal_kobo, shipping_fee_kobo, coupon_code, coupon_discount_kobo, total_kobo, status, payment_channel, paystack_reference)
       VALUES
        ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 'pending_payment', 'paystack', $14)
       RETURNING id, order_number, subtotal_kobo, shipping_fee_kobo, coupon_discount_kobo, total_kobo, paystack_reference`,
      [
        orderNumber,
        customerId,
        customerName,
        customerPhone,
        customerEmail,
        notes,
        shippingState,
        shippingCity || null,
        subtotalKobo,
        shippingFeeKobo,
        coupon ? coupon.code : null,
        couponDiscountKobo,
        totalKobo,
        reference,
      ]
    );
    const order = orderResult.rows[0];

    for (const item of orderItems) {
      await client.query(
        `INSERT INTO order_items
          (order_id, product_id, variant_id, variant_sku, variant_label, product_name, brand, unit_price_kobo, qty, line_total_kobo)
         VALUES
          ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [
          order.id,
          item.productId,
          item.variantId,
          item.variantSku,
          item.variantLabel,
          item.productName,
          item.brand,
          item.unitPriceKobo,
          item.qty,
          item.lineTotalKobo,
        ]
      );
    }

    const callbackUrl =
      process.env.PAYSTACK_CALLBACK_URL || `${req.protocol}://${req.get("host")}/`;

    const paystackData = await paystackRequest("/transaction/initialize", "POST", {
      amount: totalKobo,
      email: customerEmail,
      reference,
      callback_url: callbackUrl,
      metadata: {
        orderNumber: order.order_number,
        customerName,
        customerPhone,
        couponCode: coupon ? coupon.code : null,
        shippingState,
        shippingCity: shippingCity || null,
      },
    });

    await appendOrderStatusHistory(client, order.id, null, "pending_payment", "Awaiting Paystack payment", {
      userId: null,
      username: "system",
    });

    await client.query("COMMIT");

    await writeAuditLog(req, "order.create.pending_payment", "order", order.id, {
      orderNumber: order.order_number,
      subtotalKobo: Number(order.subtotal_kobo),
      shippingFeeKobo: Number(order.shipping_fee_kobo || 0),
      couponDiscountKobo: Number(order.coupon_discount_kobo || 0),
      totalKobo: Number(order.total_kobo || 0),
      reference,
    });

    return res.status(201).json({
      order: {
        id: Number(order.id),
        orderNumber: order.order_number,
        subtotalKobo: Number(order.subtotal_kobo),
        shippingFeeKobo: Number(order.shipping_fee_kobo || 0),
        couponDiscountKobo: Number(order.coupon_discount_kobo || 0),
        totalKobo: Number(order.total_kobo || 0),
        reference: order.paystack_reference,
      },
      payment: {
        reference,
        accessCode: paystackData.access_code,
        authorizationUrl: paystackData.authorization_url,
        publicKey: process.env.PAYSTACK_PUBLIC_KEY,
        email: customerEmail,
        amountKobo: totalKobo,
      },
      coupon,
    });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error(error);
    return res.status(500).json({ error: error.message || "Failed to initialize Paystack payment." });
  } finally {
    client.release();
  }
});

app.post("/api/paystack/verify", async (req, res) => {
  if (!isPaystackConfigured()) {
    return res.status(503).json({
      error: "Paystack is not configured. Set PAYSTACK_PUBLIC_KEY and PAYSTACK_SECRET_KEY.",
    });
  }

  const reference = String((req.body || {}).reference || "").trim();
  if (!reference) {
    return res.status(400).json({ error: "reference is required" });
  }

  try {
    const verified = await paystackRequest(`/transaction/verify/${encodeURIComponent(reference)}`);
    if (verified.status !== "success") {
      return res.status(400).json({ error: "Payment not successful." });
    }
    const finalized = await finalizePaidOrderByReference(reference, {
      paidAmountKobo: Number(verified.amount || 0),
      actor: { userId: null, username: "system" },
      note: "Paystack payment verified",
    });

    if (finalized.notFound) {
      return res.status(404).json({ error: "No pending order found for this payment reference." });
    }
    if (finalized.invalidAmount) {
      return res.status(409).json({ error: "Paid amount is less than order total." });
    }
    if (finalized.invalidOrder || finalized.stockConflict) {
      return res.status(409).json({ error: finalized.error || "Order cannot be finalized." });
    }

    await writeAuditLog(req, "order.payment.verified", "order", finalized.order.id, {
      reference,
      totalKobo: finalized.order.totalKobo,
      alreadyPaid: Boolean(finalized.alreadyPaid),
    });

    return res.json({
      verified: true,
      alreadyPaid: Boolean(finalized.alreadyPaid),
      order: {
        ...finalized.order,
        reference,
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: error.message || "Failed to verify Paystack payment." });
  }
});

app.post("/api/moniepoint/initialize", async (req, res) => {
  if (!isMoniepointConfigured()) {
    return res.status(503).json({
      error:
        "Moniepoint is not configured. Set MONIEPOINT_API_KEY, MONIEPOINT_SECRET_KEY and MONIEPOINT_CONTRACT_CODE.",
    });
  }

  const payload = req.body || {};
  const customerName = String(payload.customerName || "").trim();
  const customerPhone = String(payload.customerPhone || "").trim();
  let customerEmail = String(payload.customerEmail || "").trim();
  const notes = String(payload.notes || "").trim();
  const shippingState = normalizeRegionText(payload.shippingState || "");
  const shippingCity = normalizeRegionText(payload.shippingCity || "");
  const couponCode = String(payload.couponCode || "").trim().toUpperCase();
  const items = Array.isArray(payload.items) ? payload.items : [];

  const customerSession = await getValidatedCustomerSession(req, { touch: false });
  const customerId = customerSession ? Number(customerSession.customerId) : null;
  const sessionEmail = normalizeEmail(customerSession?.email || "");
  if (!customerEmail && sessionEmail) {
    customerEmail = sessionEmail;
  }

  if (!customerName) return res.status(400).json({ error: "customerName is required" });
  if (!customerPhone) return res.status(400).json({ error: "customerPhone is required" });
  if (!customerEmail) return res.status(400).json({ error: "customerEmail is required for Moniepoint" });
  if (!shippingState) return res.status(400).json({ error: "shippingState is required" });
  if (!items.length) return res.status(400).json({ error: "Cart cannot be empty" });

  const normalized = normalizeCartItemsWithVariants(items);
  if (!normalized.valid) {
    return res.status(400).json({ error: normalized.error || "Invalid cart items." });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const catalog = await fetchCatalogForCartItems(client, normalized.items, { lockRows: false });
    if (!catalog.valid) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: catalog.error || "One or more cart items are unavailable." });
    }
    const { productMap, variantMap } = catalog;

    let subtotalKobo = 0;
    const orderItems = [];
    const brandsInCart = new Set();
    for (const item of normalized.items) {
      const product = productMap.get(item.productId);
      if (!product) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: "Invalid product in cart." });
      }
      const variant = item.variantId ? variantMap.get(item.variantId) : null;
      if (item.variantId) {
        if (!variant || !variant.isActive || variant.productId !== product.id) {
          await client.query("ROLLBACK");
          return res.status(400).json({ error: `Variant selected for "${product.name}" is invalid.` });
        }
        if (variant.stockQty < item.qty) {
          await client.query("ROLLBACK");
          return res.status(409).json({
            error: `Insufficient stock for "${product.name}" variant (${variant.label || variant.sku}). Available: ${variant.stockQty}`,
          });
        }
      } else if (product.stockQty < item.qty) {
        await client.query("ROLLBACK");
        return res.status(409).json({
          error: `Insufficient stock for "${product.name}". Available: ${product.stockQty}`,
        });
      }

      const unitPriceKobo =
        variant && variant.priceOverrideKobo !== null ? variant.priceOverrideKobo : product.priceKobo;
      const lineTotalKobo = unitPriceKobo * item.qty;
      subtotalKobo += lineTotalKobo;
      orderItems.push({
        productId: product.id,
        variantId: variant ? variant.id : null,
        variantSku: variant ? variant.sku : null,
        variantLabel: variant ? variant.label : null,
        productName: product.name,
        brand: product.brand,
        unitPriceKobo,
        qty: item.qty,
        lineTotalKobo,
      });
      brandsInCart.add(product.brand);
    }

    let coupon = null;
    let couponDiscountKobo = 0;
    if (couponCode) {
      const validated = await validateCouponForCart(
        client,
        couponCode,
        subtotalKobo,
        Array.from(brandsInCart)
      );
      if (!validated.valid) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: validated.error || "Invalid coupon." });
      }
      coupon = validated.coupon;
      couponDiscountKobo = validated.discountKobo;
    }

    const discountedSubtotalKobo = Math.max(subtotalKobo - couponDiscountKobo, 0);
    const shippingQuote = await computeShippingQuote(client, shippingState, shippingCity, discountedSubtotalKobo);
    const shippingFeeKobo = Number(shippingQuote.shippingFeeKobo || 0);
    const totalKobo = discountedSubtotalKobo + shippingFeeKobo;

    const orderNumber = generateOrderNumber();
    const reference = `SSMON-${Date.now()}-${Math.floor(Math.random() * 1000000)}`;
    const orderResult = await client.query(
      `INSERT INTO orders
        (order_number, customer_id, customer_name, customer_phone, customer_email, notes, shipping_state, shipping_city, subtotal_kobo, shipping_fee_kobo, coupon_code, coupon_discount_kobo, total_kobo, status, payment_channel, moniepoint_reference)
       VALUES
        ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 'pending_payment', 'moniepoint', $14)
       RETURNING id, order_number, subtotal_kobo, shipping_fee_kobo, coupon_discount_kobo, total_kobo, moniepoint_reference`,
      [
        orderNumber,
        customerId,
        customerName,
        customerPhone,
        customerEmail,
        notes,
        shippingState,
        shippingCity || null,
        subtotalKobo,
        shippingFeeKobo,
        coupon ? coupon.code : null,
        couponDiscountKobo,
        totalKobo,
        reference,
      ]
    );
    const order = orderResult.rows[0];

    for (const item of orderItems) {
      await client.query(
        `INSERT INTO order_items
          (order_id, product_id, variant_id, variant_sku, variant_label, product_name, brand, unit_price_kobo, qty, line_total_kobo)
         VALUES
          ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [
          order.id,
          item.productId,
          item.variantId,
          item.variantSku,
          item.variantLabel,
          item.productName,
          item.brand,
          item.unitPriceKobo,
          item.qty,
          item.lineTotalKobo,
        ]
      );
    }

    const redirectUrl =
      process.env.MONIEPOINT_REDIRECT_URL || `${req.protocol}://${req.get("host")}/`;
    const moniepointData = await moniepointRequest(
      "/api/v1/merchant/transactions/init-transaction",
      "POST",
      {
        amount: Number((totalKobo / 100).toFixed(2)),
        customerName,
        customerEmail,
        paymentReference: reference,
        paymentDescription: `Order ${order.order_number}`,
        currencyCode: "NGN",
        contractCode: process.env.MONIEPOINT_CONTRACT_CODE,
        redirectUrl,
        paymentMethods: ["CARD", "ACCOUNT_TRANSFER"],
        metadata: {
          orderNumber: order.order_number,
          customerPhone,
          shippingState,
          shippingCity: shippingCity || null,
        },
      }
    );

    await appendOrderStatusHistory(client, order.id, null, "pending_payment", "Awaiting Moniepoint payment", {
      userId: null,
      username: "system",
    });

    await client.query("COMMIT");

    await writeAuditLog(req, "order.create.pending_payment", "order", order.id, {
      orderNumber: order.order_number,
      subtotalKobo: Number(order.subtotal_kobo),
      shippingFeeKobo: Number(order.shipping_fee_kobo || 0),
      couponDiscountKobo: Number(order.coupon_discount_kobo || 0),
      totalKobo: Number(order.total_kobo || 0),
      reference,
      paymentChannel: "moniepoint",
    });

    return res.status(201).json({
      order: {
        id: Number(order.id),
        orderNumber: order.order_number,
        subtotalKobo: Number(order.subtotal_kobo),
        shippingFeeKobo: Number(order.shipping_fee_kobo || 0),
        couponDiscountKobo: Number(order.coupon_discount_kobo || 0),
        totalKobo: Number(order.total_kobo || 0),
        reference: order.moniepoint_reference,
      },
      payment: {
        reference,
        checkoutUrl: moniepointData.checkoutUrl || moniepointData.checkoutURL || null,
        transactionReference:
          moniepointData.transactionReference || moniepointData.transactionRef || null,
      },
      coupon,
    });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error(error);
    return res
      .status(500)
      .json({ error: error.message || "Failed to initialize Moniepoint payment." });
  } finally {
    client.release();
  }
});

app.post("/api/moniepoint/verify", async (req, res) => {
  if (!isMoniepointConfigured()) {
    return res.status(503).json({
      error:
        "Moniepoint is not configured. Set MONIEPOINT_API_KEY, MONIEPOINT_SECRET_KEY and MONIEPOINT_CONTRACT_CODE.",
    });
  }

  const paymentReference = String((req.body || {}).paymentReference || (req.body || {}).reference || "")
    .trim();
  const transactionReference = String((req.body || {}).transactionReference || "").trim();

  if (!paymentReference && !transactionReference) {
    return res.status(400).json({ error: "paymentReference or transactionReference is required." });
  }

  try {
    let verified = null;
    if (transactionReference) {
      try {
        verified = await moniepointRequest(
          `/api/v2/transactions/${encodeURIComponent(transactionReference)}`,
          "GET"
        );
      } catch (_error) {
        try {
          verified = await moniepointRequest(
            `/api/v2/transactions/${encodeURIComponent(transactionReference)}/details`,
            "GET"
          );
        } catch (_innerError) {
          verified = await moniepointRequest(
            `/api/v2/merchant/transactions/query?transactionReference=${encodeURIComponent(
              transactionReference
            )}`,
            "GET"
          );
        }
      }
    } else {
      verified = await moniepointRequest(
        `/api/v2/merchant/transactions/query?paymentReference=${encodeURIComponent(paymentReference)}`,
        "GET"
      );
    }

    const remoteStatus = String(
      verified?.paymentStatus || verified?.status || verified?.transactionStatus || ""
    ).toUpperCase();
    if (!remoteStatus) {
      return res.status(400).json({ error: "Unable to resolve payment status from Moniepoint." });
    }
    if (!["PAID", "SUCCESSFUL", "COMPLETED"].includes(remoteStatus)) {
      return res.status(400).json({ error: "Payment not successful." });
    }

    const amountNaira = Number(
      verified?.amountPaid || verified?.amount || verified?.paidAmount || 0
    );
    const paidAmountKobo = Number.isFinite(amountNaira) ? Math.round(amountNaira * 100) : null;
    const verifiedReference = String(
      verified?.paymentReference || verified?.reference || verified?.merchantReference || ""
    ).trim();
    if (paymentReference && verifiedReference && paymentReference !== verifiedReference) {
      return res.status(409).json({ error: "Payment reference mismatch from Moniepoint verification." });
    }
    const orderReference = paymentReference || verifiedReference;
    if (!orderReference) {
      return res
        .status(400)
        .json({ error: "Unable to resolve Moniepoint payment reference for this order." });
    }

    const finalized = await finalizePaidOrderByReference(orderReference, {
      paidAmountKobo,
      actor: { userId: null, username: "system" },
      note: "Moniepoint payment verified",
      referenceColumn: "moniepoint_reference",
      paymentChannel: "moniepoint",
    });

    if (finalized.notFound) {
      return res.status(404).json({ error: "No pending order found for this payment reference." });
    }
    if (finalized.invalidAmount) {
      return res.status(409).json({ error: "Paid amount is less than order total." });
    }
    if (finalized.invalidOrder || finalized.stockConflict) {
      return res.status(409).json({ error: finalized.error || "Order cannot be finalized." });
    }

    await writeAuditLog(req, "order.payment.verified", "order", finalized.order.id, {
      reference: orderReference,
      transactionReference: transactionReference || verified?.transactionReference || null,
      totalKobo: finalized.order.totalKobo,
      channel: "moniepoint",
      alreadyPaid: Boolean(finalized.alreadyPaid),
    });

    return res.json({
      verified: true,
      alreadyPaid: Boolean(finalized.alreadyPaid),
      order: {
        ...finalized.order,
        reference: orderReference,
        transactionReference: transactionReference || verified?.transactionReference || null,
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: error.message || "Failed to verify Moniepoint payment." });
  }
});

app.post("/api/moniepoint/webhook", async (req, res) => {
  const secret = getMoniepointWebhookSecret();
  if (!secret) {
    return res.status(503).json({ error: "Moniepoint webhook secret is not configured." });
  }

  try {
    if (!verifyMoniepointWebhookSignature(req)) {
      return res.status(401).json({ error: "Invalid Moniepoint webhook signature." });
    }

    const payload = req.body || {};
    const eventData = payload.eventData || payload.responseBody || payload.data || payload;
    const eventType = String(payload.eventType || payload.event || eventData.eventType || "unknown").trim();
    const reference = String(
      eventData.paymentReference ||
        eventData.reference ||
        eventData.merchantReference ||
        eventData.payment_reference ||
        ""
    ).trim();
    const transactionReference = String(
      eventData.transactionReference || eventData.transactionRef || eventData.transaction_reference || ""
    ).trim();
    const eventId =
      String(
        payload.eventId ||
          payload.id ||
          transactionReference ||
          (reference ? `${eventType}:${reference}` : "")
      ).trim() ||
      crypto.createHash("sha256").update(getRawRequestBody(req)).digest("hex");

    const eventInsert = await pool.query(
      `INSERT INTO moniepoint_events (event_id, event_type, reference, payload, processed, processed_at)
       VALUES ($1, $2, $3, $4::jsonb, FALSE, NULL)
       ON CONFLICT (event_id) DO NOTHING
       RETURNING id`,
      [eventId, eventType || "unknown", reference || null, JSON.stringify(payload || {})]
    );

    if (!eventInsert.rowCount) {
      return res.json({ received: true, duplicate: true });
    }

    const remoteStatus = String(
      eventData.paymentStatus ||
        eventData.status ||
        eventData.transactionStatus ||
        payload.paymentStatus ||
        ""
    ).toUpperCase();
    const successStatus = new Set(["PAID", "SUCCESSFUL", "COMPLETED"]);
    let processed = false;
    let processNote = "ignored";

    if (reference && successStatus.has(remoteStatus)) {
      const amountNaira = Number(
        eventData.amountPaid || eventData.amount || eventData.paidAmount || payload.amount || 0
      );
      const paidAmountKobo = Number.isFinite(amountNaira) ? Math.round(amountNaira * 100) : null;
      const finalized = await finalizePaidOrderByReference(reference, {
        paidAmountKobo,
        actor: { userId: null, username: "moniepoint-webhook" },
        note: "Moniepoint webhook payment confirmation",
        referenceColumn: "moniepoint_reference",
        paymentChannel: "moniepoint",
      });
      processed = Boolean(finalized.paid || finalized.alreadyPaid);
      processNote = finalized.stockConflict
        ? "stock_conflict"
        : finalized.invalidAmount
          ? "invalid_amount"
          : finalized.notFound
            ? "order_not_found"
            : processed
              ? "paid"
              : "ignored";
    }

    await pool.query(
      `UPDATE moniepoint_events
       SET processed = $1, processed_at = NOW()
       WHERE id = $2`,
      [processed, Number(eventInsert.rows[0].id)]
    );

    return res.json({
      received: true,
      processed,
      note: processNote,
      reference: reference || null,
      transactionReference: transactionReference || null,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to process Moniepoint webhook." });
  }
});

app.post("/api/paystack/webhook", async (req, res) => {
  if (!process.env.PAYSTACK_SECRET_KEY) {
    return res.status(503).json({ error: "Paystack secret is not configured." });
  }

  try {
    const signature = String(req.headers["x-paystack-signature"] || "");
    const expected = crypto
      .createHmac("sha512", process.env.PAYSTACK_SECRET_KEY)
      .update(getRawRequestBody(req))
      .digest("hex");

    if (!signature || !safeEqualText(signature, expected)) {
      return res.status(401).json({ error: "Invalid Paystack webhook signature." });
    }

    const eventBody = req.body || {};
    const eventType = String(eventBody.event || "");
    const eventData = eventBody.data || {};
    const reference = String(eventData.reference || "").trim() || null;
    const eventId = eventData.id ? String(eventData.id) : null;

    const eventInsert = await pool.query(
      `INSERT INTO paystack_events (event_id, event_type, reference, payload, processed, processed_at)
       VALUES ($1, $2, $3, $4::jsonb, FALSE, NULL)
       ON CONFLICT (event_id) DO NOTHING
       RETURNING id`,
      [eventId, eventType || "unknown", reference, JSON.stringify(eventBody || {})]
    );

    if (!eventInsert.rowCount && eventId) {
      return res.json({ received: true, duplicate: true });
    }

    let processed = false;
    let processNote = "ignored";
    if (eventType === "charge.success" && reference) {
      const finalized = await finalizePaidOrderByReference(reference, {
        paidAmountKobo: Number(eventData.amount || 0),
        actor: { userId: null, username: "paystack-webhook" },
        note: "Paystack webhook charge.success",
      });
      processed = Boolean(finalized.paid || finalized.alreadyPaid);
      processNote = finalized.stockConflict
        ? "stock_conflict"
        : finalized.invalidAmount
          ? "invalid_amount"
          : finalized.notFound
            ? "order_not_found"
            : processed
              ? "paid"
              : "ignored";
    }

    if (eventInsert.rowCount) {
      await pool.query(
        `UPDATE paystack_events
         SET processed = $1, processed_at = NOW()
         WHERE id = $2`,
        [processed, Number(eventInsert.rows[0].id)]
      );
    }

    return res.json({ received: true, processed, note: processNote });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to process Paystack webhook." });
  }
});

app.post("/api/checkout", async (req, res) => {
  const payload = req.body || {};
  const customerName = String(payload.customerName || "").trim();
  const customerPhone = String(payload.customerPhone || "").trim();
  const customerEmailRaw = payload.customerEmail;
  let customerEmail =
    customerEmailRaw === undefined || customerEmailRaw === null || customerEmailRaw === ""
      ? null
      : String(customerEmailRaw).trim();
  const notes = String(payload.notes || "").trim();
  const shippingState = normalizeRegionText(payload.shippingState || "");
  const shippingCity = normalizeRegionText(payload.shippingCity || "");
  const couponCode = String(payload.couponCode || "").trim().toUpperCase();
  const paymentMethod = String(payload.paymentMethod || "manual")
    .trim()
    .toLowerCase();
  const checkoutMethod = paymentMethod === "bank_transfer" ? "bank_transfer" : "manual";
  const initialStatus = checkoutMethod === "bank_transfer" ? "pending_payment" : "paid";
  const paidAt = checkoutMethod === "bank_transfer" ? null : new Date();
  const items = Array.isArray(payload.items) ? payload.items : [];

  const customerSession = await getValidatedCustomerSession(req, { touch: false });
  const customerId = customerSession ? Number(customerSession.customerId) : null;
  const sessionEmail = normalizeEmail(customerSession?.email || "");
  if (!customerEmail && sessionEmail) {
    customerEmail = sessionEmail;
  }

  if (!customerName) {
    return res.status(400).json({ error: "customerName is required" });
  }
  if (!customerPhone) {
    return res.status(400).json({ error: "customerPhone is required" });
  }
  if (!shippingState) {
    return res.status(400).json({ error: "shippingState is required" });
  }
  if (!items.length) {
    return res.status(400).json({ error: "Cart cannot be empty" });
  }

  const normalized = normalizeCartItemsWithVariants(items);
  if (!normalized.valid) {
    return res.status(400).json({ error: normalized.error || "Invalid cart items." });
  }
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const catalog = await fetchCatalogForCartItems(client, normalized.items, { lockRows: true });
    if (!catalog.valid) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: catalog.error || "One or more cart items are unavailable." });
    }
    const { productMap, variantMap } = catalog;

    let subtotalKobo = 0;
    const orderItems = [];
    const brandsInCart = new Set();

    for (const item of normalized.items) {
      const product = productMap.get(item.productId);
      if (!product) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: "Invalid product in cart." });
      }
      const variant = item.variantId ? variantMap.get(item.variantId) : null;
      if (item.variantId) {
        if (!variant || !variant.isActive || variant.productId !== product.id) {
          await client.query("ROLLBACK");
          return res.status(400).json({ error: `Variant selected for "${product.name}" is invalid.` });
        }
        if (variant.stockQty < item.qty) {
          await client.query("ROLLBACK");
          return res.status(409).json({
            error: `Insufficient stock for "${product.name}" variant (${variant.label || variant.sku}). Available: ${variant.stockQty}`,
          });
        }
      } else if (product.stockQty < item.qty) {
        await client.query("ROLLBACK");
        return res.status(409).json({
          error: `Insufficient stock for "${product.name}". Available: ${product.stockQty}`,
        });
      }

      const unitPriceKobo =
        variant && variant.priceOverrideKobo !== null ? variant.priceOverrideKobo : product.priceKobo;
      const lineTotalKobo = unitPriceKobo * item.qty;
      subtotalKobo += lineTotalKobo;

      orderItems.push({
        productId: product.id,
        variantId: variant ? variant.id : null,
        variantSku: variant ? variant.sku : null,
        variantLabel: variant ? variant.label : null,
        productName: product.name,
        brand: product.brand,
        unitPriceKobo,
        qty: item.qty,
        lineTotalKobo,
      });
      brandsInCart.add(product.brand);
    }

    let coupon = null;
    let couponDiscountKobo = 0;
    if (couponCode) {
      const validated = await validateCouponForCart(
        client,
        couponCode,
        subtotalKobo,
        Array.from(brandsInCart)
      );
      if (!validated.valid) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: validated.error || "Invalid coupon." });
      }
      coupon = validated.coupon;
      couponDiscountKobo = validated.discountKobo;
    }
    const discountedSubtotalKobo = Math.max(subtotalKobo - couponDiscountKobo, 0);
    const shippingQuote = await computeShippingQuote(client, shippingState, shippingCity, discountedSubtotalKobo);
    const shippingFeeKobo = Number(shippingQuote.shippingFeeKobo || 0);
    const totalKobo = discountedSubtotalKobo + shippingFeeKobo;

    let orderNumber = generateOrderNumber();
    let attempts = 0;
    while (attempts < 3) {
      const exists = await client.query("SELECT 1 FROM orders WHERE order_number = $1", [orderNumber]);
      if (!exists.rowCount) {
        break;
      }
      orderNumber = generateOrderNumber();
      attempts += 1;
    }

    const orderResult = await client.query(
      `INSERT INTO orders
        (order_number, customer_id, customer_name, customer_phone, customer_email, notes, shipping_state, shipping_city, subtotal_kobo, shipping_fee_kobo, coupon_code, coupon_discount_kobo, total_kobo, status, payment_channel, paid_at)
       VALUES
        ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
       RETURNING id, order_number, customer_name, customer_phone, customer_email, notes, shipping_state, shipping_city, subtotal_kobo, shipping_fee_kobo, coupon_code, coupon_discount_kobo, total_kobo, status, payment_channel, created_at`,
      [
        orderNumber,
        customerId,
        customerName,
        customerPhone,
        customerEmail,
        notes,
        shippingState,
        shippingCity || null,
        subtotalKobo,
        shippingFeeKobo,
        coupon ? coupon.code : null,
        couponDiscountKobo,
        totalKobo,
        initialStatus,
        checkoutMethod,
        paidAt ? paidAt.toISOString() : null,
      ]
    );
    const order = orderResult.rows[0];

    for (const item of orderItems) {
      await client.query(
        `INSERT INTO order_items
          (order_id, product_id, variant_id, variant_sku, variant_label, product_name, brand, unit_price_kobo, qty, line_total_kobo)
         VALUES
          ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [
          order.id,
          item.productId,
          item.variantId,
          item.variantSku,
          item.variantLabel,
          item.productName,
          item.brand,
          item.unitPriceKobo,
          item.qty,
          item.lineTotalKobo,
        ]
      );

      if (item.variantId) {
        await client.query(
          `UPDATE product_variants
           SET stock_qty = stock_qty - $1, updated_at = NOW()
           WHERE id = $2`,
          [item.qty, item.variantId]
        );
      } else {
        await client.query(
          `UPDATE products
           SET stock_qty = stock_qty - $1, updated_at = NOW()
           WHERE id = $2`,
          [item.qty, item.productId]
        );
      }

      await insertStockMovement(client, {
        productId: item.productId,
        variantId: item.variantId,
        movementType: initialStatus === "paid" ? "sale" : "manual",
        deltaQty: -item.qty,
        reason:
          initialStatus === "paid"
            ? "Manual checkout completed"
            : "Bank transfer checkout created; stock reserved",
        referenceType: "order",
        referenceId: order.order_number,
        adminUserId: null,
        adminUsername: "system",
      });
    }

    if (coupon && initialStatus === "paid") {
      await client.query(`UPDATE coupons SET used_count = used_count + 1, updated_at = NOW() WHERE id = $1`, [
        coupon.id,
      ]);
      await client.query(
        `INSERT INTO coupon_redemptions (coupon_id, order_id, code, discount_kobo)
         VALUES ($1, $2, $3, $4)`,
        [coupon.id, order.id, coupon.code, couponDiscountKobo]
      );
    }

    await appendOrderStatusHistory(
      client,
      order.id,
      null,
      initialStatus,
      checkoutMethod === "bank_transfer"
        ? "Bank transfer order created, awaiting payment confirmation"
        : "Manual checkout completed",
      {
      userId: null,
      username: "system",
      }
    );

    await client.query("COMMIT");

    await writeAuditLog(
      req,
      initialStatus === "paid" ? "order.create.paid" : "order.create.pending_payment",
      "order",
      order.id,
      {
      orderNumber: order.order_number,
      subtotalKobo: Number(order.subtotal_kobo),
      shippingFeeKobo: Number(order.shipping_fee_kobo || 0),
      couponDiscountKobo: Number(order.coupon_discount_kobo || 0),
      totalKobo: Number(order.total_kobo || order.subtotal_kobo),
      paymentChannel: checkoutMethod,
      shippingState: order.shipping_state || shippingState,
      shippingCity: order.shipping_city || shippingCity || null,
      }
    );

    return res.status(201).json({
      order: {
        id: Number(order.id),
        orderNumber: order.order_number,
        customerName: order.customer_name,
        customerPhone: order.customer_phone,
        customerEmail: order.customer_email,
        notes: order.notes,
        shippingState: order.shipping_state || shippingState,
        shippingCity: order.shipping_city || shippingCity || null,
        subtotalKobo: Number(order.subtotal_kobo),
        shippingFeeKobo: Number(order.shipping_fee_kobo || 0),
        couponCode: order.coupon_code || null,
        couponDiscountKobo: Number(order.coupon_discount_kobo || 0),
        totalKobo: Number(order.total_kobo || order.subtotal_kobo),
        status: order.status,
        paymentChannel: order.payment_channel || checkoutMethod,
        createdAt: order.created_at,
      },
      items: orderItems,
      coupon,
      payment: {
        method: checkoutMethod,
        requiresConfirmation: initialStatus !== "paid",
        bankName: String(process.env.BANK_NAME || "").trim(),
        bankAccountName: String(process.env.BANK_ACCOUNT_NAME || "").trim(),
        bankAccountNumber: String(process.env.BANK_ACCOUNT_NUMBER || "").trim(),
        instructions:
          String(
            process.env.BANK_TRANSFER_INSTRUCTIONS ||
              "Complete transfer, then send your order number on WhatsApp for confirmation."
          ).trim(),
      },
    });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error(error);
    return sendPgError(res, error, "Checkout failed");
  } finally {
    client.release();
  }
});

app.post("/api/track/order", async (req, res) => {
  try {
    const payload = req.body || {};
    const orderNumber = String(payload.orderNumber || "").trim();
    const phoneInput = normalizeWhatsAppNumber(payload.customerPhone || "");
    if (!orderNumber || !phoneInput) {
      return res.status(400).json({ error: "orderNumber and customerPhone are required." });
    }

    const [orderResult, itemsResult, historyResult] = await Promise.all([
      pool.query(
        `SELECT
          id, order_number, customer_name, customer_phone, customer_email, notes,
          shipping_state, shipping_city, subtotal_kobo, shipping_fee_kobo, coupon_code, coupon_discount_kobo,
          total_kobo, status, payment_channel, paystack_reference, moniepoint_reference, paid_at,
          payment_proof_url, payment_proof_note, payment_proof_uploaded_at, payment_proof_status,
          payment_review_note, payment_reviewed_at, payment_reviewed_by,
          payment_verified_at, payment_verified_by,
          reconciliation_status, reconciliation_note, reconciled_at, reconciled_by,
          created_at, updated_at
         FROM orders
         WHERE UPPER(order_number) = UPPER($1)
         LIMIT 1`,
        [orderNumber]
      ),
      pool.query(
        `SELECT
          o.id as order_id,
          oi.id, oi.product_id, oi.variant_id, oi.variant_sku, oi.variant_label,
          oi.product_name, oi.brand, oi.unit_price_kobo, oi.qty, oi.line_total_kobo
         FROM orders o
         LEFT JOIN order_items oi ON oi.order_id = o.id
         WHERE UPPER(o.order_number) = UPPER($1)
         ORDER BY oi.id ASC`,
        [orderNumber]
      ),
      pool.query(
        `SELECT
          h.id, h.previous_status, h.new_status, h.note, h.changed_by_username, h.created_at
         FROM order_status_history h
         INNER JOIN orders o ON o.id = h.order_id
         WHERE UPPER(o.order_number) = UPPER($1)
         ORDER BY h.created_at ASC`,
        [orderNumber]
      ),
    ]);

    if (!orderResult.rowCount) {
      return res.status(404).json({ error: "Order not found." });
    }

    const order = orderResult.rows[0];
    const savedPhone = normalizeWhatsAppNumber(order.customer_phone || "");
    if (!savedPhone || savedPhone !== phoneInput) {
      return res.status(404).json({ error: "Order not found." });
    }

    const paymentChannel = order.payment_channel || "manual";
    const canUploadProof =
      order.status === "pending_payment" && ["bank_transfer", "manual"].includes(paymentChannel);

    return res.json({
      order: {
        id: Number(order.id),
        orderNumber: order.order_number,
        customerName: order.customer_name,
        customerPhone: order.customer_phone,
        customerEmail: order.customer_email,
        notes: order.notes,
        shippingState: order.shipping_state || "",
        shippingCity: order.shipping_city || null,
        subtotalKobo: Number(order.subtotal_kobo),
        shippingFeeKobo: Number(order.shipping_fee_kobo || 0),
        couponCode: order.coupon_code || null,
        couponDiscountKobo: Number(order.coupon_discount_kobo || 0),
        totalKobo: Number(order.total_kobo || order.subtotal_kobo),
        status: order.status,
        paymentChannel,
        reference: order.paystack_reference || order.moniepoint_reference || null,
        paidAt: order.paid_at,
        paymentProofUrl: order.payment_proof_url || null,
        paymentProofNote: order.payment_proof_note || "",
        paymentProofUploadedAt: order.payment_proof_uploaded_at,
        paymentProofStatus: order.payment_proof_status || "none",
        paymentReviewNote: order.payment_review_note || "",
        paymentReviewedAt: order.payment_reviewed_at,
        paymentReviewedBy: order.payment_reviewed_by || null,
        paymentVerifiedAt: order.payment_verified_at,
        paymentVerifiedBy: order.payment_verified_by || null,
        reconciliationStatus: order.reconciliation_status || "unreconciled",
        reconciliationNote: order.reconciliation_note || "",
        reconciledAt: order.reconciled_at,
        reconciledBy: order.reconciled_by || null,
        canUploadProof,
        createdAt: order.created_at,
        updatedAt: order.updated_at,
      },
      items: itemsResult.rows
        .filter((row) => row.id !== null)
        .map((row) => ({
          id: Number(row.id),
          productId: row.product_id === null ? null : Number(row.product_id),
          variantId: row.variant_id === null ? null : Number(row.variant_id),
          variantSku: row.variant_sku || null,
          variantLabel: row.variant_label || null,
          productName: row.product_name,
          brand: row.brand,
          unitPriceKobo: Number(row.unit_price_kobo),
          qty: Number(row.qty),
          lineTotalKobo: Number(row.line_total_kobo),
        })),
      history: historyResult.rows.map((row) => ({
        id: Number(row.id),
        previousStatus: row.previous_status || null,
        newStatus: row.new_status,
        note: row.note || "",
        changedByUsername: row.changed_by_username || "system",
        createdAt: row.created_at,
      })),
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to track order." });
  }
});

app.post("/api/track/order/payment-proof", upload.single("proof"), async (req, res) => {
  try {
    const payload = req.body || {};
    const orderNumber = String(payload.orderNumber || "").trim();
    const phoneInput = normalizeWhatsAppNumber(payload.customerPhone || "");
    const note = String(payload.note || "").trim();
    const proofUrlRaw = String(payload.proofUrl || "").trim();

    if (!orderNumber || !phoneInput) {
      return res.status(400).json({ error: "orderNumber and customerPhone are required." });
    }

    const orderResult = await pool.query(
      `SELECT
        id, order_number, customer_phone, status, payment_channel
       FROM orders
       WHERE UPPER(order_number) = UPPER($1)
       LIMIT 1`,
      [orderNumber]
    );
    if (!orderResult.rowCount) {
      return res.status(404).json({ error: "Order not found." });
    }

    const order = orderResult.rows[0];
    const savedPhone = normalizeWhatsAppNumber(order.customer_phone || "");
    if (!savedPhone || savedPhone !== phoneInput) {
      return res.status(404).json({ error: "Order not found." });
    }

    if (order.status !== "pending_payment") {
      return res.status(400).json({ error: "Payment proof can only be uploaded for pending orders." });
    }

    let proofUrl = "";
    if (req.file) {
      if (!isCloudinaryConfigured()) {
        return res.status(503).json({
          error:
            "Image upload is unavailable right now. Cloudinary is not configured; provide proofUrl instead.",
        });
      }
      if (!req.file.mimetype || !req.file.mimetype.startsWith("image/")) {
        return res.status(400).json({ error: "Uploaded proof must be an image file." });
      }
      const dataUri = `data:${req.file.mimetype};base64,${req.file.buffer.toString("base64")}`;
      const folder = String(process.env.CLOUDINARY_FOLDER || "sholly-store").trim();
      const uploadResult = await cloudinary.uploader.upload(dataUri, {
        folder: folder || "sholly-store",
        resource_type: "image",
        use_filename: true,
        unique_filename: true,
        overwrite: false,
      });
      proofUrl = uploadResult.secure_url;
    } else if (proofUrlRaw) {
      proofUrl = proofUrlRaw;
    }

    if (!proofUrl) {
      return res.status(400).json({ error: "Upload a proof image or provide proofUrl." });
    }

    const updatedResult = await pool.query(
      `UPDATE orders
       SET payment_proof_url = $1,
           payment_proof_note = $2,
           payment_proof_uploaded_at = NOW(),
           payment_proof_status = 'pending_review',
           payment_review_note = '',
           payment_reviewed_at = NULL,
           payment_reviewed_by = NULL,
           updated_at = NOW()
       WHERE id = $3
       RETURNING
        id, order_number, status, payment_channel,
        payment_proof_url, payment_proof_note, payment_proof_uploaded_at,
        payment_proof_status, payment_review_note, payment_reviewed_at, payment_reviewed_by`,
      [proofUrl, note, Number(order.id)]
    );
    const updated = updatedResult.rows[0];

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await appendOrderStatusHistory(
        client,
        Number(order.id),
        updated.status,
        updated.status,
        "Payment proof uploaded by customer",
        { userId: null, username: "customer" }
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }

    return res.status(201).json({
      order: {
        id: Number(updated.id),
        orderNumber: updated.order_number,
        status: updated.status,
        paymentChannel: updated.payment_channel || null,
        paymentProofUrl: updated.payment_proof_url || null,
        paymentProofNote: updated.payment_proof_note || "",
        paymentProofUploadedAt: updated.payment_proof_uploaded_at,
        paymentProofStatus: updated.payment_proof_status || "pending_review",
        paymentReviewNote: updated.payment_review_note || "",
        paymentReviewedAt: updated.payment_reviewed_at,
        paymentReviewedBy: updated.payment_reviewed_by || null,
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to upload payment proof." });
  }
});

app.get("/api/orders", requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(Math.max(parseIntOrUndefined(req.query.limit) || 25, 1), 100);
    const status = req.query.status ? String(req.query.status) : "";
    const values = [];
    let whereSql = "";
    if (status) {
      values.push(status);
      whereSql = `WHERE o.status = $${values.length}`;
    }
    values.push(limit);

    const ordersResult = await pool.query(
      `SELECT
        o.id,
        o.order_number,
        o.customer_name,
        o.customer_phone,
        o.customer_email,
        o.notes,
        o.shipping_state,
        o.shipping_city,
        o.subtotal_kobo,
        o.shipping_fee_kobo,
        o.coupon_code,
        o.coupon_discount_kobo,
        o.total_kobo,
        o.status,
        o.payment_channel,
        o.paystack_reference,
        o.moniepoint_reference,
        o.paid_at,
        o.payment_proof_url,
        o.payment_proof_note,
        o.payment_proof_uploaded_at,
        o.payment_proof_status,
        o.payment_review_note,
        o.payment_reviewed_at,
        o.payment_reviewed_by,
        o.payment_verified_at,
        o.payment_verified_by,
        o.reconciliation_status,
        o.reconciliation_note,
        o.reconciled_at,
        o.reconciled_by,
        o.payment_reminder_count,
        o.last_payment_reminder_at,
        o.created_at,
        COALESCE(SUM(oi.qty), 0)::int AS total_items
       FROM orders o
       LEFT JOIN order_items oi ON oi.order_id = o.id
       ${whereSql}
       GROUP BY o.id
       ORDER BY o.created_at DESC
       LIMIT $${values.length}`,
      values
    );
    res.json({
      orders: ordersResult.rows.map((row) => ({
        id: Number(row.id),
        orderNumber: row.order_number,
        customerName: row.customer_name,
        customerPhone: row.customer_phone,
        customerEmail: row.customer_email,
        notes: row.notes,
        shippingState: row.shipping_state || "",
        shippingCity: row.shipping_city || null,
        subtotalKobo: Number(row.subtotal_kobo),
        shippingFeeKobo: Number(row.shipping_fee_kobo || 0),
        couponCode: row.coupon_code || null,
        couponDiscountKobo: Number(row.coupon_discount_kobo || 0),
        totalKobo: Number(row.total_kobo || row.subtotal_kobo),
        status: row.status,
        paymentChannel: row.payment_channel || null,
        reference: row.paystack_reference || row.moniepoint_reference || null,
        paidAt: row.paid_at,
        paymentProofUrl: row.payment_proof_url || null,
        paymentProofNote: row.payment_proof_note || "",
        paymentProofUploadedAt: row.payment_proof_uploaded_at,
        paymentProofStatus: row.payment_proof_status || "none",
        paymentReviewNote: row.payment_review_note || "",
        paymentReviewedAt: row.payment_reviewed_at,
        paymentReviewedBy: row.payment_reviewed_by || null,
        paymentVerifiedAt: row.payment_verified_at,
        paymentVerifiedBy: row.payment_verified_by || null,
        reconciliationStatus: row.reconciliation_status || "unreconciled",
        reconciliationNote: row.reconciliation_note || "",
        reconciledAt: row.reconciled_at,
        reconciledBy: row.reconciled_by || null,
        paymentReminderCount: Number(row.payment_reminder_count || 0),
        lastPaymentReminderAt: row.last_payment_reminder_at,
        createdAt: row.created_at,
        totalItems: Number(row.total_items),
      })),
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to fetch orders" });
  }
});

app.get("/api/orders/:id", requireAdmin, async (req, res) => {
  try {
    const id = parseIntOrUndefined(req.params.id);
    if (!id) return res.status(400).json({ error: "Invalid order id." });

    const [orderResult, itemsResult, historyResult] = await Promise.all([
      pool.query(
        `SELECT
          id, order_number, customer_name, customer_phone, customer_email, notes,
          shipping_state, shipping_city, subtotal_kobo, shipping_fee_kobo, coupon_code, coupon_discount_kobo, total_kobo, status,
          payment_channel, paystack_reference, moniepoint_reference, paid_at,
          payment_proof_url, payment_proof_note, payment_proof_uploaded_at,
          payment_proof_status, payment_review_note, payment_reviewed_at, payment_reviewed_by,
          payment_verified_at, payment_verified_by,
          reconciliation_status, reconciliation_note, reconciled_at, reconciled_by,
          payment_reminder_count, last_payment_reminder_at,
          created_at, updated_at
         FROM orders
         WHERE id = $1`,
        [id]
      ),
      pool.query(
        `SELECT
          id, product_id, variant_id, variant_sku, variant_label,
          product_name, brand, unit_price_kobo, qty, line_total_kobo, created_at
         FROM order_items
         WHERE order_id = $1
         ORDER BY id ASC`,
        [id]
      ),
      pool.query(
        `SELECT
          id, previous_status, new_status, note, changed_by_user_id, changed_by_username, created_at
         FROM order_status_history
         WHERE order_id = $1
         ORDER BY created_at ASC`,
        [id]
      ),
    ]);

    if (!orderResult.rowCount) {
      return res.status(404).json({ error: "Order not found." });
    }

    const row = orderResult.rows[0];
    return res.json({
      order: {
        id: Number(row.id),
        orderNumber: row.order_number,
        customerName: row.customer_name,
        customerPhone: row.customer_phone,
        customerEmail: row.customer_email,
        notes: row.notes,
        shippingState: row.shipping_state || "",
        shippingCity: row.shipping_city || null,
        subtotalKobo: Number(row.subtotal_kobo),
        shippingFeeKobo: Number(row.shipping_fee_kobo || 0),
        couponCode: row.coupon_code || null,
        couponDiscountKobo: Number(row.coupon_discount_kobo || 0),
        totalKobo: Number(row.total_kobo || row.subtotal_kobo),
        status: row.status,
        paymentChannel: row.payment_channel || null,
        reference: row.paystack_reference || row.moniepoint_reference || null,
        paidAt: row.paid_at,
        paymentProofUrl: row.payment_proof_url || null,
        paymentProofNote: row.payment_proof_note || "",
        paymentProofUploadedAt: row.payment_proof_uploaded_at,
        paymentProofStatus: row.payment_proof_status || "none",
        paymentReviewNote: row.payment_review_note || "",
        paymentReviewedAt: row.payment_reviewed_at,
        paymentReviewedBy: row.payment_reviewed_by || null,
        paymentVerifiedAt: row.payment_verified_at,
        paymentVerifiedBy: row.payment_verified_by || null,
        reconciliationStatus: row.reconciliation_status || "unreconciled",
        reconciliationNote: row.reconciliation_note || "",
        reconciledAt: row.reconciled_at,
        reconciledBy: row.reconciled_by || null,
        paymentReminderCount: Number(row.payment_reminder_count || 0),
        lastPaymentReminderAt: row.last_payment_reminder_at,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      },
      items: itemsResult.rows.map((item) => ({
        id: Number(item.id),
        productId: item.product_id === null ? null : Number(item.product_id),
        variantId: item.variant_id === null ? null : Number(item.variant_id),
        variantSku: item.variant_sku || null,
        variantLabel: item.variant_label || null,
        productName: item.product_name,
        brand: item.brand,
        unitPriceKobo: Number(item.unit_price_kobo),
        qty: Number(item.qty),
        lineTotalKobo: Number(item.line_total_kobo),
        createdAt: item.created_at,
      })),
      history: historyResult.rows.map((item) => ({
        id: Number(item.id),
        previousStatus: item.previous_status || null,
        newStatus: item.new_status,
        note: item.note || "",
        changedByUserId: item.changed_by_user_id === null ? null : Number(item.changed_by_user_id),
        changedByUsername: item.changed_by_username || "system",
        createdAt: item.created_at,
      })),
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to fetch order details." });
  }
});

app.post("/api/admin/orders/:id/payment-reminder", requireAdmin, requireRole("owner", "manager"), async (req, res) => {
  try {
    const id = parseIntOrUndefined(req.params.id);
    if (!id) return res.status(400).json({ error: "Invalid order id." });

    const orderResult = await pool.query(
      `SELECT
        id, order_number, customer_name, customer_phone, total_kobo, status, payment_channel
       FROM orders
       WHERE id = $1
       LIMIT 1`,
      [id]
    );
    if (!orderResult.rowCount) {
      return res.status(404).json({ error: "Order not found." });
    }

    const order = orderResult.rows[0];
    if (order.status !== "pending_payment") {
      return res.status(400).json({ error: "Order is not pending payment." });
    }

    const phone = normalizeWhatsAppNumber(order.customer_phone || "");
    if (!phone) {
      return res.status(400).json({ error: "Order has no valid customer phone number." });
    }

    const paymentChannel = String(order.payment_channel || "manual");
    const lines = [
      `Hello ${order.customer_name || "Customer"},`,
      `This is a reminder for your order ${order.order_number}.`,
      `Amount due: NGN ${(Number(order.total_kobo || 0) / 100).toFixed(2)}.`,
    ];

    if (paymentChannel === "bank_transfer" || paymentChannel === "manual") {
      const bankName = String(process.env.BANK_NAME || "").trim();
      const bankAccountName = String(process.env.BANK_ACCOUNT_NAME || "").trim();
      const bankAccountNumber = String(process.env.BANK_ACCOUNT_NUMBER || "").trim();
      if (bankName || bankAccountName || bankAccountNumber) {
        lines.push(`Bank: ${bankName || "-"}`);
        lines.push(`Account Name: ${bankAccountName || "-"}`);
        lines.push(`Account Number: ${bankAccountNumber || "-"}`);
      }
      lines.push("After payment, please share your payment proof on the order tracking page.");
    } else {
      lines.push("Please complete payment via the checkout link you received.");
    }

    const message = lines.join("\n");
    const whatsappUrl = `https://wa.me/${phone}?text=${encodeURIComponent(message)}`;

    const reminderUpdate = await pool.query(
      `UPDATE orders
       SET payment_reminder_count = payment_reminder_count + 1,
           last_payment_reminder_at = NOW(),
           updated_at = NOW()
       WHERE id = $1
       RETURNING payment_reminder_count, last_payment_reminder_at`,
      [id]
    );

    await pool.query(
      `INSERT INTO order_payment_reminders
        (order_id, reminder_channel, message, sent_by_user_id, sent_by_username)
       VALUES
        ($1, $2, $3, $4, $5)`,
      [
        id,
        "whatsapp",
        message,
        req.admin?.userId || null,
        req.admin?.username || "system",
      ]
    );

    await writeAuditLog(req, "order.payment_reminder.sent", "order", id, {
      orderNumber: order.order_number,
      paymentChannel,
      phone,
    });

    return res.json({
      orderId: Number(order.id),
      orderNumber: order.order_number,
      phone,
      message,
      whatsappUrl,
      reminderCount: Number(reminderUpdate.rows[0]?.payment_reminder_count || 0),
      lastReminderAt: reminderUpdate.rows[0]?.last_payment_reminder_at || null,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to create payment reminder." });
  }
});

app.get("/api/admin/orders/payment-review", requireAdmin, requireRole("owner", "manager"), async (req, res) => {
  try {
    const limit = Math.min(Math.max(parseIntOrUndefined(req.query.limit) || 100, 1), 300);
    const paymentProofStatus = String(req.query.paymentProofStatus || "").trim().toLowerCase();
    const reconciliationStatus = String(req.query.reconciliationStatus || "").trim().toLowerCase();
    const validProofStatuses = new Set(["none", "pending_review", "approved", "rejected"]);
    const validReconciliationStatuses = new Set(["unreconciled", "reconciled", "disputed"]);

    const where = [];
    const values = [];
    if (paymentProofStatus) {
      if (!validProofStatuses.has(paymentProofStatus)) {
        return res.status(400).json({ error: "Invalid paymentProofStatus value." });
      }
      values.push(paymentProofStatus);
      where.push(`payment_proof_status = $${values.length}`);
    }
    if (reconciliationStatus) {
      if (!validReconciliationStatuses.has(reconciliationStatus)) {
        return res.status(400).json({ error: "Invalid reconciliationStatus value." });
      }
      values.push(reconciliationStatus);
      where.push(`reconciliation_status = $${values.length}`);
    }
    values.push(limit);

    const result = await pool.query(
      `SELECT
        id, order_number, customer_name, customer_phone, customer_email, total_kobo, status, payment_channel,
        payment_proof_url, payment_proof_note, payment_proof_uploaded_at, payment_proof_status,
        payment_review_note, payment_reviewed_at, payment_reviewed_by,
        payment_verified_at, payment_verified_by,
        reconciliation_status, reconciliation_note, reconciled_at, reconciled_by,
        payment_reminder_count, last_payment_reminder_at,
        created_at, updated_at
       FROM orders
       ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
       ORDER BY
        CASE WHEN payment_proof_status = 'pending_review' THEN 0 ELSE 1 END ASC,
        created_at DESC
       LIMIT $${values.length}`,
      values
    );

    return res.json({
      orders: result.rows.map((row) => ({
        id: Number(row.id),
        orderNumber: row.order_number,
        customerName: row.customer_name,
        customerPhone: row.customer_phone,
        customerEmail: row.customer_email,
        totalKobo: Number(row.total_kobo || 0),
        status: row.status,
        paymentChannel: row.payment_channel || null,
        paymentProofUrl: row.payment_proof_url || null,
        paymentProofNote: row.payment_proof_note || "",
        paymentProofUploadedAt: row.payment_proof_uploaded_at,
        paymentProofStatus: row.payment_proof_status || "none",
        paymentReviewNote: row.payment_review_note || "",
        paymentReviewedAt: row.payment_reviewed_at,
        paymentReviewedBy: row.payment_reviewed_by || null,
        paymentVerifiedAt: row.payment_verified_at,
        paymentVerifiedBy: row.payment_verified_by || null,
        reconciliationStatus: row.reconciliation_status || "unreconciled",
        reconciliationNote: row.reconciliation_note || "",
        reconciledAt: row.reconciled_at,
        reconciledBy: row.reconciled_by || null,
        paymentReminderCount: Number(row.payment_reminder_count || 0),
        lastPaymentReminderAt: row.last_payment_reminder_at,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      })),
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to fetch payment review queue." });
  }
});

app.get("/api/admin/orders/:id/payment-reminders", requireAdmin, requireRole("owner", "manager"), async (req, res) => {
  try {
    const id = parseIntOrUndefined(req.params.id);
    if (!id) return res.status(400).json({ error: "Invalid order id." });
    const limit = Math.min(Math.max(parseIntOrUndefined(req.query.limit) || 50, 1), 200);
    const result = await pool.query(
      `SELECT
        id, reminder_channel, message, sent_by_user_id, sent_by_username, created_at
       FROM order_payment_reminders
       WHERE order_id = $1
       ORDER BY created_at DESC
       LIMIT $2`,
      [id, limit]
    );
    return res.json({
      reminders: result.rows.map((row) => ({
        id: Number(row.id),
        reminderChannel: row.reminder_channel,
        message: row.message || "",
        sentByUserId: row.sent_by_user_id === null ? null : Number(row.sent_by_user_id),
        sentByUsername: row.sent_by_username || "system",
        createdAt: row.created_at,
      })),
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to fetch payment reminders." });
  }
});

app.patch(
  "/api/admin/orders/:id/payment-proof",
  requireAdmin,
  requireRole("owner", "manager"),
  async (req, res) => {
    try {
      const id = parseIntOrUndefined(req.params.id);
      if (!id) return res.status(400).json({ error: "Invalid order id." });

      const payload = req.body || {};
      const decision = String(payload.decision || "").trim().toLowerCase();
      const note = String(payload.note || "").trim();
      const setStatusPaid = parseBoolean(payload.setStatusPaid) !== false;
      const validDecisions = new Set(["pending_review", "approved", "rejected"]);
      if (!validDecisions.has(decision)) {
        return res.status(400).json({ error: "decision must be pending_review, approved, or rejected." });
      }

      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const orderResult = await client.query(
          `SELECT
            id, order_number, status, payment_channel, payment_proof_url, payment_proof_status
           FROM orders
           WHERE id = $1
           FOR UPDATE`,
          [id]
        );
        if (!orderResult.rowCount) {
          await client.query("ROLLBACK");
          return res.status(404).json({ error: "Order not found." });
        }
        const order = orderResult.rows[0];
        if (!order.payment_proof_url && decision !== "pending_review") {
          await client.query("ROLLBACK");
          return res.status(400).json({ error: "No payment proof uploaded for this order." });
        }

        let nextStatus = order.status;
        if (decision === "approved" && setStatusPaid && order.status === "pending_payment") {
          nextStatus = "paid";
        } else if (decision === "rejected" && order.status === "paid") {
          nextStatus = "pending_payment";
        }

        const updateResult = await client.query(
          `UPDATE orders
           SET
            payment_proof_status = $1,
            payment_review_note = $2,
            payment_reviewed_at = NOW(),
            payment_reviewed_by = $3,
            status = $4,
            payment_verified_at = CASE
              WHEN $1 = 'approved' THEN COALESCE(payment_verified_at, NOW())
              ELSE payment_verified_at
            END,
            payment_verified_by = CASE
              WHEN $1 = 'approved' THEN COALESCE(payment_verified_by, $3)
              ELSE payment_verified_by
            END,
            paid_at = CASE
              WHEN $4 = 'paid' THEN COALESCE(paid_at, NOW())
              ELSE paid_at
            END,
            updated_at = NOW()
           WHERE id = $5
           RETURNING
            id, order_number, status, payment_proof_status, payment_review_note,
            payment_reviewed_at, payment_reviewed_by, payment_verified_at, payment_verified_by`,
          [decision, note, req.admin?.username || "system", nextStatus, id]
        );
        const updated = updateResult.rows[0];

        if (order.status !== nextStatus) {
          await appendOrderStatusHistory(
            client,
            id,
            order.status,
            nextStatus,
            `Payment proof ${decision}${note ? `: ${note}` : ""}`,
            { userId: req.admin?.userId || null, username: req.admin?.username || "system" }
          );
        }

        await client.query("COMMIT");

        await writeAuditLog(req, "order.payment_proof.review", "order", id, {
          orderNumber: updated.order_number,
          decision,
          note,
          statusFrom: order.status,
          statusTo: nextStatus,
        });

        return res.json({
          order: {
            id: Number(updated.id),
            orderNumber: updated.order_number,
            status: updated.status,
            paymentProofStatus: updated.payment_proof_status,
            paymentReviewNote: updated.payment_review_note || "",
            paymentReviewedAt: updated.payment_reviewed_at,
            paymentReviewedBy: updated.payment_reviewed_by || null,
            paymentVerifiedAt: updated.payment_verified_at,
            paymentVerifiedBy: updated.payment_verified_by || null,
          },
        });
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
    } catch (error) {
      console.error(error);
      return res.status(500).json({ error: "Failed to review payment proof." });
    }
  }
);

app.patch(
  "/api/admin/orders/:id/reconciliation",
  requireAdmin,
  requireRole("owner", "manager"),
  async (req, res) => {
    try {
      const id = parseIntOrUndefined(req.params.id);
      if (!id) return res.status(400).json({ error: "Invalid order id." });

      const payload = req.body || {};
      const reconciliationStatus = String(payload.reconciliationStatus || "").trim().toLowerCase();
      const note = String(payload.note || "").trim();
      const validStatuses = new Set(["unreconciled", "reconciled", "disputed"]);
      if (!validStatuses.has(reconciliationStatus)) {
        return res.status(400).json({ error: "Invalid reconciliationStatus value." });
      }

      const result = await pool.query(
        `UPDATE orders
         SET
          reconciliation_status = $1,
          reconciliation_note = $2,
          reconciled_at = CASE WHEN $1 = 'reconciled' THEN NOW() ELSE NULL END,
          reconciled_by = CASE WHEN $1 = 'reconciled' THEN $3 ELSE NULL END,
          updated_at = NOW()
         WHERE id = $4
         RETURNING
          id, order_number, reconciliation_status, reconciliation_note, reconciled_at, reconciled_by`,
        [reconciliationStatus, note, req.admin?.username || "system", id]
      );
      if (!result.rowCount) {
        return res.status(404).json({ error: "Order not found." });
      }
      const row = result.rows[0];

      await writeAuditLog(req, "order.reconciliation.update", "order", id, {
        orderNumber: row.order_number,
        reconciliationStatus,
        note,
      });

      return res.json({
        order: {
          id: Number(row.id),
          orderNumber: row.order_number,
          reconciliationStatus: row.reconciliation_status,
          reconciliationNote: row.reconciliation_note || "",
          reconciledAt: row.reconciled_at,
          reconciledBy: row.reconciled_by || null,
        },
      });
    } catch (error) {
      console.error(error);
      return res.status(500).json({ error: "Failed to update reconciliation status." });
    }
  }
);

app.patch("/api/orders/:id/status", requireAdmin, requireRole("owner", "manager"), async (req, res) => {
  try {
    const id = parseIntOrUndefined(req.params.id);
    if (!id) return res.status(400).json({ error: "Invalid order id." });

    const payload = req.body || {};
    const nextStatus = String(payload.status || "").trim();
    const note = String(payload.note || "").trim();
    const validStatuses = new Set([
      "pending_payment",
      "paid",
      "processing",
      "shipped",
      "delivered",
      "cancelled",
      "refunded",
    ]);

    if (!validStatuses.has(nextStatus)) {
      return res.status(400).json({ error: "Invalid order status value." });
    }

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const orderResult = await client.query(
        `SELECT id, status, order_number, coupon_code, coupon_discount_kobo, payment_channel
         FROM orders
         WHERE id = $1
         FOR UPDATE`,
        [id]
      );
      if (!orderResult.rowCount) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "Order not found." });
      }

      const order = orderResult.rows[0];
      if (order.status === nextStatus) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: "Order is already in this status." });
      }

      const updates = [`status = $1`, `updated_at = NOW()`];
      const values = [nextStatus, id];
      if (nextStatus === "paid") {
        updates.push(`paid_at = COALESCE(paid_at, NOW())`);
        updates.push(`payment_proof_status = CASE WHEN payment_proof_status = 'pending_review' THEN 'approved' ELSE payment_proof_status END`);
        updates.push(
          `payment_reviewed_at = CASE WHEN payment_proof_status = 'pending_review' THEN COALESCE(payment_reviewed_at, NOW()) ELSE payment_reviewed_at END`
        );
        updates.push(
          `payment_reviewed_by = CASE WHEN payment_proof_status = 'pending_review' THEN COALESCE(payment_reviewed_by, $${values.length + 1}) ELSE payment_reviewed_by END`
        );
        updates.push(`payment_verified_at = COALESCE(payment_verified_at, NOW())`);
        updates.push(`payment_verified_by = COALESCE(payment_verified_by, $${values.length + 1})`);
        values.push(req.admin?.username || "system");
      }

      const updatedResult = await client.query(
        `UPDATE orders
         SET ${updates.join(", ")}
         WHERE id = $${values.length === 2 ? 2 : values.length - 1}
         RETURNING id, order_number, status, subtotal_kobo, total_kobo`,
        values
      );

      if (nextStatus === "paid" && order.coupon_code) {
        const couponResult = await client.query(
          `SELECT id FROM coupons WHERE UPPER(code) = UPPER($1) LIMIT 1`,
          [order.coupon_code]
        );
        if (couponResult.rowCount) {
          const couponId = Number(couponResult.rows[0].id);
          const existingRedemption = await client.query(
            `SELECT 1 FROM coupon_redemptions WHERE coupon_id = $1 AND order_id = $2 LIMIT 1`,
            [couponId, id]
          );
          if (!existingRedemption.rowCount) {
            await client.query(
              `INSERT INTO coupon_redemptions (coupon_id, order_id, code, discount_kobo)
               VALUES ($1, $2, $3, $4)`,
              [couponId, id, order.coupon_code, Number(order.coupon_discount_kobo || 0)]
            );
            await client.query(
              `UPDATE coupons
               SET used_count = used_count + 1, updated_at = NOW()
               WHERE id = $1`,
              [couponId]
            );
          }
        }
      }

      await appendOrderStatusHistory(client, id, order.status, nextStatus, note, {
        userId: req.admin?.userId || null,
        username: req.admin?.username || "system",
      });

      await client.query("COMMIT");

      const updated = updatedResult.rows[0];
      await writeAuditLog(req, "order.status.update", "order", updated.id, {
        orderNumber: updated.order_number,
        previousStatus: order.status,
        newStatus: nextStatus,
        note,
      });

      return res.json({
        order: {
          id: Number(updated.id),
          orderNumber: updated.order_number,
          status: updated.status,
          subtotalKobo: Number(updated.subtotal_kobo),
          totalKobo: Number(updated.total_kobo || updated.subtotal_kobo),
        },
      });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to update order status." });
  }
});

app.get("/api/orders/summary", requireAdmin, async (_req, res) => {
  try {
    const result = await pool.query(
      `SELECT
        COUNT(*)::int AS total_orders,
        COALESCE(SUM(total_kobo), 0)::bigint AS total_revenue_kobo,
        COALESCE(SUM(CASE WHEN created_at >= date_trunc('month', NOW()) THEN total_kobo ELSE 0 END), 0)::bigint AS month_revenue_kobo,
        COALESCE(AVG(total_kobo), 0)::bigint AS average_order_kobo
       FROM orders
       WHERE status IN ('paid', 'processing', 'shipped', 'delivered')`
    );
    res.json({ summary: result.rows[0] || null });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to fetch order summary" });
  }
});

app.get("/api/expenses", requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(Math.max(parseIntOrUndefined(req.query.limit) || 50, 1), 200);
    const result = await pool.query(
      `SELECT id, title, category, amount_kobo, notes, spent_at, created_at
       FROM expenses
       ORDER BY spent_at DESC
       LIMIT $1`,
      [limit]
    );
    res.json({
      expenses: result.rows.map((row) => ({
        id: Number(row.id),
        title: row.title,
        category: row.category,
        amountKobo: Number(row.amount_kobo),
        notes: row.notes,
        spentAt: row.spent_at,
        createdAt: row.created_at,
      })),
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to fetch expenses" });
  }
});

app.post("/api/expenses", requireAdmin, requireRole("owner", "manager"), async (req, res) => {
  try {
    const payload = req.body || {};
    const title = String(payload.title || "").trim();
    const category = String(payload.category || "general").trim() || "general";
    const notes = String(payload.notes || "").trim();
    const amountKobo = parseIntOrUndefined(payload.amountKobo);
    const spentAtRaw = payload.spentAt;
    const spentAt = spentAtRaw ? new Date(String(spentAtRaw)) : new Date();

    if (!title) {
      return res.status(400).json({ error: "title is required" });
    }
    if (amountKobo === undefined || amountKobo < 0) {
      return res.status(400).json({ error: "amountKobo must be a non-negative integer" });
    }
    if (Number.isNaN(spentAt.getTime())) {
      return res.status(400).json({ error: "spentAt must be a valid date string" });
    }

    const result = await pool.query(
      `INSERT INTO expenses
        (title, category, amount_kobo, notes, spent_at)
       VALUES
        ($1, $2, $3, $4, $5)
       RETURNING id, title, category, amount_kobo, notes, spent_at, created_at`,
      [title, category, amountKobo, notes, spentAt.toISOString()]
    );

    const row = result.rows[0];
    await writeAuditLog(req, "expense.create", "expense", row.id, {
      title: row.title,
      amountKobo: Number(row.amount_kobo),
      category: row.category,
    });
    return res.status(201).json({
      expense: {
        id: Number(row.id),
        title: row.title,
        category: row.category,
        amountKobo: Number(row.amount_kobo),
        notes: row.notes,
        spentAt: row.spent_at,
        createdAt: row.created_at,
      },
    });
  } catch (error) {
    console.error(error);
    return sendPgError(res, error, "Failed to create expense");
  }
});

app.delete("/api/expenses/:id", requireAdmin, requireRole("owner", "manager"), async (req, res) => {
  try {
    const id = parseIntOrUndefined(req.params.id);
    if (id === undefined) {
      return res.status(400).json({ error: "Invalid expense id" });
    }
    const result = await pool.query(`DELETE FROM expenses WHERE id = $1 RETURNING id, title`, [id]);
    if (!result.rowCount) {
      return res.status(404).json({ error: "Expense not found" });
    }
    await writeAuditLog(req, "expense.delete", "expense", result.rows[0].id, {
      title: result.rows[0].title,
    });
    return res.json({
      deleted: {
        id: Number(result.rows[0].id),
        title: result.rows[0].title,
      },
    });
  } catch (error) {
    console.error(error);
    return sendPgError(res, error, "Failed to delete expense");
  }
});

app.get("/api/expenses/summary", requireAdmin, async (_req, res) => {
  try {
    const result = await pool.query(
      `SELECT
        COALESCE(SUM(amount_kobo), 0)::bigint AS total_expenses_kobo,
        COALESCE(SUM(CASE WHEN spent_at >= date_trunc('month', NOW()) THEN amount_kobo ELSE 0 END), 0)::bigint AS month_expenses_kobo
       FROM expenses`
    );
    res.json({ summary: result.rows[0] || null });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to fetch expense summary" });
  }
});

app.get("/api/admin/analytics", requireAdmin, async (req, res) => {
  try {
    const days = Math.min(Math.max(parseIntOrUndefined(req.query.days) || 30, 1), 365);
    const sinceDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

    const [funnel, trend, topProducts, brandSplit] = await Promise.all([
      pool.query(
        `SELECT
          COUNT(*)::int AS initiated_orders,
          COALESCE(SUM(CASE WHEN status IN ('paid', 'processing', 'shipped', 'delivered') THEN 1 ELSE 0 END), 0)::int AS successful_orders,
          COALESCE(SUM(CASE WHEN status IN ('paid', 'processing', 'shipped', 'delivered') THEN total_kobo ELSE 0 END), 0)::bigint AS successful_revenue_kobo
         FROM orders
         WHERE created_at >= $1`,
        [sinceDate.toISOString()]
      ),
      pool.query(
        `SELECT
          DATE_TRUNC('day', created_at) AS day,
          COALESCE(SUM(CASE WHEN status IN ('paid', 'processing', 'shipped', 'delivered') THEN total_kobo ELSE 0 END), 0)::bigint AS revenue_kobo,
          COUNT(*)::int AS orders_count
         FROM orders
         WHERE created_at >= $1
         GROUP BY DATE_TRUNC('day', created_at)
         ORDER BY day ASC`,
        [sinceDate.toISOString()]
      ),
      pool.query(
        `SELECT
          oi.product_id,
          oi.product_name,
          COALESCE(SUM(oi.qty), 0)::int AS units_sold,
          COALESCE(SUM(oi.line_total_kobo), 0)::bigint AS revenue_kobo
         FROM order_items oi
         INNER JOIN orders o ON o.id = oi.order_id
         WHERE o.created_at >= $1
           AND o.status IN ('paid', 'processing', 'shipped', 'delivered')
         GROUP BY oi.product_id, oi.product_name
         ORDER BY revenue_kobo DESC, units_sold DESC
         LIMIT 10`,
        [sinceDate.toISOString()]
      ),
      pool.query(
        `SELECT
          oi.brand,
          COALESCE(SUM(oi.qty), 0)::int AS units_sold,
          COALESCE(SUM(oi.line_total_kobo), 0)::bigint AS revenue_kobo
         FROM order_items oi
         INNER JOIN orders o ON o.id = oi.order_id
         WHERE o.created_at >= $1
           AND o.status IN ('paid', 'processing', 'shipped', 'delivered')
         GROUP BY oi.brand
         ORDER BY revenue_kobo DESC`,
        [sinceDate.toISOString()]
      ),
    ]);

    const funnelRow = funnel.rows[0] || {};
    const initiated = Number(funnelRow.initiated_orders || 0);
    const successful = Number(funnelRow.successful_orders || 0);
    const successRate = initiated > 0 ? successful / initiated : 0;
    const revenueKobo = Number(funnelRow.successful_revenue_kobo || 0);
    const averageOrderKobo = successful > 0 ? Math.round(revenueKobo / successful) : 0;

    return res.json({
      windowDays: days,
      since: sinceDate.toISOString(),
      funnel: {
        initiatedOrders: initiated,
        successfulOrders: successful,
        successRate,
        successfulRevenueKobo: revenueKobo,
        averageOrderKobo,
      },
      trend: trend.rows.map((row) => ({
        day: row.day,
        revenueKobo: Number(row.revenue_kobo || 0),
        ordersCount: Number(row.orders_count || 0),
      })),
      topProducts: topProducts.rows.map((row) => ({
        productId: row.product_id === null ? null : Number(row.product_id),
        productName: row.product_name,
        unitsSold: Number(row.units_sold || 0),
        revenueKobo: Number(row.revenue_kobo || 0),
      })),
      brandSplit: brandSplit.rows.map((row) => ({
        brand: row.brand,
        unitsSold: Number(row.units_sold || 0),
        revenueKobo: Number(row.revenue_kobo || 0),
      })),
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to fetch analytics." });
  }
});

app.post("/api/cart/track", async (req, res) => {
  try {
    const payload = req.body || {};
    let sessionId = String(payload.sessionId || "").trim();
    if (!sessionId) {
      sessionId = crypto.randomUUID();
    }

    const normalized = normalizeCartItemsWithVariants(payload.items || []);
    const normalizedItems = normalized.valid ? normalized.items : [];

    let subtotalKobo = 0;
    if (normalizedItems.length) {
      const catalog = await fetchCatalogForCartItems(pool, normalizedItems, { lockRows: false });
      if (catalog.valid) {
        const { productMap, variantMap } = catalog;
        for (const item of normalizedItems) {
          const product = productMap.get(item.productId);
          if (!product) continue;
          const variant = item.variantId ? variantMap.get(item.variantId) : null;
          const unitPriceKobo =
            variant && variant.priceOverrideKobo !== null ? variant.priceOverrideKobo : product.priceKobo;
          subtotalKobo += unitPriceKobo * item.qty;
        }
      }
    }

    const compactItems = normalizedItems
      .filter((item) => item.productId && item.qty)
      .map((item) => ({
        productId: Number(item.productId),
        variantId: item.variantId === null ? null : Number(item.variantId),
        qty: Number(item.qty),
      }));

    const statusRaw = String(payload.status || "").trim().toLowerCase();
    const validStatuses = new Set(["open", "abandoned", "converted", "contacted", "recovered"]);
    const status = validStatuses.has(statusRaw)
      ? statusRaw
      : compactItems.length
        ? "open"
        : "converted";

    const customerName =
      payload.customerName === undefined || payload.customerName === null
        ? null
        : String(payload.customerName).trim() || null;
    const customerPhone =
      payload.customerPhone === undefined || payload.customerPhone === null
        ? null
        : String(payload.customerPhone).trim() || null;
    const customerEmail =
      payload.customerEmail === undefined || payload.customerEmail === null
        ? null
        : String(payload.customerEmail).trim() || null;

    await pool.query(
      `INSERT INTO cart_sessions
        (session_id, customer_name, customer_phone, customer_email, items_json, subtotal_kobo, status, reminder_count, last_seen_at)
       VALUES
        ($1, $2, $3, $4, $5::jsonb, $6, $7, 0, NOW())
       ON CONFLICT (session_id) DO UPDATE SET
        customer_name = COALESCE(EXCLUDED.customer_name, cart_sessions.customer_name),
        customer_phone = COALESCE(EXCLUDED.customer_phone, cart_sessions.customer_phone),
        customer_email = COALESCE(EXCLUDED.customer_email, cart_sessions.customer_email),
        items_json = EXCLUDED.items_json,
        subtotal_kobo = EXCLUDED.subtotal_kobo,
        status = EXCLUDED.status,
        last_seen_at = NOW(),
        updated_at = NOW()`,
      [
        sessionId,
        customerName,
        customerPhone,
        customerEmail,
        JSON.stringify(compactItems),
        subtotalKobo,
        status,
      ]
    );

    return res.json({
      sessionId,
      status,
      subtotalKobo,
      itemsCount: compactItems.reduce((sum, item) => sum + item.qty, 0),
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to track cart session." });
  }
});

app.get("/api/admin/abandoned-carts", requireAdmin, async (req, res) => {
  try {
    const hours = Math.min(Math.max(parseIntOrUndefined(req.query.hours) || 1, 1), 168);
    const limit = Math.min(Math.max(parseIntOrUndefined(req.query.limit) || 100, 1), 500);
    const result = await pool.query(
      `SELECT
        session_id, customer_name, customer_phone, customer_email, items_json, subtotal_kobo,
        status, reminder_count, last_reminder_at, last_seen_at, created_at, updated_at
       FROM cart_sessions
       WHERE
        status = 'abandoned'
        OR (status = 'open' AND last_seen_at < NOW() - ($1::text || ' hours')::interval)
       ORDER BY last_seen_at ASC
       LIMIT $2`,
      [String(hours), limit]
    );

    res.json({
      carts: result.rows.map((row) => ({
        sessionId: row.session_id,
        customerName: row.customer_name,
        customerPhone: row.customer_phone,
        customerEmail: row.customer_email,
        items: row.items_json || [],
        subtotalKobo: Number(row.subtotal_kobo || 0),
        status: row.status,
        reminderCount: Number(row.reminder_count || 0),
        lastReminderAt: row.last_reminder_at,
        lastSeenAt: row.last_seen_at,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      })),
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to fetch abandoned carts." });
  }
});

app.post(
  "/api/admin/abandoned-carts/:sessionId/reminder",
  requireAdmin,
  requireRole("owner", "manager"),
  async (req, res) => {
    try {
      const sessionId = String(req.params.sessionId || "").trim();
      if (!sessionId) return res.status(400).json({ error: "Invalid session id." });

      const cartResult = await pool.query(
        `SELECT
          session_id, customer_name, customer_phone, subtotal_kobo, reminder_count
         FROM cart_sessions
         WHERE session_id = $1
         LIMIT 1`,
        [sessionId]
      );
      if (!cartResult.rowCount) {
        return res.status(404).json({ error: "Cart session not found." });
      }
      const cart = cartResult.rows[0];
      const phone = normalizeWhatsAppNumber(cart.customer_phone || "");
      if (!phone) {
        return res.status(400).json({ error: "No valid customer phone number for this cart." });
      }

      const message = [
        `Hello ${cart.customer_name || "there"},`,
        "You still have items in your cart at Sholly & Shaddy's.",
        `Current cart value: NGN ${(Number(cart.subtotal_kobo || 0) / 100).toFixed(2)}.`,
        "Reply here if you want us to complete your order for you.",
      ].join("\n");
      const whatsappUrl = `https://wa.me/${phone}?text=${encodeURIComponent(message)}`;

      const updateResult = await pool.query(
        `UPDATE cart_sessions
         SET
          status = 'contacted',
          reminder_count = reminder_count + 1,
          last_reminder_at = NOW(),
          updated_at = NOW()
         WHERE session_id = $1
         RETURNING reminder_count, status, updated_at`,
        [sessionId]
      );

      await writeAuditLog(req, "cart_session.reminder.sent", "cart_session", sessionId, {
        phone,
        reminderCount: Number(updateResult.rows[0].reminder_count || 0),
      });

      return res.json({
        sessionId,
        phone,
        message,
        whatsappUrl,
        reminderCount: Number(updateResult.rows[0].reminder_count || 0),
        status: updateResult.rows[0].status,
        updatedAt: updateResult.rows[0].updated_at,
      });
    } catch (error) {
      console.error(error);
      return res.status(500).json({ error: "Failed to create abandoned cart reminder." });
    }
  }
);

app.patch("/api/admin/abandoned-carts/:sessionId", requireAdmin, requireRole("owner", "manager"), async (req, res) => {
  try {
    const sessionId = String(req.params.sessionId || "").trim();
    if (!sessionId) return res.status(400).json({ error: "Invalid session id." });
    const status = String((req.body || {}).status || "").trim().toLowerCase();
    const incrementReminder = parseBoolean((req.body || {}).incrementReminder);
    const validStatuses = new Set(["open", "abandoned", "converted", "contacted", "recovered"]);
    if (!validStatuses.has(status)) {
      return res.status(400).json({ error: "Invalid status value." });
    }

    const result = await pool.query(
      `UPDATE cart_sessions
       SET
        status = $1,
        reminder_count = CASE WHEN $2 THEN reminder_count + 1 ELSE reminder_count END,
        updated_at = NOW()
       WHERE session_id = $3
       RETURNING session_id, status, reminder_count, updated_at`,
      [status, Boolean(incrementReminder), sessionId]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Cart session not found." });

    await writeAuditLog(req, "cart_session.update", "cart_session", sessionId, {
      status,
      incrementReminder: Boolean(incrementReminder),
    });

    const row = result.rows[0];
    return res.json({
      cart: {
        sessionId: row.session_id,
        status: row.status,
        reminderCount: Number(row.reminder_count || 0),
        updatedAt: row.updated_at,
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to update cart session." });
  }
});

app.get("/api/admin/dashboard", requireAdmin, async (_req, res) => {
  try {
    const [inventory, sales, expenses, coupons, abandoned] = await Promise.all([
      pool.query(
        `SELECT
          COUNT(*)::int AS total_products,
          COALESCE(SUM(stock_qty), 0)::int AS total_units,
          COALESCE(SUM(price_kobo * stock_qty), 0)::bigint AS stock_value_kobo,
          COALESCE(SUM(CASE WHEN stock_qty <= reorder_threshold THEN 1 ELSE 0 END), 0)::int AS low_stock_products,
          (SELECT COUNT(*)::int FROM product_variants) AS total_variants,
          (SELECT COALESCE(SUM(stock_qty), 0)::int FROM product_variants) AS total_variant_units,
          (
            SELECT COALESCE(SUM(CASE WHEN is_active = TRUE AND stock_qty <= reorder_threshold THEN 1 ELSE 0 END), 0)::int
            FROM product_variants
          ) AS low_stock_variants
         FROM products`
      ),
      pool.query(
        `SELECT
          COUNT(*)::int AS total_orders,
          COALESCE(SUM(total_kobo), 0)::bigint AS total_revenue_kobo,
          COALESCE(SUM(CASE WHEN created_at >= date_trunc('month', NOW()) THEN total_kobo ELSE 0 END), 0)::bigint AS month_revenue_kobo,
          COALESCE(AVG(total_kobo), 0)::bigint AS average_order_kobo
         FROM orders
         WHERE status IN ('paid', 'processing', 'shipped', 'delivered')`
      ),
      pool.query(
        `SELECT
          COALESCE(SUM(amount_kobo), 0)::bigint AS total_expenses_kobo,
          COALESCE(SUM(CASE WHEN spent_at >= date_trunc('month', NOW()) THEN amount_kobo ELSE 0 END), 0)::bigint AS month_expenses_kobo
         FROM expenses`
      ),
      pool.query(
        `SELECT
          COALESCE(SUM(CASE WHEN is_active THEN 1 ELSE 0 END), 0)::int AS active_coupons,
          COUNT(*)::int AS total_coupons
         FROM coupons`
      ),
      pool.query(
        `SELECT
          COUNT(*)::int AS abandoned_count,
          COALESCE(SUM(subtotal_kobo), 0)::bigint AS abandoned_value_kobo
         FROM cart_sessions
         WHERE status = 'abandoned'
            OR (status = 'open' AND last_seen_at < NOW() - INTERVAL '60 minutes')`
      ),
    ]);

    const inventorySummary = inventory.rows[0];
    const salesSummary = sales.rows[0];
    const expenseSummary = expenses.rows[0];
    const couponSummary = coupons.rows[0];
    const abandonedSummary = abandoned.rows[0];

    const totalRevenueKobo = Number(salesSummary.total_revenue_kobo || 0);
    const totalExpensesKobo = Number(expenseSummary.total_expenses_kobo || 0);
    const monthRevenueKobo = Number(salesSummary.month_revenue_kobo || 0);
    const monthExpensesKobo = Number(expenseSummary.month_expenses_kobo || 0);

    res.json({
      inventory: {
        totalProducts: Number(inventorySummary.total_products || 0),
        totalUnits: Number(inventorySummary.total_units || 0),
        stockValueKobo: Number(inventorySummary.stock_value_kobo || 0),
        lowStockProducts: Number(inventorySummary.low_stock_products || 0),
        totalVariants: Number(inventorySummary.total_variants || 0),
        totalVariantUnits: Number(inventorySummary.total_variant_units || 0),
        lowStockVariants: Number(inventorySummary.low_stock_variants || 0),
      },
      sales: {
        totalOrders: Number(salesSummary.total_orders || 0),
        totalRevenueKobo,
        monthRevenueKobo,
        averageOrderKobo: Number(salesSummary.average_order_kobo || 0),
      },
      expenses: {
        totalExpensesKobo,
        monthExpensesKobo,
      },
      coupons: {
        totalCoupons: Number(couponSummary.total_coupons || 0),
        activeCoupons: Number(couponSummary.active_coupons || 0),
      },
      abandoned: {
        carts: Number(abandonedSummary.abandoned_count || 0),
        valueKobo: Number(abandonedSummary.abandoned_value_kobo || 0),
      },
      net: {
        totalProfitKobo: totalRevenueKobo - totalExpensesKobo,
        monthProfitKobo: monthRevenueKobo - monthExpensesKobo,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to fetch admin dashboard" });
  }
});

app.get("/api/admin/audit-logs", requireAdmin, requireRole("owner", "manager"), async (req, res) => {
  try {
    const limit = Math.min(Math.max(parseIntOrUndefined(req.query.limit) || 100, 1), 500);
    const result = await pool.query(
      `SELECT
        id, admin_user_id, admin_username, action, entity_type, entity_id, metadata, ip_address, user_agent, created_at
       FROM audit_logs
       ORDER BY created_at DESC
       LIMIT $1`,
      [limit]
    );
    res.json({
      logs: result.rows.map((row) => ({
        id: Number(row.id),
        adminUserId: row.admin_user_id === null ? null : Number(row.admin_user_id),
        adminUsername: row.admin_username,
        action: row.action,
        entityType: row.entity_type,
        entityId: row.entity_id,
        metadata: row.metadata || {},
        ipAddress: row.ip_address,
        userAgent: row.user_agent,
        createdAt: row.created_at,
      })),
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to fetch audit logs." });
  }
});

app.get("/api/admin/cloudinary/status", requireAdmin, (_req, res) => {
  res.json({
    enabled: isCloudinaryConfigured(),
    cloudName: process.env.CLOUDINARY_CLOUD_NAME || null,
    folder: process.env.CLOUDINARY_FOLDER || "sholly-store",
  });
});

app.post(
  "/api/admin/upload-image",
  requireAdmin,
  requireRole("owner", "manager", "editor"),
  upload.single("image"),
  async (req, res) => {
  try {
    if (!isCloudinaryConfigured()) {
      return res.status(503).json({
        error: "Cloudinary is not configured. Set CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET.",
      });
    }

    if (!req.file) {
      return res.status(400).json({ error: "No image file found. Upload using field name 'image'." });
    }

    if (!req.file.mimetype || !req.file.mimetype.startsWith("image/")) {
      return res.status(400).json({ error: "Uploaded file must be an image." });
    }

    const dataUri = `data:${req.file.mimetype};base64,${req.file.buffer.toString("base64")}`;
    const folder = String(process.env.CLOUDINARY_FOLDER || "sholly-store").trim();

    const result = await cloudinary.uploader.upload(dataUri, {
      folder: folder || "sholly-store",
      resource_type: "image",
      use_filename: true,
      unique_filename: true,
      overwrite: false,
    });

    return res.status(201).json({
      url: result.secure_url,
      publicId: result.public_id,
      width: result.width,
      height: result.height,
      format: result.format,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Failed to upload image to Cloudinary." });
  }
  }
);

app.get("/admin", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

app.get("/account", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "account.html"));
});

app.get("/track", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "track.html"));
});

app.use((error, _req, res, next) => {
  if (!error) {
    return next();
  }

  if (error instanceof multer.MulterError) {
    if (error.code === "LIMIT_FILE_SIZE") {
      return res.status(400).json({ error: "Image is too large. Max file size is 8MB." });
    }
    return res.status(400).json({ error: `Upload error: ${error.code}` });
  }

  console.error(error);
  return res.status(500).json({ error: "Unexpected server error." });
});

async function runMigrationsIfEnabled() {
  if (String(process.env.AUTO_MIGRATE).toLowerCase() !== "true") {
    return;
  }
  const sqlPath = path.join(__dirname, "db", "schema.sql");
  const sql = await fs.readFile(sqlPath, "utf8");
  await pool.query(sql);
  console.log("Schema ensured.");
}

async function ensureBootstrapAdminUser() {
  const username = normalizeUsername(ADMIN_USERNAME);
  const password = String(ADMIN_PASSWORD || "");
  const role = ROLE_LEVEL[ADMIN_BOOTSTRAP_ROLE] ? ADMIN_BOOTSTRAP_ROLE : "owner";
  if (!username || !password) {
    return;
  }

  const existing = await pool.query(
    `SELECT id FROM admin_users WHERE LOWER(username) = LOWER($1) LIMIT 1`,
    [username]
  );
  if (existing.rowCount) {
    return;
  }

  const passwordHash = hashPassword(password);
  await pool.query(
    `INSERT INTO admin_users (username, password_hash, role, is_active)
     VALUES ($1, $2, $3, TRUE)`,
    [username, passwordHash, role]
  );
  console.log(`Bootstrap admin user created for "${username}" with role "${role}".`);
}

async function start() {
  if (!process.env.DATABASE_URL) {
    console.error("Missing DATABASE_URL in environment.");
    process.exit(1);
  }

  try {
    await pool.query("SELECT 1");
    await runMigrationsIfEnabled();
    await ensureBootstrapAdminUser();
    app.listen(port, () => {
      console.log(`Server running on http://localhost:${port}`);
    });
  } catch (error) {
    console.error("Startup failed:", error);
    process.exit(1);
  }
}

start();
