// secureAuth.js
// A plug-and-play Express module with secure auth, CSRF, headers, CORS, and rate limiting.
// Requires: express, bcrypt, jsonwebtoken, helmet, cors, express-rate-limit, csurf, cookie-parser, dotenv

import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import csurf from "csurf";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";

dotenv.config();

const {
  JWT_SECRET = "change_this_in_env",
  JWT_EXPIRES_IN = "1h",
  NODE_ENV = "development",
  CORS_ORIGIN = "http://localhost:3000",
} = process.env;

const isProd = NODE_ENV === "production";

/**
 * Simple in-memory user store for demo.
 * Replace with your DB (e.g., MongoDB, Postgres).
 */
const users = new Map(); // key: email, value: { email, passwordHash, role }

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

/**
 * Middleware: verify JWT from Authorization header
 * Format: Authorization: Bearer <token>
 */
function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: "Missing token" });
  }

  try {
    const decoded = verifyToken(token);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

/**
 * Middleware: role-based access control (RBAC)
 * Example usage: app.get("/admin", requireAuth, requireRole("admin"), handler)
 */
function requireRole(role) {
  return (req, res, next) => {
    if (!req.user?.role || req.user.role !== role) {
      return res.status(403).json({ error: "Forbidden" });
    }
    next();
  };
}

/**
 * Rate limiter: helps protect auth endpoints from brute force
 */
const authLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 50,                 // 50 requests per window per IP
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * CSRF protection:
 * Uses cookie-based CSRF tokens. Frontend must read token from /csrf-token and send it back
 * in a header (e.g., X-CSRF-Token) for state-changing requests.
 */
const csrfProtection = csurf({
  cookie: {
    httpOnly: true,
    sameSite: isProd ? "strict" : "lax",
    secure: isProd, // requires HTTPS in production
  },
});

function createSecureApp() {
  const app = express();

  // Basic parsers
  app.use(express.json());
  app.use(cookieParser());

  // Security headers
  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: true,
        directives: {
          "default-src": ["'self'"],
          "script-src": ["'self'"],
          "style-src": ["'self'", "'unsafe-inline'"], // allow inline styles if needed
          "img-src": ["'self'", "data:"],
          "connect-src": ["'self'", CORS_ORIGIN],
          "frame-ancestors": ["'none'"], // prevents clickjacking
        },
      },
      frameguard: { action: "deny" }, // X-Frame-Options
      hsts: isProd ? { maxAge: 31536000, includeSubDomains: true, preload: true } : false,
      referrerPolicy: { policy: "no-referrer" },
      xssFilter: true,
      noSniff: true,
    })
  );

  // CORS
  app.use(
    cors({
      origin: CORS_ORIGIN,
      credentials: true,
      methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
      allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token"],
      exposedHeaders: ["Authorization"],
    })
  );

  // Health check
  app.get("/health", (req, res) => {
    res.json({ status: "ok" });
  });

  // CSRF token route (frontend fetches token and includes it in subsequent requests)
  app.get("/csrf-token", csrfProtection, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
  });

  // Auth routes
  const auth = express.Router();

  // Apply rate limiting + CSRF to auth router
  auth.use(authLimiter);
  auth.use(csrfProtection);

  // Register
  auth.post("/register", async (req, res) => {
    const { email, password, role = "user" } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }
    if (users.has(email)) {
      return res.status(409).json({ error: "User already exists" });
    }

    try {
      const passwordHash = await bcrypt.hash(password, 12);
      users.set(email, { email, passwordHash, role });
      return res.status(201).json({ message: "Registered successfully" });
    } catch (err) {
      return res.status(500).json({ error: "Registration failed" });
    }
  });

  // Login
  auth.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const user = users.get(email);
    if (!user) {
      // Avoid user enumeration
      return res.status(401).json({ error: "
