import rateLimit from 'express-rate-limit'

// Single-instance in-memory rate limiting for the free demo deployment.
// No Redis service is required. Limits reset when the service restarts.
function makeLimiter(opts: { windowMs: number; max: number }) {
  return rateLimit({
    windowMs: opts.windowMs,
    limit: opts.max,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, error: { code: 'RATE_LIMITED', message: 'Too many requests' } },
  })
}

// Strict limiter for auth endpoints (login/register/refresh) — per IP.
export const authLimiter = makeLimiter({ windowMs: 15 * 60 * 1000, max: 30 })

// Very strict for OTP requests.
export const otpLimiter = makeLimiter({ windowMs: 10 * 60 * 1000, max: 5 })

// General API limiter.
export const apiLimiter = makeLimiter({ windowMs: 60 * 1000, max: 120 })
