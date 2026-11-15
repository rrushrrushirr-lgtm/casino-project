import { createHash, randomInt } from 'node:crypto'
import type { OtpChannel } from '@prisma/client'
import { prisma } from './lib/prisma.js'
import { logger } from './lib/logger.js'
import { AppError } from './lib/errors.js'

const OTP_TTL_SECONDS = 300 // 5 minutes
const MAX_VERIFY_ATTEMPTS = 5
const REQUEST_COOLDOWN_SECONDS = 60

function hashCode(code: string): string {
  return createHash('sha256').update(code).digest('hex')
}

/**
 * OTP simulation. In this demo, OTP cooldowns and codes are stored in PostgreSQL.
 * No Redis service is required.
 */
export const otpService = {
  async request(userId: string, channel: OtpChannel): Promise<{ devCode?: string }> {
    // Enforce the per-user/per-channel cooldown using the latest database record.
    const recentOtp = await prisma.otpCode.findFirst({
      where: {
        userId,
        channel,
        createdAt: { gt: new Date(Date.now() - REQUEST_COOLDOWN_SECONDS * 1000) },
      },
      select: { id: true },
    })
    if (recentOtp) {
      throw AppError.tooMany('Please wait before requesting another code', 'OTP_COOLDOWN')
    }

    const code = randomInt(0, 1_000_000).toString().padStart(6, '0')

    await prisma.otpCode.create({
      data: {
        userId,
        channel,
        codeHash: hashCode(code),
        expiresAt: new Date(Date.now() + OTP_TTL_SECONDS * 1000),
      },
    })

    // SIMULATION: deliver via logs / dev response instead of a real provider.
    logger.info({ userId, channel, code }, 'OTP issued (simulation)')
    return process.env.NODE_ENV === 'production' ? {} : { devCode: code }
  },

  async verify(userId: string, channel: OtpChannel, code: string): Promise<boolean> {
    const otp = await prisma.otpCode.findFirst({
      where: { userId, channel, consumed: false, expiresAt: { gt: new Date() } },
      orderBy: { createdAt: 'desc' },
    })

    if (!otp) throw AppError.badRequest('No valid code — request a new one', 'OTP_NOT_FOUND')

    if (otp.attempts >= MAX_VERIFY_ATTEMPTS) {
      throw AppError.tooMany('Too many attempts — request a new code', 'OTP_LOCKED')
    }

    if (otp.codeHash !== hashCode(code)) {
      await prisma.otpCode.update({
        where: { id: otp.id },
        data: { attempts: { increment: 1 } },
      })
      throw AppError.badRequest('Invalid code', 'OTP_INVALID')
    }

    await prisma.$transaction([
      prisma.otpCode.update({ where: { id: otp.id }, data: { consumed: true } }),
      channel === 'EMAIL'
        ? prisma.user.update({ where: { id: userId }, data: { emailVerified: true } })
        : prisma.user.update({ where: { id: userId }, data: { phoneVerified: true } }),
    ])

    return true
  },
}
