import { createCipheriv, randomBytes, randomInt } from 'node:crypto'

export function generateToken04(appId, userId, serverSecret, expiresInSeconds, payload = '') {
  if (!Number.isSafeInteger(appId) || appId <= 0) throw new Error('ZEGOCLOUD App ID must be a positive integer.')
  if (typeof userId !== 'string' || userId.length < 1 || userId.length > 64) {
    throw new Error('ZEGOCLOUD user ID must contain 1–64 characters.')
  }
  if (typeof serverSecret !== 'string' || Buffer.byteLength(serverSecret, 'utf8') !== 32) {
    throw new Error('ZEGOCLOUD Server Secret must be 32 bytes.')
  }
  if (!Number.isSafeInteger(expiresInSeconds) || expiresInSeconds < 1) {
    throw new Error('Token lifetime must be a positive integer.')
  }
  if (typeof payload !== 'string') throw new Error('Token payload must be a string.')

  const createdAt = Math.floor(Date.now() / 1000)
  const expiresAt = createdAt + expiresInSeconds
  const tokenData = JSON.stringify({
    app_id: appId,
    user_id: userId,
    nonce: randomInt(-0x80000000, 0x80000000),
    ctime: createdAt,
    expire: expiresAt,
    payload,
  })

  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', Buffer.from(serverSecret, 'utf8'), iv)
  const encrypted = Buffer.concat([cipher.update(tokenData, 'utf8'), cipher.final(), cipher.getAuthTag()])
  const header = Buffer.alloc(10)
  header.writeBigInt64BE(BigInt(expiresAt), 0)
  header.writeUInt16BE(iv.length, 8)
  const cipherLength = Buffer.alloc(2)
  cipherLength.writeUInt16BE(encrypted.length, 0)

  return `04${Buffer.concat([header, iv, cipherLength, encrypted, Buffer.from([1])]).toString('base64')}`
}
