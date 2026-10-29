import assert from 'node:assert/strict'
import { createDecipheriv } from 'node:crypto'
import { test } from 'node:test'
import { generateToken04 } from './zegoToken.js'

test('generates a ZEGOCLOUD Token04 that decrypts to the supplied room token data', () => {
  const appId = 123456789
  const userId = 'u0123456789abcdef0123'
  const secret = '0123456789abcdef0123456789abcdef'
  const payload = JSON.stringify({
    room_id: 'ABCD-1234',
    privilege: { 1: 1, 2: 1 },
    stream_id_list: [userId],
  })

  const token = generateToken04(appId, userId, secret, 3600, payload)
  assert.ok(token.startsWith('04'))

  const binary = Buffer.from(token.slice(2), 'base64')
  const expiresAt = Number(binary.readBigInt64BE(0))
  const ivLength = binary.readUInt16BE(8)
  const ivOffset = 10
  const iv = binary.subarray(ivOffset, ivOffset + ivLength)
  const lengthOffset = ivOffset + ivLength
  const encryptedLength = binary.readUInt16BE(lengthOffset)
  const encryptedOffset = lengthOffset + 2
  const encrypted = binary.subarray(encryptedOffset, encryptedOffset + encryptedLength)
  const mode = binary.readUInt8(encryptedOffset + encryptedLength)

  assert.equal(ivLength, 12)
  assert.equal(mode, 1)

  const decipher = createDecipheriv('aes-256-gcm', Buffer.from(secret, 'utf8'), iv)
  decipher.setAuthTag(encrypted.subarray(-16))
  const decrypted = Buffer.concat([
    decipher.update(encrypted.subarray(0, -16)),
    decipher.final(),
  ])
  const tokenData = JSON.parse(decrypted.toString('utf8'))

  assert.equal(tokenData.app_id, appId)
  assert.equal(tokenData.user_id, userId)
  assert.equal(tokenData.expire, expiresAt)
  assert.equal(tokenData.payload, payload)
  assert.ok(tokenData.nonce >= -0x80000000 && tokenData.nonce < 0x80000000)
})

test('rejects invalid Token04 configuration', () => {
  assert.throws(() => generateToken04(0, 'user', '0123456789abcdef0123456789abcdef', 3600))
  assert.throws(() => generateToken04(123, 'user', 'short', 3600))
})
