import cors from 'cors'
import dotenv from 'dotenv'
import express from 'express'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { generateToken04 } from './zegoToken.js'

const backendDirectory = dirname(fileURLToPath(import.meta.url))
dotenv.config({ path: join(backendDirectory, '.env') })

const app = express()
const port = Number(process.env.PORT || 3001)
const allowedOrigin = process.env.CLIENT_ORIGIN || 'http://localhost:5173'

app.disable('x-powered-by')
app.use(cors({ origin: allowedOrigin }))
app.use(express.json({ limit: '8kb' }))

function getCredentials() {
  const appId = Number(process.env.ZEGO_APP_ID)
  const serverSecret = process.env.ZEGO_SERVER_SECRET
  const valid = Number.isSafeInteger(appId)
    && appId > 0
    && typeof serverSecret === 'string'
    && Buffer.byteLength(serverSecret, 'utf8') === 32

  return valid ? { appId, serverSecret } : null
}

app.get('/api/health', (_request, response) => {
  response.json({ status: 'ok', configured: Boolean(getCredentials()) })
})

app.post('/api/token', (request, response) => {
  const { roomId, userId, userName } = request.body ?? {}
  if (typeof roomId !== 'string' || !/^[A-Za-z0-9-]{4,64}$/.test(roomId)) {
    return response.status(400).json({ error: 'Room ID must contain 4–64 letters, numbers, or hyphens.' })
  }
  if (typeof userId !== 'string' || !/^u[a-f0-9]{20}$/.test(userId)) {
    return response.status(400).json({ error: 'A valid meeting user ID is required.' })
  }
  if (typeof userName !== 'string' || userName.trim().length < 1 || userName.trim().length > 60) {
    return response.status(400).json({ error: 'Display name must contain 1–60 characters.' })
  }

  const credentials = getCredentials()
  if (!credentials) {
    return response.status(503).json({
      error: 'Set a valid ZEGO_APP_ID and 32-byte ZEGO_SERVER_SECRET in backend/.env.',
    })
  }

  try {
    const payload = JSON.stringify({
      room_id: roomId,
      privilege: { 1: 1, 2: 1 },
      stream_id_list: [userId],
    })
    const token = generateToken04(credentials.appId, userId, credentials.serverSecret, 60 * 60, payload)
    return response.json({ appId: credentials.appId, token })
  } catch (error) {
    console.error('Could not generate ZEGOCLOUD room token:', error.message)
    return response.status(500).json({ error: 'Could not create secure room access. Please try again.' })
  }
})

app.use((error, _request, response, _next) => {
  if (error instanceof SyntaxError && 'body' in error) {
    return response.status(400).json({ error: 'Request body must be valid JSON.' })
  }
  console.error('Token service request failed:', error instanceof Error ? error.message : 'Unknown error')
  return response.status(500).json({ error: 'The token service encountered an unexpected error.' })
})

export { app }

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  app.listen(port, '127.0.0.1', () => {
    console.log(`ConnectNow token service listening on http://localhost:${port}`)
  })
}
