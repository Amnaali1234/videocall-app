import assert from 'node:assert/strict'
import { once } from 'node:events'
import { after, test } from 'node:test'

const originalAppId = process.env.ZEGO_APP_ID
const originalSecret = process.env.ZEGO_SERVER_SECRET
process.env.ZEGO_APP_ID = '123456789'
process.env.ZEGO_SERVER_SECRET = '0123456789abcdef0123456789abcdef'

const { app } = await import('./server.js')
const server = app.listen(0, '127.0.0.1')
await once(server, 'listening')
const address = server.address()
const apiUrl = `http://127.0.0.1:${address.port}/api`

after(async () => {
  await new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve())
  })
  if (originalAppId === undefined) delete process.env.ZEGO_APP_ID
  else process.env.ZEGO_APP_ID = originalAppId
  if (originalSecret === undefined) delete process.env.ZEGO_SERVER_SECRET
  else process.env.ZEGO_SERVER_SECRET = originalSecret
})

test('serves a real Token04 response and reports missing credentials', async () => {
  const tokenResponse = await fetch(`${apiUrl}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      roomId: 'ABCD-1234',
      userId: 'u0123456789abcdef0123',
      userName: 'Test participant',
    }),
  })
  const tokenData = await tokenResponse.json()

  assert.equal(tokenResponse.status, 200)
  assert.equal(tokenData.appId, 123456789)
  assert.ok(tokenData.token.startsWith('04'))

  const invalidResponse = await fetch(`${apiUrl}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ roomId: 'bad', userId: 'u0123456789abcdef0123', userName: 'Guest' }),
  })
  assert.equal(invalidResponse.status, 400)

  process.env.ZEGO_SERVER_SECRET = ''
  const unconfiguredResponse = await fetch(`${apiUrl}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      roomId: 'ABCD-1234',
      userId: 'u0123456789abcdef0123',
      userName: 'Test participant',
    }),
  })
  assert.equal(unconfiguredResponse.status, 503)
  assert.match((await unconfiguredResponse.json()).error, /backend\/\.env/)
})
