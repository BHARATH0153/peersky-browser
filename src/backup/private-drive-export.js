import crypto from 'crypto'
import z32 from 'z32'
import { listPrivateHyperdrives } from '../protocols/private-hyperdrive-registry.js'

// Named private-drive-key.json for mobile compatibility, even though the
// record carries no key yet: desktop private drives are unencrypted and
// "device only" (autoJoin:false, doReplicate:false, announce:false). The
// filename is the mobile transfer contract; key will be populated once
// desktop private drives are encrypted.
export const PRIVATE_DRIVE_KEY_FILE = 'private-drive-key.json'

export async function buildPrivateDriveKeyExport (userDataDir, now = Date.now()) {
  let entries
  try {
    entries = await listPrivateHyperdrives(userDataDir)
  } catch {
    return null
  }
  if (entries.length === 0) return null

  const drives = []
  for (const entry of entries) {
    const driveId = decodeDriveId(entry.url)
    if (!driveId) continue
    drives.push({ driveId, createdAt: entry.timestamp || null })
  }
  if (drives.length === 0) return null

  const primary = drives[0].driveId

  return Buffer.from(JSON.stringify({
    version: 3,
    createdAt: new Date(now).toISOString(),
    key: null,
    driveId: primary,
    encrypted: false,
    announce: false,
    source: 'desktop',
    entries: drives
  }, null, 2))
}

export function decodeDriveId (url) {
  let hostname
  try {
    hostname = new URL(url).hostname
  } catch {
    return null
  }

  try {
    if (/^[a-z0-9]{52}$/i.test(hostname)) {
      return Buffer.from(z32.decode(hostname.toLowerCase())).toString('hex')
    }
    if (/^[0-9a-f]{64}$/i.test(hostname)) {
      return hostname.toLowerCase()
    }
  } catch {}

  return null
}

export function hashPrivateDriveKeyExport (bytes) {
  const hash = crypto.createHash('sha256')
  hash.update(bytes)
  return hash.digest('hex')
}
