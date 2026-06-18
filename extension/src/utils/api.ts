const VT_BASE = 'https://www.virustotal.com/api/v3'
const TEST_IP = '8.8.8.8'

export interface ExTentionConfig {
  vtApiKey?: string
  backendUrl?: string
  useBackend?: boolean
}

export interface VtStats {
  malicious: number
  suspicious: number
  harmless: number
  undetected: number
}

export interface ThreatResult {
  malicious: boolean
  source: 'virustotal' | 'backend' | 'cache'
  label: string
  stats?: VtStats
}

export async function validateApiKey(key: string): Promise<{ valid: boolean; error?: string }> {
  try {
    const res = await fetch(`${VT_BASE}/ip_addresses/${TEST_IP}`, {
      headers: { 'x-apikey': key },
    })

    if (res.status === 200) return { valid: true }
    if (res.status === 401) return { valid: false, error: 'Invalid API key' }
    if (res.status === 403) return { valid: false, error: 'API key lacks access' }
    if (res.status === 429) return { valid: false, error: 'Rate limited – try again later' }

    return { valid: false, error: `Unexpected HTTP ${res.status}` }
  } catch (err) {
    return { valid: false, error: `Network error: ${(err as Error).message}` }
  }
}

function hexEncode(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

async function sha256Hex(input: string): Promise<string> {
  const encoder = new TextEncoder()
  const hash = await crypto.subtle.digest('SHA-256', encoder.encode(input))
  return hexEncode(hash)
}

function parseVtStats(data: any): VtStats | undefined {
  const attrs = data?.data?.attributes?.last_analysis_stats
  if (!attrs) return undefined
  return {
    malicious: attrs.malicious ?? 0,
    suspicious: attrs.suspicious ?? 0,
    harmless: attrs.harmless ?? 0,
    undetected: attrs.undetected ?? 0,
  }
}

async function callVtDirect(url: string, apiKey: string): Promise<ThreatResult> {
  const urlId = await sha256Hex(url)

  const res = await fetch(`${VT_BASE}/urls/${urlId}`, {
    headers: { 'x-apikey': apiKey },
  })

  if (res.status === 404) {
    return { malicious: false, source: 'virustotal', label: 'No analysis found for this URL' }
  }

  if (!res.ok) {
    throw new Error(`VirusTotal error: HTTP ${res.status}`)
  }

  const data = await res.json()
  const stats = parseVtStats(data)

  if (!stats) {
    return { malicious: false, source: 'virustotal', label: 'No analysis data returned' }
  }

  const isMalicious = stats.malicious > 0 || stats.suspicious > 2

  return {
    malicious: isMalicious,
    source: 'virustotal',
    label: isMalicious
      ? `${stats.malicious} malicious, ${stats.suspicious} suspicious`
      : 'Clean',
    stats,
  }
}

async function callBackendProxy(url: string, apiKey: string, backendUrl: string): Promise<ThreatResult> {
  const res = await fetch(`${backendUrl.replace(/\/+$/, '')}/check`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, api_key: apiKey }),
  })

  if (!res.ok) {
    throw new Error(`Backend proxy error: HTTP ${res.status}`)
  }

  const data = await res.json()

  const stats: VtStats | undefined = data.vt_stats
    ? {
        malicious: data.vt_stats.malicious ?? 0,
        suspicious: data.vt_stats.suspicious ?? 0,
        harmless: data.vt_stats.harmless ?? 0,
        undetected: data.vt_stats.undetected ?? 0,
      }
    : undefined

  return {
    malicious: data.malicious ?? false,
    source: 'backend',
    label: data.label ?? 'No result from backend',
    stats,
  }
}

export async function checkUrl(url: string, apiKey: string, backendUrl?: string): Promise<ThreatResult> {
  try {
    return await callVtDirect(url, apiKey)
  } catch {
    // Direct call failed — CORS, network outage, or rate-limit
    if (backendUrl) {
      try {
        return await callBackendProxy(url, apiKey, backendUrl)
      } catch {
        throw new Error(
          'Connection Error: Direct API call failed and backend proxy is unreachable. ' +
          'Verify your backend URL or check your network connection.'
        )
      }
    }

    throw new Error(
      'Connection Error: Cannot reach VirusTotal. ' +
      'If CORS is blocked in your environment, enable the optional Python backend.'
    )
  }
}
