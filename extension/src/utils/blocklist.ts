export interface BlocklistEntry {
  type: 'domain' | 'url' | 'substring' | 'regex'
  pattern: string
  label: string
}

export const BLOCKLIST: BlocklistEntry[] = [
  { type: 'domain', pattern: 'malware.testing.google.test', label: 'Test malware domain' },
  { type: 'domain', pattern: 'testmalware.com', label: 'Known malware test domain' },
  { type: 'domain', pattern: 'malware-sample.com', label: 'Malware sample distribution' },
  { type: 'domain', pattern: 'phishing.army', label: 'Phishing Army blocklist' },
  { type: 'domain', pattern: 'malwaredomainlist.com', label: 'Malware domain list' },

  { type: 'url', pattern: 'tinyurl.com/evil', label: 'Shortened malicious redirect' },
  { type: 'url', pattern: 'tinyurl.com/prank', label: 'Shortened prank redirect' },

  { type: 'substring', pattern: '.tk/phishing', label: 'Suspicious TLD phishing page' },
  { type: 'substring', pattern: '.ml/login', label: 'Suspicious TLD login page' },
  { type: 'substring', pattern: '.ga/login', label: 'Suspicious TLD login page' },
  { type: 'substring', pattern: '.cf/login', label: 'Suspicious TLD login page' },

  { type: 'substring', pattern: 'secure-login.xyz', label: 'Credential harvesting domain' },
  { type: 'substring', pattern: 'account-verify.com', label: 'Phishing verification page' },
  { type: 'substring', pattern: 'banking-secure.com', label: 'Fake banking portal' },
  { type: 'substring', pattern: 'paypal-security.com', label: 'Fake PayPal security page' },
  { type: 'substring', pattern: 'apple-id-verify.com', label: 'Fake Apple ID verification' },
]

export const RICKROLL_BLOCKLIST: BlocklistEntry[] = [
  { type: 'url', pattern: 'youtube.com/watch?v=dQw4w9WgXcQ', label: 'Classic Rickroll video' },
  { type: 'url', pattern: 'youtu.be/dQw4w9WgXcQ', label: 'Classic Rickroll video (short)' },
  { type: 'domain', pattern: 'rickastley.co', label: 'Rick Astley prank domain' },
  { type: 'regex', pattern: 'rickroll\\..*', label: 'Rickroll domain pattern' },
  { type: 'url', pattern: 'bit.ly/rickroll', label: 'Shortened rickroll redirect' },
  { type: 'domain', pattern: 'tenor.co', label: 'Rickroll GIF redirect' },
  { type: 'domain', pattern: 'nevergonna.give', label: 'Rickroll prank site' },
]
