links.forEach(link => {
    const url = link.href;
    if (!url || url.startsWith('javascript:')...
    ...
    const score = computePhishingProbability(features);
    const reasons = generateReasons(features, score);

    if (score >= HIGH_RISK_THRESHOLD) {
      scanResults.flagged++;
      link.classList.add('phishing-high-risk');
      ...
    }
});// featureExtractor.js
// Phishing detection: whitelist + ML features + typosquatting (Levenshtein distance)

// ─── TRUSTED DOMAIN WHITELIST ─────────────────────────────────────────────────
const TRUSTED_DOMAINS = new Set([
  'google.com','bing.com','yahoo.com','duckduckgo.com','baidu.com','yandex.com',
  'accounts.google.com','mail.google.com','drive.google.com','docs.google.com',
  'maps.google.com','youtube.com','youtu.be','googleapis.com','gstatic.com',
  'googleusercontent.com','googlevideo.com','google.co.uk','google.com.au',
  'facebook.com','instagram.com','twitter.com','x.com','linkedin.com',
  'reddit.com','pinterest.com','tiktok.com','snapchat.com','whatsapp.com',
  'microsoft.com','live.com','outlook.com','office.com','office365.com',
  'microsoftonline.com','azure.com','msn.com','hotmail.com',
  'sharepoint.com','onedrive.com','teams.microsoft.com',
  'apple.com','icloud.com','appleid.apple.com',
  'amazon.com','amazon.co.uk','amazonaws.com',
  'paypal.com','stripe.com','barclays.co.uk','hsbc.co.uk','lloydsbank.com',
  'santander.co.uk','natwest.com','chase.com','bankofamerica.com','wellsfargo.com',
  'github.com','gitlab.com','stackoverflow.com','npmjs.com','cloudflare.com',
  'netlify.com','vercel.com','heroku.com','digitalocean.com',
  'wikipedia.org','bbc.com','bbc.co.uk','cnn.com','nytimes.com','theguardian.com',
  'reuters.com','bloomberg.com',
  'ebay.com','etsy.com','shopify.com','aliexpress.com',
  'openai.com','chat.openai.com','chatgpt.com','claude.ai','anthropic.com',
  'gemini.google.com','perplexity.ai','poe.com','copilot.microsoft.com',
  'netflix.com','spotify.com','twitch.tv','vimeo.com','soundcloud.com',
  'dropbox.com','notion.so','slack.com','zoom.us','discord.com',
  // Educational institutions
  'ac.uk','edu','edu.au','edu.ca','ac.nz','ac.za',
  // Trusted country-code second-level domains — legitimate businesses use these
  'co.uk','org.uk','gov.uk','nhs.uk','police.uk','mod.uk',
  'com.au','org.au','gov.au','net.au',
  'co.nz','govt.nz','org.nz',
  'co.za','gov.za',
  'co.in','gov.in','nic.in',
  // Common university platforms
  'moodle.org','blackboard.com','canvas.instructure.com','turnitin.com',
  'studylink.com','studentroom.com','ucas.com',
  // Google ad & tracking domains — these appear on YouTube and other Google properties
  'googleadservices.com','doubleclick.net','googlesyndication.com','googletagmanager.com',
  'googletagservices.com','google-analytics.com','googleoptimize.com','g.co',
  // Common ad networks that appear on major sites
  'adsrvr.org','adobedtm.com','advertising.com','adnxs.com','criteo.com',
  'taboola.com','outbrain.com','moatads.com','scorecardresearch.com',
  'wordpress.com','medium.com','substack.com',
]);

function isTrustedDomain(hostname) {
  hostname = hostname.toLowerCase().replace(/^www\./, '');
  if (TRUSTED_DOMAINS.has(hostname)) return true;
  const parts = hostname.split('.');

  // Check parent domains (e.g. accounts.google.com → google.com)
  for (let i = 1; i < parts.length - 1; i++) {
    if (TRUSTED_DOMAINS.has(parts.slice(i).join('.'))) return true;
  }

  // Check two-part TLDs like ac.uk, co.uk, edu.au
  // e.g. affinitywater.co.uk → co.uk is trusted
  //      moodlecurrent.gre.ac.uk → ac.uk is trusted
  if (parts.length >= 2) {
    const twoPartTld = parts.slice(-2).join('.');
    if (TRUSTED_DOMAINS.has(twoPartTld)) return true;
  }

  // Check single TLDs like .edu, .gov
  const singleTld = parts[parts.length - 1];
  // .uk, .gov, .edu etc are regulated TLDs — treat all as trusted
  if (['gov', 'edu', 'mil', 'int', 'uk'].includes(singleTld)) return true;

  return false;
}

// ─── TYPOSQUATTING: LEVENSHTEIN DISTANCE ─────────────────────────────────────
// Target brands to compare against — these are the domains attackers impersonate.
// We extract just the domain name part (without TLD) for comparison.
const BRAND_TARGETS = [
  'paypal','amazon','apple','google','microsoft','facebook','instagram',
  'twitter','netflix','spotify','ebay','barclays','hsbc','lloyds','natwest',
  'santander','chase','dropbox','linkedin','youtube','github','discord',
  'whatsapp','snapchat','tiktok',
];

// Wagner-Fischer dynamic programming Levenshtein distance
// Research standard: threshold of 1-2 catches most typosquats without false positives
function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i-1] === b[j-1]) {
        dp[i][j] = dp[i-1][j-1];
      } else {
        dp[i][j] = 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
      }
    }
  }
  return dp[m][n];
}

// Also handle homoglyph substitutions (0→o, 1→l, 3→e, etc.)
function normalizeHomoglyphs(str) {
  return str
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/8/g, 'b')
    .replace(/@/g, 'a')
    .replace(/\$/g, 's');
}

function checkTyposquatting(hostname) {
  // Extract just the registrable domain name part (strip subdomains and TLD)
  const parts = hostname.replace(/^www\./, '').split('.');
  // Get the second-to-last part as the "domain name" (e.g. "paypa1" from "paypa1.com")
  const domainName = parts.length >= 2 ? parts[parts.length - 2] : parts[0];
  const normalized = normalizeHomoglyphs(domainName.toLowerCase());

  let closestBrand = null;
  let minDistance = Infinity;

  for (const brand of BRAND_TARGETS) {
    // Direct check on normalized name
    const dist = levenshtein(normalized, brand);
    // Also check without hyphens (pay-pal → paypal)
    const distNoHyphen = levenshtein(normalized.replace(/-/g, ''), brand);
    const best = Math.min(dist, distNoHyphen);

    if (best < minDistance) {
      minDistance = best;
      closestBrand = brand;
    }
  }

  // Threshold: distance 1 = one character off (very likely typosquat)
  //            distance 2 = two characters off (possible typosquat)
  //            Only flag if domain is similar in length (avoids flagging unrelated short words)
  const lengthRatio = Math.abs(domainName.length - closestBrand.length) / closestBrand.length;
  if (minDistance <= 2 && lengthRatio <= 0.5 && domainName !== closestBrand) {
    return { isTyposquat: true, brand: closestBrand, distance: minDistance, domainName };
  }
  return { isTyposquat: false };
}

// ─── FEATURE EXTRACTION ───────────────────────────────────────────────────────
function extractFeatures(url) {
  let urlObj;
  try { urlObj = new URL(url); } catch (e) { return null; }

  const hostname = urlObj.hostname.toLowerCase().replace(/^www\./, '');
  if (isTrustedDomain(hostname)) return null;

  const fullUrl = url.toLowerCase();
  const features = {};

  features.urlLength      = fullUrl.length;
  features.numDots        = (hostname.match(/\./g) || []).length;
  features.numHyphens     = (hostname.match(/-/g) || []).length;
  features.hasHttps       = urlObj.protocol === 'https:' ? 1 : 0;
  features.hasIpAddress   = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(hostname) ? 1 : 0;
  features.hasAtSymbol    = fullUrl.includes('@') ? 1 : 0;
  features.hasEncoding    = (fullUrl.match(/%[0-9a-f]{2}/gi) || []).length > 0 ? 1 : 0;
  features.domainLength   = hostname.length;
  features.hasDigitsInDomain = /[0-9]/.test(hostname.split('.')[0]) ? 1 : 0;

  const hostParts = hostname.split('.');
  features.numSubdomains  = Math.max(0, hostParts.length - 2);

  // Brand keywords only in domain name, not path
  const domainKeywords = ['paypal','amazon','apple','microsoft','google',
    'ebay','bank','secure','verify','signin','netflix','account-update'];
  features.matchedKeywords = [];
  for (const kw of domainKeywords) {
    if (hostname.includes(kw)) features.matchedKeywords.push(kw);
  }
  features.suspiciousKeywordCount = features.matchedKeywords.length;

  // Brand name in subdomain but root domain is different
  const subdomainPart = hostParts.slice(0, -2).join('.');
  const brands = ['paypal','amazon','apple','google','microsoft','ebay','netflix','hsbc','barclays'];
  features.brandInSubdomain = brands.some(b => subdomainPart.includes(b)) ? 1 : 0;


  // Suspicious TLD check — free/cheap TLDs heavily abused by phishers
  // Source: abuse statistics from SpamHaus and SURBL threat feeds
  const SUSPICIOUS_TLDS = new Set([
    'xyz','top','tk','ml','ga','cf','gq','pw','cc','su',
    'info','biz','click','link','online','site','website',
    'live','stream','download','win','loan','racing','party',
    'trade','date','faith','review','cricket','science','work',
    'icu','uno','fun','rest','tech','space','store','press',
    'monster','digital','media','network','solutions','services'
  ]);
  const tld = hostParts[hostParts.length - 1].toLowerCase();
  features.hasSuspiciousTld = SUSPICIOUS_TLDS.has(tld) ? 1 : 0;
  features.tld = tld;


  // Scam-specific keywords in the domain name — software scams, fake updates, malware installs
  // These catch sites like ultraplusadblocker.info, chrome-update-required.xyz etc.
  const SCAM_DOMAIN_KEYWORDS = [
    // Ad blocker scams
    'adblocker','adblock','ultrablocker','superadblocker','proadblocker',
    'bestadblocker','topadblocker','freeadblocker','fastblocker',
    // Fake software / crack sites (only when in domain, not path)
    'crack','keygen','warez','nulled','cracked',
    // Fake security scams
    'virus-detected','malware-found','pc-infected','device-infected',
    'your-computer','yourcomputer','computer-virus',
    // Prize/reward scams
    'prize','winner','you-won','youwon','congratulations','claim-reward',
    // Fake tech support
    'tech-support','techsupport','microsoft-support','apple-support',
    'windows-support','call-now','callnow',
    // Fake VPN/security
    'freevpn','free-vpn','bestvpn','vpnfree',
    // Browser hijack patterns
    'browsersecurity','protectnow','securebrowse','browsersafe'
  ];
  let scamKeywordCount = 0;
  features.matchedScamKeywords = [];
  const domainNameOnly = hostParts.slice(0, -1).join('.').toLowerCase();
  for (const kw of SCAM_DOMAIN_KEYWORDS) {
    if (domainNameOnly.includes(kw)) {
      scamKeywordCount++;
      features.matchedScamKeywords.push(kw);
    }
  }
  features.scamKeywordCount = scamKeywordCount;

  // 3. Long compound domain — many words jammed together with no hyphens
  // e.g. "ultraplusadblocker" — legitimate sites don't do this
  const domainWord = hostParts[hostParts.length - 2] || '';
  // Count approx word count by looking for camelCase boundaries or known words
  const wordBoundaries = domainWord.replace(/([a-z])([A-Z])/g, '$1 $2')
    .replace(/(plus|ultra|super|free|best|top|pro|new|get|my|the|web|net|app|go|click|online|download|install|update|your|now)/gi, ' $1 ')
    .trim().split(/\s+/).filter(w => w.length > 1);
  features.domainWordCount = wordBoundaries.length;
  features.isLongCompoundDomain = domainWord.length > 12 && features.numHyphens === 0 && features.scamKeywordCount > 0 ? 1 : 0;

  // Typosquatting check
  const typo = checkTyposquatting(hostname);
  features.isTyposquat     = typo.isTyposquat ? 1 : 0;
  features.typoInfo        = typo; // for XAI reasons

  return features;
}

// ─── XAI REASON GENERATION ────────────────────────────────────────────────────
function generateReasons(features, score) {
  const reasons = [];

  if (features.hasIpAddress) {
    reasons.push({ text: 'Uses a raw IP address instead of a domain name', severity: 'high' });
  }
  if (features.isTyposquat && features.typoInfo) {
    const t = features.typoInfo;
    const editWord = t.distance === 1 ? '1 character' : '2 characters';
    reasons.push({
      text: `Typosquatting detected — "${t.domainName}" is only ${editWord} away from "${t.brand}" (Levenshtein distance: ${t.distance})`,
      severity: 'high'
    });
  }
  if (features.brandInSubdomain) {
    reasons.push({ text: 'Brand name in subdomain but root domain is unknown — classic impersonation (e.g. paypal.evil.com)', severity: 'high' });
  }
  if (features.hasAtSymbol) {
    reasons.push({ text: 'Contains @ in URL — disguises the real destination', severity: 'high' });
  }
  if (features.matchedKeywords && features.matchedKeywords.length > 0) {
    reasons.push({
      text: `Suspicious brand/sensitive keywords in domain: "${features.matchedKeywords.join('", "')}"`,
      severity: 'high'
    });
  }
  if (features.numHyphens >= 2) {
    reasons.push({ text: `${features.numHyphens} hyphens in domain — phishing domains mimic real sites with hyphens`, severity: 'medium' });
  }
  if (features.numSubdomains >= 3) {
    reasons.push({ text: `Deep subdomain structure (${features.numSubdomains} levels) — used to obscure the real domain`, severity: 'high' });
  } else if (features.numSubdomains === 2) {
    reasons.push({ text: 'Multiple subdomains — verify the root domain carefully', severity: 'medium' });
  }
  if (!features.hasHttps) {
    reasons.push({ text: 'No HTTPS — data is transmitted without encryption', severity: 'medium' });
  }
  if (features.hasEncoding) {
    reasons.push({ text: 'URL contains encoded characters — common obfuscation technique', severity: 'medium' });
  }
  if (features.hasDigitsInDomain) {
    reasons.push({ text: 'Domain uses digits substituting letters (e.g. "paypa1" → "paypal")', severity: 'medium' });
  }
  if (features.domainLength > 30) {
    reasons.push({ text: `Very long domain name (${features.domainLength} chars) — legitimate sites rarely need this`, severity: 'low' });
  }
  if (features.matchedScamKeywords && features.matchedScamKeywords.length > 0) {
    reasons.push({
      text: `Domain contains scam/malware keywords: "${features.matchedScamKeywords.slice(0,3).join('", "')}" — common in fake update and software scam sites`,
      severity: 'high'
    });
  }
  if (features.isLongCompoundDomain) {
    reasons.push({
      text: `Domain is an unusually long compound word (${features.domainWord || ''}) — legitimate sites use short, recognisable names`,
      severity: 'medium'
    });
  }
  if (features.hasSuspiciousTld) {
    reasons.push({ text: `Domain uses a suspicious TLD (.${features.tld}) — commonly associated with free/throwaway phishing domains`, severity: 'medium' });
  }
  if (features.urlLength > 150) {
    reasons.push({ text: `Unusually long URL (${features.urlLength} chars)`, severity: 'low' });
  }
  if (reasons.length === 0 && score >= 0.6) {
    reasons.push({ text: 'Combination of structural features flagged by the ML model', severity: 'medium' });
  }
  return reasons;
}
