// SecondLook analysis engine. Runs fully on-device: no network calls, nothing leaves the browser.
const SEV = { high: 30, medium: 15, low: 6 };
const f = (sev, title, detail, evidence = '') => ({ sev, title, detail, evidence });

const BRANDS = {
  paypal: ['paypal.com'], apple: ['apple.com', 'icloud.com'], microsoft: ['microsoft.com', 'live.com', 'office.com'],
  google: ['google.com', 'gmail.com'], amazon: ['amazon.com'], netflix: ['netflix.com'], facebook: ['facebook.com'],
  instagram: ['instagram.com'], whatsapp: ['whatsapp.com'], fedex: ['fedex.com'], usps: ['usps.com'],
  binance: ['binance.com'], coinbase: ['coinbase.com'], linkedin: ['linkedin.com'], docusign: ['docusign.com', 'docusign.net'],
  chase: ['chase.com'], wellsfargo: ['wellsfargo.com'], bankofamerica: ['bankofamerica.com'], dropbox: ['dropbox.com'], adobe: ['adobe.com']
};
const SHORT = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'rb.gy', 'ow.ly', 'shorturl.at', 't.ly', 'buff.ly']);
const BADTLD = new Set(['zip', 'mov', 'top', 'xyz', 'click', 'icu', 'sbs', 'cfd', 'cyou', 'buzz', 'rest', 'monster', 'quest', 'support', 'work', 'tk', 'ml', 'cf', 'gq']);
const SLD2 = new Set(['co.uk', 'org.uk', 'com.au', 'com.tn', 'co.in', 'com.br', 'co.jp', 'com.tr', 'co.za', 'com.mx']);

export function registrable(h) {
  const p = h.split('.');
  if (p.length <= 2) return h;
  return SLD2.has(p.slice(-2).join('.')) ? p.slice(-3).join('.') : p.slice(-2).join('.');
}
const norm = s => s.replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/0/g, 'o').replace(/[1|]/g, 'l').replace(/3/g, 'e').replace(/5/g, 's');
function lev(a, b) {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++)
    d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return d[a.length][b.length];
}

function urlSignals(raw) {
  const out = { findings: [], good: [], host: '' };
  let u;
  try { u = new URL(raw); } catch { out.findings.push(f('medium', 'Not a valid web address', 'This doesn’t read as a normal link.', raw.slice(0, 80))); return out; }
  if (!/^https?:$/.test(u.protocol)) { out.findings.push(f('high', 'Unusual link type', 'Links that don’t start with http or https can run code or hide where they go.', u.protocol)); return out; }
  const host = u.hostname.toLowerCase().replace(/\.$/, '');
  out.host = host;
  const reg = registrable(host), sld = reg.split('.')[0], tld = host.split('.').pop();
  if (u.protocol === 'http:') out.findings.push(f('medium', 'Connection isn’t encrypted', 'Anything you type here can be read in transit. Legitimate login and payment pages use HTTPS.', 'http://' + host));
  else out.good.push('Uses an encrypted connection (HTTPS). Common, and scammers use it too.');
  if (u.username || u.password) out.findings.push(f('high', 'Disguised destination', 'Text before the “@” is ignored by the browser. The real site is what comes after it.', u.username + '@' + host));
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) out.findings.push(f('high', 'Raw IP address instead of a name', 'Real companies use their own domain names.', host));
  if (host.includes('xn--')) out.findings.push(f('high', 'May use look-alike characters', 'Internationalised domains can imitate well-known sites with letters that look identical.', host));
  if (SHORT.has(host)) out.findings.push(f('medium', 'Shortened link hides the destination', 'You can’t see where this goes without opening it.', host));
  if (BADTLD.has(tld)) out.findings.push(f('low', 'Domain ending often seen in scams', `“.${tld}” is cheap and heavily used for throwaway sites. Plenty of honest sites use it too.`, host));
  const tokens = host.split(/[.\-]/);
  let matched = null;
  for (const [b, doms] of Object.entries(BRANDS)) {
    if (doms.includes(reg) || sld === b) { matched = matched || b; continue; }
    const typo = norm(sld) === b || (b.length >= 6 && lev(sld, b) === 1);
    const used = b.length >= 5 && tokens.includes(b);
    if (typo) { out.findings.push(f('high', `Looks like a copy of ${b}`, `The real site is ${doms[0]}. This one belongs to ${reg}.`, host)); break; }
    if (used) { out.findings.push(f('high', `Uses ${b}’s name but isn’t ${b}`, `The real site is ${doms[0]}. This one belongs to ${reg}.`, host)); break; }
  }
  if (matched && !out.findings.some(x => x.sev === 'high')) out.good.push(`Address matches ${matched}’s own domain. Still check the page itself.`);
  if (host.split('.').length - reg.split('.').length >= 3) out.findings.push(f('low', 'Unusually many subdomains', 'Long chains of subdomains can push the real domain out of sight.', host));
  if ((host.match(/-/g) || []).length >= 3) out.findings.push(f('low', 'Lots of hyphens in the address', 'Strings like “secure-account-login-verify” are typical of throwaway sites.', host));
  if (/(login|signin|verify|secure|update|wallet|claim|prize|gift|recover|unlock|suspend)/.test(host) && !matched) out.findings.push(f('low', 'Address contains pressure words', 'Words like “verify” or “claim” in a domain name are common in phishing.', host));
  for (const [k, v] of u.searchParams) if (/^https?:\/\//i.test(v)) { out.findings.push(f('medium', 'Passes you on to another site', 'The link contains a second address and may forward you there.', `${k}=${v.slice(0, 60)}`)); break; }
  if (u.port && !['80', '443'].includes(u.port)) out.findings.push(f('low', 'Unusual port number', 'Ordinary sites rarely need one.', ':' + u.port));
  if (raw.length > 150) out.findings.push(f('low', 'Very long link', 'Long links can bury what matters.', raw.slice(0, 70) + '…'));
  return out;
}

const RULES = [
  ['high', 'Asks for payment that’s hard to trace', 'Gift cards, wire transfers and crypto are how scammers get paid.', /gift ?cards?|western union|moneygram|wire transfer|bitcoin|crypto(?:currency)?|usdt|zelle/i],
  ['high', 'Asks you to pay to get something', 'Genuine employers and prize schemes don’t charge you fees up front.', /(?:registration|training|processing|application|security|shipping|release|activation) fee|refundable deposit|pay for (?:your )?(?:equipment|laptop|kit|software)/i],
  ['high', 'Asks for codes, IDs or credentials', 'Legitimate organisations don’t ask you to send these in a message.', /(?:send|share|confirm|verify|enter|provide|reply with)[^.\n]{0,30}(?:password|otp|one[- ]time|verification code|\bpin\b|\bssn\b|social security|card number|\bcvv\b|seed phrase|recovery phrase|passport)/i],
  ['high', 'Too-good-to-be-true promise', 'Guaranteed returns, surprise wins and risk-free money are classic hooks.', /you(?:'ve| have) (?:won|been selected)|guaranteed (?:returns?|profit|income)|risk[- ]free|double your|100% profit/i],
  ['medium', 'Unrealistic pay for easy work', 'Big, fixed earnings for little effort is a common job-scam signal.', /earn \$?\d[\d,]*\s?(?:\/|per|a)\s?(?:day|hour|week)|make \$?\d[\d,]*[^.\n]{0,20}(?:daily|per day|weekly|from home)|no experience (?:needed|required)/i],
  ['medium', 'Pushes you to act fast', 'Urgency is designed to stop you from checking.', /act now|urgent(?:ly)?|immediately|within (?:24|48) hours|last chance|final notice|expires? (?:today|soon|in)|hurry/i],
  ['medium', 'Moves the conversation to a private app', 'Scammers move chats off the platform where they can be reported.', /(?:contact|message|text|reach|chat|interview)[^.\n]{0,40}(?:whatsapp|telegram|signal)/i],
  ['medium', 'Threatens consequences', 'Fear of lockouts or legal trouble is used to rush decisions.', /account (?:has been|will be) (?:suspended|closed|locked|limited)|unusual activity|legal action|arrest|final warning|compromised/i],
  ['medium', 'Asks for secrecy', 'Legitimate offers don’t need to be hidden from people you trust.', /don'?t tell anyone|keep (?:this|it) (?:confidential|secret|private)|between us/i],
  ['medium', 'Involves cashing or depositing a check', 'Overpayment and fake-check schemes leave you owing the bank.', /(?:cash|deposit)[^.\n]{0,20}(?:check|cheque)|mystery shopper/i],
  ['low', 'Generic greeting', 'Real senders usually know your name.', /dear (?:customer|user|sir|madam|valued|account holder|applicant)/i]
];
const DOWN = { high: 'medium', medium: 'low', low: 'low' };

function textFindings(text, page = false) {
  const out = [];
  for (const [sev, title, detail, re] of RULES) {
    const m = text.match(re);
    if (!m) continue;
    const i = m.index, ev = '…' + text.slice(Math.max(0, i - 25), i + m[0].length + 25).replace(/\s+/g, ' ').trim() + '…';
    out.push(f(page ? DOWN[sev] : sev, title, detail, ev));
  }
  return out;
}

function finish(kind, subject, url, findings, good, unknowns, steps) {
  const seen = new Set();
  const fs = findings.filter(x => !seen.has(x.title + x.evidence) && seen.add(x.title + x.evidence));
  const rank = { high: 0, medium: 1, low: 2 };
  fs.sort((a, b) => rank[a.sev] - rank[b.sev]);
  const score = Math.min(100, fs.reduce((s, x) => s + SEV[x.sev], 0));
  const v = score >= 60 ? { level: 'high', label: 'High risk', line: 'Several strong warning signs. Don’t enter information or send money.' }
    : score >= 30 ? { level: 'caution', label: 'Be careful', line: 'Real warning signs. Verify independently before you act.' }
    : score >= 10 ? { level: 'low', label: 'A few flags', line: 'Minor concerns. Worth a quick check before you trust it.' }
    : { level: 'none', label: 'Nothing obvious', line: 'We found no red flags, which isn’t proof it’s safe.' };
  return { kind, subject, url, findings: fs, good, unknowns, steps, score, ...v, at: Date.now() };
}

const U_UNKNOWN = ['How old the site is, or whether other people have reported it', 'Who actually sent or posted this'];
const U_STEPS = ['Don’t enter passwords, codes or payment details yet.', 'Visit the company’s site by typing its address yourself.', 'Ask the sender through a different channel, such as a call to a number you already trust.'];

export function analyzeUrl(raw) {
  const s = urlSignals(raw);
  return finish('link', s.host || 'link', raw, s.findings, s.good,
    ['Where this link really leads. We didn’t open it.', ...U_UNKNOWN], U_STEPS);
}

export function analyzeText(text) {
  const findings = textFindings(text), good = [];
  const urls = [...new Set(text.match(/(?:https?:\/\/|www\.)[^\s<>"')]+/gi) || [])].slice(0, 3);
  for (const raw of urls) {
    const s = urlSignals(/^www\./i.test(raw) ? 'https://' + raw : raw);
    s.findings.forEach(x => findings.push({ ...x, title: `Link to ${s.host || 'link'}: ${x.title}` }));
  }
  return finish('message', urls.length ? 'message with links' : 'message', '', findings, good,
    ['Whether the person or company is real. We can’t verify the sender.', 'Where any links really lead', 'Whether others have received the same message'],
    ['Look the company up yourself on its official website. Don’t use contact details from the message.', 'Never pay to receive a job, prize or refund.', 'Show it to someone you trust before replying.']);
}

export function analyzePage(d) {
  const s = urlSignals(d.url), findings = [...s.findings, ...textFindings(d.text || '', true)], good = [...s.good];
  const pageReg = s.host ? registrable(s.host) : '';
  const SENS = /ssn|social.?security|passport|seed|recovery.?phrase|otp|cvv|card.?num|cc-number|iban/;
  for (const fm of d.forms || []) {
    let ah = ''; try { ah = new URL(fm.action).hostname; } catch {}
    const sensitive = fm.pw || SENS.test(fm.fields);
    if (fm.pw && fm.action.startsWith('http:')) findings.push(f('high', 'Password sent without encryption', 'This form submits your password over plain HTTP.', fm.action.slice(0, 80)));
    if (sensitive && ah && registrable(ah) !== pageReg) findings.push(f('high', 'Form sends your details to a different site', `You’re on ${pageReg}, but this form submits to ${registrable(ah)}.`, fm.action.slice(0, 80)));
    else if (SENS.test(fm.fields)) findings.push(f('medium', 'Page asks for sensitive information', 'Check that you reached this page by typing the address yourself.', 'ID, card or recovery-phrase fields'));
  }
  const mism = (d.links || []).filter(l => { try { return registrable(new URL(l.href).hostname) !== registrable(l.shown.replace(/^www\./, '')); } catch { return false; } }).slice(0, 2);
  mism.forEach(l => findings.push(f('medium', 'A link shows one address but goes to another', 'What you read is not where you’d land.', `${l.shown} → ${new URL(l.href).hostname}`)));
  if (d.hidden > 0) findings.push(f('low', 'Hidden frames on the page', 'Invisible embedded content is sometimes used to track or trick visitors.', `${d.hidden} hidden frame(s)`));
  return finish('page', s.host || 'this page', d.url, findings, good,
    ['How old this site is, or whether others have reported it', 'Whether it shows different content to other visitors', 'Who runs it'], U_STEPS);
}

export function unscannable(url) {
  return finish('page', 'this page', url || '', [], [], ['This page type can’t be read by extensions (for example browser pages or the web store).'],
    ['Open a normal website and try again, or paste a link or message below.']);
}

export function buildShareText(r, full = false) {
  const lines = [`🔎 SecondLook check: ${r.subject}. ${r.label}`, r.line, ''];
  if (r.findings.length) { lines.push('What looked off:'); r.findings.slice(0, 4).forEach(x => lines.push(`• ${x.title}: ${x.detail}`)); lines.push(''); }
  lines.push('Still unknown:'); r.unknowns.slice(0, 2).forEach(x => lines.push('• ' + x)); lines.push('');
  if (full && r.url) lines.push('Link: ' + r.url, '');
  lines.push('Before you trust it, check it. Checked with the SecondLook Chrome extension.');
  return lines.join('\n');
}
