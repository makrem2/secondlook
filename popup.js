import { analyzeUrl, analyzeText, analyzePage, unscannable } from './analyzer.js';
import { collectPage } from './scan.js';
import { render } from './ui.js';

const root = document.getElementById('result'), openBtn = document.getElementById('open');
let current = null;

function show(r) { current = r; render(root, r); openBtn.hidden = false; }

async function scanPage() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  try {
    if (!/^https?:/.test(tab?.url || '')) throw new Error('unsupported');
    const [{ result }] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: collectPage });
    show(analyzePage(result));
  } catch { show(unscannable(tab?.url)); }
}

document.getElementById('check').onclick = () => {
  const t = document.getElementById('input').value.trim();
  if (!t) return;
  const looksUrl = /^\S+$/.test(t) && /^(https?:\/\/|www\.)|^[\w-]+(\.[\w-]+)+(\/|$)/i.test(t);
  show(looksUrl ? analyzeUrl(/^https?:/i.test(t) ? t : 'https://' + t) : analyzeText(t));
};
openBtn.onclick = async () => {
  await chrome.storage.local.set({ lastReport: current });
  chrome.tabs.create({ url: chrome.runtime.getURL('report.html') });
};
scanPage();
