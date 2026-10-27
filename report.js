import { render } from './ui.js';
import { buildShareText } from './analyzer.js';

const { lastReport: r } = await chrome.storage.local.get('lastReport');
const main = document.getElementById('report');
if (!r) { main.textContent = 'Nothing to show yet. Click the SecondLook icon on a page, or right-click a link.'; }
else {
  render(main, r);
  const box = document.getElementById('sharebox'), prev = document.getElementById('preview'), full = document.getElementById('full'), st = document.getElementById('status');
  box.hidden = false;
  full.disabled = !r.url;
  const sync = () => { prev.value = buildShareText(r, full.checked); };
  full.onchange = sync; sync();
  document.getElementById('copy').onclick = async () => { await navigator.clipboard.writeText(prev.value); st.textContent = 'Copied. Paste it into a chat or email.'; };
  if (navigator.share) { const b = document.getElementById('native'); b.hidden = false; b.onclick = () => navigator.share({ title: 'SecondLook check', text: prev.value }).catch(() => {}); }
}
