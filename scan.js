// Injected into the active tab on demand. Must be self-contained.
export function collectPage() {
  const forms = [...document.forms].slice(0, 10).map(fm => ({
    action: fm.action || location.href,
    pw: !!fm.querySelector('input[type=password]'),
    fields: [...fm.querySelectorAll('input,select')].map(i => `${i.name} ${i.id} ${i.autocomplete || ''} ${i.placeholder || ''}`).join(' ').toLowerCase().slice(0, 500)
  }));
  const links = [];
  for (const a of document.querySelectorAll('a[href]')) {
    const m = (a.textContent || '').trim().match(/^(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:\/|$)/i);
    if (m) links.push({ shown: m[1].toLowerCase(), href: a.href });
    if (links.length >= 15) break;
  }
  const hidden = [...document.querySelectorAll('iframe')].filter(i => { const r = i.getBoundingClientRect(); return r.width < 3 || r.height < 3; }).length;
  return { url: location.href, title: document.title, forms, links, hidden, text: (document.body?.innerText || '').slice(0, 6000) };
}
