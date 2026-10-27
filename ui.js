export function el(tag, cls, text) { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; }
const SEVLABEL = { high: 'Serious', medium: 'Warning', low: 'Minor' };

// Evidence comes from untrusted pages, so everything is inserted as text, never HTML.
export function render(root, r) {
  root.replaceChildren();
  const head = el('section', `verdict v-${r.level}`);
  head.append(el('p', 'subject', `Checked: ${r.subject}`), el('h2', 'label', r.label), el('p', 'line', r.line));
  root.append(head);
  if (r.findings.length) {
    const sec = el('section'); sec.append(el('h3', '', 'What looks suspicious'));
    const ul = el('ul', 'findings');
    for (const x of r.findings) {
      const li = el('li', `finding s-${x.sev}`);
      li.append(el('span', 'pill', SEVLABEL[x.sev]), el('strong', '', x.title), el('p', '', x.detail));
      if (x.evidence) li.append(el('code', '', x.evidence));
      ul.append(li);
    }
    sec.append(ul); root.append(sec);
  }
  if (r.good.length) { const sec = el('section'); sec.append(el('h3', '', 'What checks out')); const ul = el('ul', 'plain'); r.good.forEach(g => ul.append(el('li', '', g))); sec.append(ul); root.append(sec); }
  const unk = el('section', 'unknown'); unk.append(el('h3', '', 'What we can’t tell'));
  const ul2 = el('ul', 'plain'); r.unknowns.forEach(g => ul2.append(el('li', '', g))); unk.append(ul2); root.append(unk);
  const st = el('section'); st.append(el('h3', '', 'Safer next steps'));
  const ol = el('ul', 'plain'); r.steps.forEach(g => ol.append(el('li', '', g))); st.append(ol); root.append(st);
}
