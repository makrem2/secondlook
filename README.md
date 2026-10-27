# SecondLook

**Before you trust it, check it.**

SecondLook is a Chrome extension that helps you make safer decisions about things you meet online: suspicious links, job offers, deals, emails and text messages. It explains what looks suspicious, shows the evidence, says what it *can't* tell, and lets you share the findings with someone else.

It is not a general AI assistant. It does one job well.

## Features

- **Check the current page:** click the toolbar icon for an instant verdict.
- **Right-click to check:** a link, selected text, or a whole page.
- **Paste to check:** drop in a link, email, job offer or message you received elsewhere.
- **Evidence, not just a score:** every flag shows the exact snippet that triggered it.
- **Honest about limits:** a "What we can't tell" section, and it never claims something is "safe".
- **Safer next steps:** plain-language advice for what to do next.
- **Share the result:** copy or share a summary (domain only by default) with a friend or relative.

## What it looks for

| Area | Examples |
|---|---|
| Links | Look-alike brand names (`paypa1.com`), brand names on the wrong domain, `user@host` tricks, raw IP addresses, look-alike characters, URL shorteners, redirect parameters, no HTTPS |
| Messages and job offers | Gift card, wire or crypto payments, up-front fees, unrealistic pay, urgency, moving to WhatsApp or Telegram, requests for codes or IDs, secrecy, fake-check schemes |
| Pages | Forms sending data to a different site, passwords over HTTP, links that show one address but go to another, hidden frames |

## Install (developer mode)

1. Download or clone this repository.
2. Open `chrome://extensions` in Chrome.
3. Turn on **Developer mode**.
4. Click **Load unpacked** and select this folder (the one containing `manifest.json`).
5. Pin SecondLook to your toolbar.

## Privacy

All analysis runs on your device. SecondLook makes no network requests, has no accounts, and sends nothing anywhere. Permissions used: `activeTab` and `scripting` (read the page you click on), `contextMenus` (right-click options), `storage` (keeps your last report so the report tab can show it).

## Limitations

- Rule-based heuristics only. It will miss some scams and may flag some honest sites.
- It does not check domain age or reputation databases, and it does not open links to see where they lead.
- Treat results as a prompt to verify, not a final verdict.

## Project structure

```
manifest.json    extension config (Manifest V3)
analyzer.js      analysis engine (links, text, pages, share text)
scan.js          page data collector, injected on demand
background.js    right-click menus
popup.html/js    toolbar popup
report.html/js   full report and share panel
ui.js            safe rendering helpers
styles.css       shared styles (light and dark)
```

## Roadmap

- Shareable result page for people without the extension
- Domain age and reputation lookups
- Optional AI explanation for messages
- Larger brand list and local-language scam patterns

## Contributing

Issues and pull requests are welcome, especially new scam patterns with real-world examples (remove personal details first).

## License

MIT. See [LICENSE](LICENSE).
