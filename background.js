import { analyzeUrl, analyzeText, analyzePage, unscannable } from './analyzer.js';
import { collectPage } from './scan.js';

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => {
    [['sl-link', 'Check this link with SecondLook', ['link']],
     ['sl-sel', 'Check selected text with SecondLook', ['selection']],
     ['sl-page', 'Check this page with SecondLook', ['page']]]
      .forEach(([id, title, contexts]) => chrome.contextMenus.create({ id, title, contexts }));
  });
});

async function open(result) {
  await chrome.storage.local.set({ lastReport: result });
  chrome.tabs.create({ url: chrome.runtime.getURL('report.html') });
}

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === 'sl-link') return open(analyzeUrl(info.linkUrl));
  if (info.menuItemId === 'sl-sel') return open(analyzeText(info.selectionText || ''));
  if (info.menuItemId === 'sl-page') {
    try {
      const [{ result }] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: collectPage });
      open(analyzePage(result));
    } catch { open(unscannable(tab?.url)); }
  }
});
