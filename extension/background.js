// background.js

console.log('[PCF Extension] background service worker loaded');

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'PCF_REPORT_FP') {
    const payload = message.payload;
    console.log('[PCF Extension][BG] /report_fp 호출 준비:', payload);

    fetch('http://localhost:3000/report_fp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    })
      .then(async (resp) => {
        const text = await resp.text();
        let data;
        try {
          data = JSON.parse(text);
        } catch {
          data = { raw: text };
        }

        console.log('[PCF Extension][BG] /report_fp 응답:', resp.status, data);
        sendResponse({ ok: resp.ok, status: resp.status, data });
      })
      .catch((err) => {
        console.error('[PCF Extension][BG] /report_fp 호출 실패:', err);
        sendResponse({ ok: false, error: String(err) });
      });

    // 비동기 응답을 위해 true 리턴
    return true;
  }
});
