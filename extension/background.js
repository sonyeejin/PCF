// background.js

console.log('[PCF Extension] background service worker loaded');

// PCF 백엔드 기본 URL (나중에 실제 서버 주소로 변경 가능)
const PCF_BACKEND_BASE_URL = 'http://localhost:3000';

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== 'PCF_REPORT_FP') {
    return; // 관심 없는 메시지는 무시
  }

  const payload = message.payload || {};
  console.log('[PCF Extension][BG] /report_fp 호출 준비 (raw payload):', payload);

  const {
    login_event_id,
    safe_fp,
    security_signal,
    local_classification,
  } = payload;

  // 설계서 기준으로 필요한 필드들 검증
  // login_event_id, safe_fp, security_signal, local_classification { is_bot, trust_score }
  if (
    !login_event_id ||
    !safe_fp ||
    !security_signal ||
    typeof local_classification !== 'object'
  ) {
    console.error(
      '[PCF Extension][BG] 잘못된 payload 형식:',
      payload
    );
    sendResponse({
      ok: false,
      error: 'Invalid payload for /report_fp',
    });
    return; // 이 경우는 동기 응답이므로 true 리턴 필요 없음
  }

  (async () => {
    try {
      const url = `${PCF_BACKEND_BASE_URL}/report_fp`;

      console.log('[PCF Extension][BG] /report_fp 요청 URL:', url);

      const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        // 보고서 스펙 그대로: login_event_id, safe_fp, security_signal, local_classification
        body: JSON.stringify({
          login_event_id,
          safe_fp,
          security_signal,
          local_classification,
        }),
      });

      const text = await resp.text();
      let data;
      try {
        data = JSON.parse(text);
      } catch (e) {
        data = { raw: text };
      }

      console.log(
        '[PCF Extension][BG] /report_fp 응답:',
        resp.status,
        data
      );

      sendResponse({
        ok: resp.ok,
        status: resp.status,
        data,
      });
    } catch (err) {
      console.error('[PCF Extension][BG] /report_fp 호출 실패:', err);
      sendResponse({
        ok: false,
        error: String(err),
      });
    }
  })();

  // 비동기 sendResponse 사용
  return true;
});
