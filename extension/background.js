// background.js 

console.log('[PCF Extension] background service worker loaded');

// PCF 백엔드 기본 URL (나중에 실제 서버 주소로 변경 가능)
const PCF_BACKEND_BASE_URL = 'http://localhost:3000';

// 탭별 run_sandbox 플래그 저장용
// - key: tabId
// - value: boolean (true → 샌드박스 허용, false → 비허용)
const runSandboxByTab = {};

// -----------------------
// 1. 응답 헤더 후킹: X-PCF-Run-Sandbox 읽기
// -----------------------
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    const headers = details.responseHeaders || [];
    const h = headers.find(
      (hdr) => hdr.name && hdr.name.toLowerCase() === 'x-pcf-run-sandbox'
    );
    if (!h) return;

    const flag = h.value === '1';
    runSandboxByTab[details.tabId] = flag;

    console.log('[PCF Extension][BG] X-PCF-Run-Sandbox 감지:', {
      tabId: details.tabId,
      value: h.value,
      run_sandbox: flag,
      url: details.url,
    });
  },
  {
    urls: ['<all_urls>'],    // 필요 시 http://localhost:4000/* 로 좁혀도 됨
    types: ['main_frame'],   // 메인 문서 응답만
  },
  ['responseHeaders']
);

// -----------------------
// 2. content.js → /report_fp 요청 처리
// -----------------------
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

  // -----------------------
  // (A) run_sandbox 헤더 기반 탭 검증
  // -----------------------
  const tabId = sender && sender.tab && sender.tab.id;
  if (typeof tabId === 'number') {
    const allowed = runSandboxByTab[tabId];

    // 헤더에서 run_sandbox=1 이었던 탭이 아니면 리포트 거부
    if (!allowed) {
      console.warn(
        '[PCF Extension][BG] run_sandbox=false 또는 헤더 없음 → /report_fp 무시:',
        { tabId, allowed }
      );
      sendResponse({
        ok: false,
        error:
          'run_sandbox flag is false or missing for this tab; /report_fp blocked',
      });
      return; // 동기 종료
    }
  } else {
    console.warn(
      '[PCF Extension][BG] sender.tab 정보 없음 → run_sandbox 검증 생략'
    );
  }

  // -----------------------
  // (B) payload 형식 검증
  // -----------------------
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

  // -----------------------
  // (C) /report_fp 비동기 호출
  // -----------------------
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
