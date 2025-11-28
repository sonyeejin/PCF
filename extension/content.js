// content.js

// -----------------------
// 전역 컨텍스트 저장용
// -----------------------
let pcfContext = null;

// -----------------------
// 1. 유틸: SHA-256 해시 → hex
// -----------------------
async function sha256Hex(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// -----------------------
// 2. 원시 fingerprint 수집
// -----------------------
function buildRawFingerprint() {
  const browser = {
    userAgent: navigator.userAgent,
    language: navigator.language,
    languages: navigator.languages,
  };

  const device = {
    platform: navigator.platform,
    hardwareConcurrency: navigator.hardwareConcurrency,
    deviceMemory: navigator.deviceMemory || null,
  };

  const screenInfo = {
    width: window.screen.width,
    height: window.screen.height,
    colorDepth: window.screen.colorDepth,
    pixelRatio: window.devicePixelRatio || 1,
  };

  const time = {
    timezoneOffset: new Date().getTimezoneOffset(),
    timezone:
      (Intl.DateTimeFormat().resolvedOptions &&
        Intl.DateTimeFormat().resolvedOptions().timeZone) ||
      null,
  };

  const privacy = {
    doNotTrack: navigator.doNotTrack || null,
  };

  return {
    browser,
    device,
    screen: screenInfo,
    time,
    privacy,
  };
}

// -----------------------
// 3. 저해상도 security_signal 생성
// -----------------------
function getBrowserMajorFromUa(ua) {
  if (typeof ua !== 'string') ua = navigator.userAgent;
  const m = ua.match(/Chrome\/(\d+)/);
  if (m) return parseInt(m[1], 10);
  return null;
}

function getOsMajorFromUa(ua) {
  if (typeof ua !== 'string') ua = navigator.userAgent;
  const low = ua.toLowerCase();

  if (low.includes('windows nt 11')) return 'Windows 11';
  if (low.includes('windows nt 10')) return 'Windows 10';
  if (low.includes('windows nt 6.1')) return 'Windows 7';
  if (low.includes('windows nt 6.0')) return 'Windows Vista';
  if (low.includes('windows nt 5.1')) return 'Windows XP';

  if (low.includes('mac os x')) {
    const m = low.match(/mac os x (\d+)_(\d+)/);
    if (m) return `macOS ${m[1]}.${m[2]}`;
    return 'macOS (unknown)';
  }

  if (low.includes('linux')) return 'Linux';
  return 'Unknown OS';
}

function buildSecuritySignal(raw_fp) {
  const ua =
    (raw_fp &&
      raw_fp.browser &&
      typeof raw_fp.browser.userAgent === 'string' &&
      raw_fp.browser.userAgent) ||
    navigator.userAgent;

  const browser_major = getBrowserMajorFromUa(ua);
  const os_major = getOsMajorFromUa(ua);
  const security_version = 'v1.0.0';

  return {
    browser_major,
    os_major,
    security_version,
  };
}

// -----------------------
// 4. local_classification 계산
// -----------------------
function computeLocalClassification(raw_fp, security_signal) {
  let trust_score = 80;
  let is_bot = false;

  const bm = security_signal.browser_major;
  const os = (security_signal.os_major || '').toLowerCase();

  const device = raw_fp.device || {};
  const hwThreads = device.hardwareConcurrency;
  const browser = raw_fp.browser || {};
  const languages = browser.languages || [];
  const privacy = raw_fp.privacy || {};
  const doNotTrack = privacy.doNotTrack;

  if (typeof bm === 'number' && bm < 100) {
    trust_score -= 20;
  }

  if (os.includes('windows 7') || os.includes('vista') || os.includes('xp')) {
    trust_score -= 20;
  }
  if (os.startsWith('macos')) {
    const m = os.match(/macos\s+(\d+)/);
    if (m) {
      const major = parseInt(m[1], 10);
      if (major < 11) {
        trust_score -= 10;
      }
    }
  }

  if (typeof hwThreads === 'number') {
    if (hwThreads >= 32) {
      trust_score -= 10;
    }
  } else {
    trust_score -= 5;
  }

  if (!languages || languages.length === 0) {
    trust_score -= 10;
  }

  if (doNotTrack === '1') {
    trust_score -= 5;
  }

  if (navigator.webdriver) {
    trust_score -= 40;
  }

  if (trust_score < 0) trust_score = 0;
  if (trust_score > 100) trust_score = 100;

  if (trust_score <= 30 || navigator.webdriver) {
    is_bot = true;
  }

  return { is_bot, trust_score };
}

// -----------------------
// 5. 샌드박스 실행 (PCF 컨텍스트 필요)
// -----------------------
async function runSandboxIfNeeded() {
  console.log('[PCF Extension] content.js loaded on', window.location.href);

  const ctx = pcfContext;
  if (!ctx) {
    console.log('[PCF Extension] 아직 PCF context 없음, 대기');
    return;
  }

  if (!ctx.run_sandbox) {
    console.log('[PCF Extension] run_sandbox=false → 샌드박스 실행 안 함');
    return;
  }

  console.log('[PCF Extension] 사용 PCF_CONTEXT:', ctx);

  const raw_fp = buildRawFingerprint();
  console.log('[PCF Extension] raw_fp:', raw_fp);

  const rawString = JSON.stringify(raw_fp);
  const salted = String(ctx.domain_salt || '') + '|' + rawString;
  const fullHex = await sha256Hex(salted);
  const safe_fp = 'fp-' + fullHex.slice(0, 32);

  const security_signal = buildSecuritySignal(raw_fp);
  const local_classification = computeLocalClassification(raw_fp, security_signal);

  const payload = {
    login_event_id: ctx.login_event_id,
    domain: ctx.domain,
    safe_fp,
    local_classification,
    security_signal,
  };

  console.log('[PCF Extension] /report_fp payload 준비:', payload);

  if (chrome && chrome.runtime && chrome.runtime.sendMessage) {
    chrome.runtime.sendMessage(
      {
        type: 'PCF_REPORT_FP',
        payload,
      },
      (response) => {
        console.log('[PCF Extension] background 응답:', response);
      }
    );
  } else {
    console.warn('[PCF Extension] chrome.runtime.sendMessage 사용 불가');
  }
}

// -----------------------
// 6. 페이지 → content.js 메시지 수신
// -----------------------
window.addEventListener('message', (event) => {
  // 같은 페이지에서 온 메시지만 처리
  if (event.source !== window) return;
  if (!event.data || event.data.type !== 'PCF_CONTEXT') return;

  pcfContext = event.data.pcf;
  console.log('[PCF Extension] PCF_CONTEXT 받음:', pcfContext);

  // context를 받은 뒤 샌드박스 실행
  runSandboxIfNeeded().catch((err) =>
    console.error('[PCF Extension] runSandboxIfNeeded error:', err)
  );
});

// -----------------------
// 7. 로딩 로그
// -----------------------
console.log('[PCF Extension] content.js loaded on', window.location.href);

// 8. 페이지에 "나 준비됨" 신호 보내기
try {
    window.postMessage(
      {type: 'PCF_EXTENSION_HELLO'},
      '*'
    );
    console.log('[PCF Extension] PCF_EXTENSION_HELLO 전송');
  } catch (e) {
    console.error('[PCF Extension] HELLO 전송 실패:', e);
  }
