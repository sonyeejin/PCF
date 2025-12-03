// content.js

// -----------------------
// 전역 컨텍스트 저장용 (페이지 PCF_CONTEXT만 사용)
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
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
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

  const touch = {
    hasTouch:
      'ontouchstart' in window || (navigator.maxTouchPoints || 0) > 0,
    maxTouchPoints: navigator.maxTouchPoints || 0,
  };

  const privacy = {
    doNotTrack: navigator.doNotTrack || null,
  };

  // storage 지원 여부만 간단 체크
  const storage = {
    localStorage: (() => {
      try {
        return !!window.localStorage;
      } catch (e) {
        return false;
      }
    })(),
    sessionStorage: (() => {
      try {
        return !!window.sessionStorage;
      } catch (e) {
        return false;
      }
    })(),
    indexedDB: typeof indexedDB !== 'undefined',
  };

  // permissions API 존재 여부만
  const permissions = {
    hasPermissionsApi: !!(navigator.permissions && navigator.permissions.query),
  };

  const mediaDevices = {
    hasMediaDevices:
      !!(navigator.mediaDevices && navigator.mediaDevices.enumerateDevices),
    deviceCount: null,
  };

  // 간단 WebGL 지원 여부
  let webglSupported = false;
  try {
    const canvas = document.createElement('canvas');
    const gl =
      canvas.getContext('webgl') ||
      canvas.getContext('experimental-webgl');
    webglSupported = !!gl;
  } catch (e) {
    webglSupported = false;
  }
  const webgl = { supported: webglSupported };

  // Canvas 렌더링 지원 여부만 체크
  let canvasSupported = false;
  try {
    const canvasEl = document.createElement('canvas');
    canvasSupported = !!canvasEl.getContext('2d');
  } catch (e) {
    canvasSupported = false;
  }
  const canvas = { supported: canvasSupported };

  const audio = {
    hasOfflineAudioContext: !!(
      window.OfflineAudioContext || window.webkitOfflineAudioContext
    ),
  };

  // 실제 폰트 fingerprinting 은 placeholder
  const fonts = { placeholder: true };

  return {
    browser,
    device,
    screen: screenInfo,
    time,
    touch,
    privacy,
    storage,
    permissions,
    mediaDevices,
    webgl,
    canvas,
    audio,
    fonts,
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

  // 브라우저 메이저 버전이 너무 낮으면 감점
  if (typeof bm === 'number' && bm < 100) {
    trust_score -= 20;
  }

  // 구식 OS 감점
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

  // CPU 코어 수가 너무 많거나 알 수 없을 때
  if (typeof hwThreads === 'number') {
    if (hwThreads >= 32) {
      trust_score -= 10;
    }
  } else {
    trust_score -= 5;
  }

  // 언어 정보 없음 → 감점
  if (!languages || languages.length === 0) {
    trust_score -= 10;
  }

  // DNT 켜져 있으면 약간 감점
  if (doNotTrack === '1') {
    trust_score -= 5;
  }

  // webdriver 감지 → 봇 강한 신호
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
// 5. 샌드박스 실행 (PCF_CONTEXT만 사용)
//    ⚠ 헤더(X-PCF-Run-Sandbox)는 background에서만 사용하고,
//      content.js는 오직 pcfContext.run_sandbox 로만 실행 여부 체크
// -----------------------
async function runSandboxIfNeeded() {
  console.log(
    '[PCF Extension] content.js runSandboxIfNeeded on',
    window.location.href
  );

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

  // safe_fp = SHA-256(JSON.stringify(raw_fp) + domain_salt)
  const rawString = JSON.stringify(raw_fp);
  const domainSalt = String(ctx.domain_salt || '');
  const hashInput = rawString + domainSalt;
  const safe_fp = await sha256Hex(hashInput);

  const security_signal = buildSecuritySignal(raw_fp);
  const local_classification = computeLocalClassification(
    raw_fp,
    security_signal
  );

  // /report_fp로 보낼 payload
  const payload = {
    login_event_id: ctx.login_event_id,
    safe_fp,
    security_signal,
    local_classification,
  };

  console.log('[PCF Extension] /report_fp payload 준비:', payload);

  if (
    typeof chrome !== 'undefined' &&
    chrome.runtime &&
    chrome.runtime.sendMessage
  ) {
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
//    (페이지가 보낸 PCF_CONTEXT만 사용)
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
// 7. 로딩 로그 + HELLO (PCF_CONTEXT 요청)
// -----------------------
console.log('[PCF Extension] content.js loaded on', window.location.href);

try {
  // 페이지에게 "PCF_CONTEXT 있으면 보내라"는 신호
  window.postMessage(
    { type: 'PCF_EXTENSION_HELLO' },
    '*'
  );
  console.log('[PCF Extension] PCF_EXTENSION_HELLO 전송');
} catch (e) {
  console.error('[PCF Extension] HELLO 전송 실패:', e);
}
