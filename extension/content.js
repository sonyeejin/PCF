// content.js

// -----------------------
// 전역 컨텍스트 저장용 (백그라운드에서 받은 PCF 헤더 컨텍스트 사용)
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
  // 초기 점수
  let trust_score = 80;
  let is_bot = false;

  // UA / OS / 브라우저 버전
  const ua =
    (raw_fp &&
      raw_fp.browser &&
      typeof raw_fp.browser.userAgent === 'string' &&
      raw_fp.browser.userAgent) ||
    navigator.userAgent;
  const uaLower = String(ua).toLowerCase();

  const browser_major =
    security_signal && typeof security_signal.browser_major === 'number'
      ? security_signal.browser_major
      : null;

  const osStr = String(
    (security_signal && security_signal.os_major) || ''
  ).toLowerCase();

  const device = raw_fp.device || {};
  const hwThreads = device.hardwareConcurrency;

  const browser = raw_fp.browser || {};
  const languages = browser.languages || [];

  const privacy = raw_fp.privacy || {};
  const doNotTrack = privacy.doNotTrack;

  const storage = raw_fp.storage || {};
  const mediaDevices = raw_fp.mediaDevices || {};

  // -----------------------
  // (1) 강한 bot 신호 체크 → is_bot = true면 trust_score -60
  // -----------------------
  let strongBotSignal = false;

  // 1) webdriver 플래그
  if (navigator.webdriver) {
    strongBotSignal = true;
  }

  // 2) UA에 headless/selenium/puppeteer/... 키워드 포함
  if (!strongBotSignal) {
    const botKeywords = [
      'headless',
      'selenium',
      'puppeteer',
      'playwright',
      'phantomjs',
      'bot',
      'spider',
      'crawler',
    ];
    for (const kw of botKeywords) {
      if (uaLower.includes(kw)) {
        strongBotSignal = true;
        break;
      }
    }
  }

  // 3) 창 크기가 0인 비정상 환경
  if (
    !strongBotSignal &&
    (window.outerWidth === 0 || window.outerHeight === 0)
  ) {
    strongBotSignal = true;
  }

  // 4) 미디어/스토리지가 모두 막힌 것처럼 보이는 경우
  if (!strongBotSignal) {
    const storageBlocked =
      storage.localStorage === false &&
      storage.sessionStorage === false &&
      storage.indexedDB === false;
    const mediaBlocked = mediaDevices.hasMediaDevices === false;

    if (storageBlocked && mediaBlocked) {
      strongBotSignal = true;
    }
  }

  if (strongBotSignal) {
    trust_score -= 60;
    is_bot = true;
  }

  // -----------------------
  // (2) 기타 신호들: 각각 -10점씩
  //    - plugins/languages/storage, DNT, CPU 코어 비정상 등
  // -----------------------

  // 언어 정보 없음
  if (!languages || languages.length === 0) {
    trust_score -= 10;
  }

  // DNT 켜져 있음
  if (doNotTrack === '1') {
    trust_score -= 10;
  }

  // CPU 코어 정보 비정상 (없거나 너무 많음)
  if (typeof hwThreads !== 'number' || hwThreads >= 32) {
    trust_score -= 10;
  }

  // 스토리지 중 하나라도 비활성화(비정상)처럼 보이면 -10
  const storageWeird =
    storage.localStorage === false ||
    storage.sessionStorage === false ||
    storage.indexedDB === false;
  if (storageWeird) {
    trust_score -= 10;
  }

  // -----------------------
  // (3) 구버전 브라우저 (major < 100) → -10점
  // -----------------------
  if (typeof browser_major === 'number' && browser_major < 100) {
    trust_score -= 10;
  }

  // -----------------------
  // (4) 구버전 OS (Win7, OS X 10.x 등) → -10점
  // -----------------------
  if (
    osStr.includes('windows 7') ||
    osStr.includes('windows xp') ||
    osStr.includes('vista')
  ) {
    trust_score -= 10;
  } else if (osStr.startsWith('macos')) {
    const m = osStr.match(/macos\s+(\d+)/);
    if (m) {
      const major = parseInt(m[1], 10);
      if (major <= 10) {
        // macOS 10.x 계열은 구버전 취급
        trust_score -= 10;
      }
    }
  }

  // -----------------------
  // (5) 샌드박스 security_version 미준수 → -10점
  //     - "v1.x" 형태만 최신
  //     - "v0.x" 이거나 버전 누락/이상 → 구버전
  // -----------------------
  const ver = security_signal && security_signal.security_version;
  if (typeof ver !== 'string' || !ver.startsWith('v1.')) {
    trust_score -= 10;
  }

  // -----------------------
  // (6) 0~100 범위로 클램프 + 추가 is_bot 판정
  // -----------------------
  if (trust_score < 0) trust_score = 0;
  if (trust_score > 100) trust_score = 100;

  // 강한 bot 신호가 아니더라도, 점수가 너무 낮으면 봇으로 간주
  if (!is_bot && trust_score <= 30) {
    is_bot = true;
  }

  return { is_bot, trust_score };
}

// -----------------------
// 5. 백그라운드에서 PCF 헤더 컨텍스트 가져오기
//    (runSandbox, loginEventId, domainSalt)
// -----------------------
async function fetchPcfContextFromBackground() {
  return new Promise((resolve) => {
    if (
      typeof chrome === 'undefined' ||
      !chrome.runtime ||
      !chrome.runtime.sendMessage
    ) {
      console.warn('[PCF Extension] chrome.runtime.sendMessage 사용 불가');
      resolve(null);
      return;
    }

    chrome.runtime.sendMessage(
      { type: 'PCF_GET_CONTEXT' },
      (response) => {
        if (!response || !response.ok) {
          console.warn(
            '[PCF Extension] PCF_GET_CONTEXT 실패:',
            response && response.error
          );
          resolve(null);
          return;
        }

        console.log(
          '[PCF Extension] PCF_GET_CONTEXT 성공, context:',
          response.context
        );
        resolve(response.context); // { runSandbox, loginEventId, domainSalt }
      }
    );
  });
}

// -----------------------
// 6. 샌드박스 실행 (백그라운드 컨텍스트 사용)
// -----------------------
async function runSandboxWithContext(ctx) {
  console.log(
    '[PCF Extension] runSandboxWithContext on',
    window.location.href
  );

  if (!ctx) {
    console.log('[PCF Extension] PCF context 없음 → 샌드박스 실행 안 함');
    return;
  }

  if (!ctx.runSandbox) {
    console.log('[PCF Extension] runSandbox=false → 샌드박스 실행 안 함');
    return;
  }

  console.log('[PCF Extension] 사용 PCF 컨텍스트(헤더 기반):', ctx);

  const raw_fp = buildRawFingerprint();
  console.log('[PCF Extension] raw_fp:', raw_fp);

  // safe_fp = SHA-256(JSON.stringify(raw_fp) + domainSalt)
  const rawString = JSON.stringify(raw_fp);
  const domainSalt = String(ctx.domainSalt || '');
  const hashInput = rawString + domainSalt;
  const safe_fp = await sha256Hex(hashInput);

  const security_signal = buildSecuritySignal(raw_fp);
  const local_classification = computeLocalClassification(
    raw_fp,
    security_signal
  );

  // /report_fp로 보낼 payload
  const payload = {
    login_event_id: ctx.loginEventId,
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
// 7. 초기화: 로딩 시 백그라운드에서 컨텍스트 받아와서 샌드박스 실행 시도
// -----------------------
console.log('[PCF Extension] content.js loaded on', window.location.href);

(async () => {
  try {
    const ctx = await fetchPcfContextFromBackground();
    pcfContext = ctx;
    await runSandboxWithContext(ctx);
  } catch (e) {
    console.error('[PCF Extension] 초기 샌드박스 실행 실패:', e);
  }
})();
