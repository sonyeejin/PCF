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
 // ---- 보조 함수들 ----

// WebGL 정보 수집 (GPU vendor/renderer, shader precision, 확장 리스트)
function collectWebGLInfo() {
  let info = {
    supported: false,
    vendor: null,
    renderer: null,
    shaderPrecision: {
      vertex: null,
      fragment: null,
    },
    extensions: null,
  };

  try {
    const canvas = document.createElement('canvas');
    const gl =
      canvas.getContext('webgl') ||
      canvas.getContext('experimental-webgl');

    if (!gl) return info;

    info.supported = true;

    // vendor / renderer
    const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
    if (debugInfo) {
      info.vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
      info.renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
    } else {
      info.vendor = gl.getParameter(gl.VENDOR);
      info.renderer = gl.getParameter(gl.RENDERER);
    }

    // shader precision (간단히 high float만)
    const vHigh = gl.getShaderPrecisionFormat(
      gl.VERTEX_SHADER,
      gl.HIGH_FLOAT
    );
    const fHigh = gl.getShaderPrecisionFormat(
      gl.FRAGMENT_SHADER,
      gl.HIGH_FLOAT
    );
    info.shaderPrecision.vertex = vHigh
      ? { precision: vHigh.precision, rangeMin: vHigh.rangeMin, rangeMax: vHigh.rangeMax }
      : null;
    info.shaderPrecision.fragment = fHigh
      ? { precision: fHigh.precision, rangeMin: fHigh.rangeMin, rangeMax: fHigh.rangeMax }
      : null;

    // 확장 리스트
    info.extensions = gl.getSupportedExtensions() || [];
  } catch (e) {
    // 실패해도 info 기본값 유지
  }

  return info;
}

// Canvas 렌더링 fingerprint (텍스트/도형 렌더링 결과 dataURL)
function collectCanvasFingerprint() {
  const result = {
    supported: false,
    dataURL: null,
  };

  try {
    const canvas = document.createElement('canvas');
    canvas.width = 300;
    canvas.height = 80;
    const ctx = canvas.getContext('2d');
    if (!ctx) return result;

    result.supported = true;

    // 배경
    ctx.fillStyle = '#f0f0f0';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // 텍스트 렌더링 (폰트/스타일 섞어서)
    ctx.textBaseline = 'top';
    ctx.font = "16px 'Arial'";
    ctx.fillStyle = '#000000';
    ctx.fillText('PCF Canvas FP 테스트 123', 10, 10);

    ctx.font = "16px 'Times New Roman'";
    ctx.fillStyle = '#ff0000';
    ctx.fillText('Canvas Fingerprint', 10, 35);

    // 간단 도형
    ctx.strokeStyle = '#0000ff';
    ctx.beginPath();
    ctx.arc(250, 40, 20, 0, Math.PI * 2);
    ctx.stroke();

    result.dataURL = canvas.toDataURL(); // 표에 적은 것처럼 dataURL 그대로
  } catch (e) {
    // 실패 시 기본값 유지
  }

  return result;
}

// Audio fingerprint (OfflineAudioContext 기반 처리 패턴 → digest)
async function collectAudioFingerprint() {
  const result = {
    supported: false,
    digest: null,
  };

  try {
    const OfflineCtx =
      window.OfflineAudioContext || window.webkitOfflineAudioContext;
    if (!OfflineCtx) return result;

    const sampleRate = 44100;
    const duration = 1.0; // 1초
    const frameCount = sampleRate * duration;

    const ctx = new OfflineCtx(1, frameCount, sampleRate);

    const osc = ctx.createOscillator();
    osc.type = 'sine';
    osc.frequency.value = 440;

    const gain = ctx.createGain();
    gain.gain.value = 0.5;

    osc.connect(gain);
    gain.connect(ctx.destination);

    osc.start(0);

    const rendered = await ctx.startRendering();
    const channelData = rendered.getChannelData(0);

    // 샘플 몇 개만 추려서 문자열로 → hash
    const step = 1000;
    let fingerprintStr = '';
    for (let i = 0; i < channelData.length; i += step) {
      fingerprintStr += channelData[i].toFixed(5) + ',';
    }

    result.supported = true;
    // sha256Hex 는 기존에 정의되어 있다고 가정
    result.digest = await sha256Hex(fingerprintStr);
  } catch (e) {
    // 실패 시 기본값 유지
  }

  return result;
}

// Installed Fonts: 후보 폰트 리스트에 대해 설치 여부 + digest
async function collectInstalledFonts() {
  const result = {
    fonts: {},
    digest: null,
  };

  try {
    const testFonts = [
      'Arial',
      'Times New Roman',
      'Courier New',
      'Roboto',
      'Noto Sans',
      'Noto Serif',
      'Noto Sans CJK KR',
      'Malgun Gothic',
    ];
    const baseFonts = ['monospace', 'serif', 'sans-serif'];

    const canvas = document.createElement('canvas');
    canvas.width = 200;
    canvas.height = 50;
    const ctx = canvas.getContext('2d');
    if (!ctx) return result;

    const text = 'abcdefghijkABCDEFGHIJK 12345 한글 테스트';

    function getWidth(font) {
      ctx.font = '20px ' + font;
      return ctx.measureText(text).width;
    }

    // 기본 폰트 폭
    const baseWidths = {};
    baseFonts.forEach((bf) => {
      baseWidths[bf] = getWidth(bf);
    });

    const installedFlags = {};

    testFonts.forEach((fontName) => {
      let installed = false;
      for (const bf of baseFonts) {
        const widthWithFont = getWidth("'" + fontName + "'," + bf);
        const widthBase = baseWidths[bf];
        if (widthWithFont !== widthBase) {
          installed = true;
          break;
        }
      }
      installedFlags[fontName] = installed;
    });

    result.fonts = installedFlags;
    // boolean 배열을 문자열로 만들어 digest
    const concat = Object.entries(installedFlags)
      .map(([name, flag]) => `${name}:${flag ? 1 : 0}`)
      .join('|');
    result.digest = await sha256Hex(concat);
  } catch (e) {
    // 실패 시 기본값 유지
  }

  return result;
}

// 브라우저 권한 상태 (noti / geo / camera / mic)
async function collectPermissions() {
  const result = {
    notifications: null,
    geolocation: null,
    camera: null,
    microphone: null,
  };

  if (!(navigator.permissions && navigator.permissions.query)) {
    return result;
  }

  async function queryPermission(name) {
    try {
      const status = await navigator.permissions.query({ name });
      return status.state; // 'granted' | 'denied' | 'prompt'
    } catch (e) {
      return null; // 지원 안 하거나 에러
    }
  }

  result.notifications = await queryPermission('notifications');
  result.geolocation = await queryPermission('geolocation');
  result.camera = await queryPermission('camera');     // 일부 브라우저만
  result.microphone = await queryPermission('microphone');

  return result;
}

// MediaDevices: audioinput / audiooutput / videoinput 개수
async function collectMediaDevices() {
  const result = {
    hasMediaDevices: false,
    audioInputCount: null,
    audioOutputCount: null,
    videoInputCount: null,
  };

  try {
    if (!(navigator.mediaDevices && navigator.mediaDevices.enumerateDevices)) {
      return result;
    }
    result.hasMediaDevices = true;

    const devices = await navigator.mediaDevices.enumerateDevices();
    let audioIn = 0;
    let audioOut = 0;
    let videoIn = 0;

    devices.forEach((d) => {
      if (d.kind === 'audioinput') audioIn += 1;
      else if (d.kind === 'audiooutput') audioOut += 1;
      else if (d.kind === 'videoinput') videoIn += 1;
    });

    result.audioInputCount = audioIn;
    result.audioOutputCount = audioOut;
    result.videoInputCount = videoIn;
  } catch (e) {
    // 실패 시 기본값 유지
  }

  return result;
}

// ---- 최종 Raw Fingerprint 빌더 ----
async function buildRawFingerprint() {
  // (4) 소프트웨어 정보
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

  // (2) 환경 설정 기반 지문
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

  // (3) 브라우저 기능/권한 기반 지문
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

  const webgl = collectWebGLInfo();
  const canvasFp = collectCanvasFingerprint();

  // async 로 필요한 애들 병렬 실행
  const [permissions, mediaDevices, audio, fonts] = await Promise.all([
    collectPermissions(),
    collectMediaDevices(),
    collectAudioFingerprint(),
    collectInstalledFonts(),
  ]);

  // 최종 raw fingerprint 객체
  return {
    browser,          // UA, language, languages
    device,           // platform, CPU 코어 수, 메모리
    screen: screenInfo,
    time,
    touch,
    privacy,          // DNT

    storage,          // local/session/indexedDB 지원 여부
    permissions,      // noti/geo/camera/mic 권한 상태
    mediaDevices,     // audioinput/audiooutput/videoinput 개수

    webgl,            // vendor/renderer, shader precision, 확장 리스트
    canvas: canvasFp, // 텍스트/도형 렌더링 dataURL
    audio,            // OfflineAudioContext 기반 digest
    fonts,            // 폰트 설치 여부 + digest
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

  const raw_fp = await buildRawFingerprint();
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
