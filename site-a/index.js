// site-a/index.js

const express = require('express');

const app = express();
const PORT = 4000;                            // Site A 서버 포트
const PCF_BASE_URL = 'http://localhost:3000'; // PCF 백엔드 주소
const SITE_DOMAIN = 'a.com';                  // 보고서 기준 domain

// Node 18+ (global fetch) 기준

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

/**
 * GET /
 */
app.get('/', (req, res) => {
  res.send(`
    <html>
      <head><title>Site A - Home</title></head>
      <body>
        <h1>Welcome to Site A</h1>
        <a href="/login"><button>로그인 하기</button></a>
      </body>
    </html>
  `);
});

/**
 * GET /login (폼)
 */
app.get('/login', (req, res) => {
  res.send(`
    <html>
      <head><title>Site A Login</title></head>
      <body>
        <h1>Site A Login</h1>
        <form method="POST" action="/login">
          <label>Username: <input name="username" /></label><br/>
          <label>Password: <input type="password" name="password" /></label><br/>
          <button type="submit">Login</button>
        </form>
      </body>
    </html>
  `);
});

/**
 * POST /login
 *  - 로그인 성공 후 PCF /evaluate_login 호출
 *  - 보고서 스펙대로 user_token, domain, login_ip 만 전달
 *  - PCF 백엔드는 login_event_id, domain_salt, run_sandbox 를
 *    전부 응답 헤더(X-PCF-*)에 넣어서 돌려줌 (JSON 바디는 옵션)
 *  - 이 서비스 서버는 그 헤더들을 "재구성 없이" 그대로 복사해서
 *    브라우저 응답 헤더로 전달
 *  - HTML 본문은 단순 로그인 성공 페이지만 내려보냄
 */
app.post('/login', async (req, res) => {
  const { username } = req.body || {};

  if (!username) {
    return res.status(400).send('username is required');
  }

  const user_token = `user-${username}`;
  const domain = SITE_DOMAIN;
  const login_ip = req.ip || '127.0.0.1';

  console.log('[Site-A] Call /evaluate_login (headers-only mode):', {
    user_token,
    domain,
    login_ip
  });

  // ---------- PCF /evaluate_login ----------
  let pcfResp;
  try {
    pcfResp = await fetch(`${PCF_BASE_URL}/evaluate_login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_token,
        domain,
        login_ip,
      }),
    });
  } catch (err) {
    console.error('[Site-A] Error calling PCF:', err);
    return res.status(500).send('Failed to call PCF backend');
  }

  if (!pcfResp.ok) {
    const errText = await pcfResp.text().catch(() => '(no body)');
    console.error('[Site-A] PCF error:', pcfResp.status, errText);
    return res.status(500).send('PCF evaluate_login failed');
  }

  // ---------- PCF 응답 헤더에서 값 읽기 ----------
  const pcfHeaders = pcfResp.headers;
  const login_event_id = pcfHeaders.get('X-PCF-Login-Event-Id');
  const domain_salt    = pcfHeaders.get('X-PCF-Domain-Salt');
  const run_sandbox    = pcfHeaders.get('X-PCF-Run-Sandbox');


  console.log('[Site-A] PCF headers from backend:', {
    login_event_id,
    domain_salt,
    run_sandbox,
  });

  // 필수 헤더가 없으면 에러 처리
  if (!login_event_id || domain_salt === null || run_sandbox === null) {
    console.error('[Site-A] Missing required PCF headers from backend');
    return res.status(500).send('Invalid PCF evaluate_login response (headers)');
  }

  // ---------- (A) PCF 헤더를 그대로 브라우저 응답 헤더로 복사 ----------
  // 여기서는 "재구성 없이" 그대로 전달한다는 컨셉으로,
  // 이름/값을 그냥 그대로 세팅한다.
  res.set('X-PCF-Login-Event-Id', login_event_id);
  res.set('X-PCF-Domain-Salt', domain_salt);
  res.set('X-PCF-Run-Sandbox', run_sandbox);

  // ---------- (B) 로그인 성공 HTML 본문 ----------
  // PCF_CONTEXT 스크립트는 제거하고, 단순한 UI만 렌더링.
  // 샌드박스에 필요한 값들은 전부 헤더에 있으므로,
  // 확장(background + content)이 헤더/메시지로 처리한다.
  const html = `
    <html>
      <head><title>Site A</title></head>
      <body>
        <h1>Welcome, ${username}!</h1>
        <p>로그인 성공 (PCF 샌드박스는 브라우저 확장이 백그라운드/컨텐트에서 처리)</p>
      </body>
    </html>
  `;

  return res.send(html);
});

app.listen(PORT, () => {
  console.log(`Site A server running at http://localhost:${PORT}`);
});
