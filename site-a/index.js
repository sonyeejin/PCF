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
 *  - 응답(login_event_id, domain_salt, run_sandbox)을
 *      1) HTTP 헤더에는 **X-PCF-Run-Sandbox 하나만** 넣어서
 *         확장이 "샌드박스 실행 여부"만 판단하도록 하고
 *      2) 페이지 PCF_CONTEXT(본문 스크립트) 안에
 *         login_event_id, domain_salt, run_sandbox 를 전부 넣어
 *         content script가 /report_fp 계산에 사용하도록 함
 *  - ❗ 페이지 PCF_CONTEXT에는 domain 넣지 않음 (요청 받은 대로)
 */
app.post('/login', async (req, res) => {
  const { username } = req.body || {};

  if (!username) {
    return res.status(400).send('username is required');
  }

  const user_token = `user-${username}`;
  const domain = SITE_DOMAIN;
  const login_ip = req.ip || '127.0.0.1';

  console.log('[Site-A] Call /evaluate_login with (REPORT SPEC ONLY):', {
    user_token,
    domain,
    login_ip
  });

  // ---------- PCF /evaluate_login ----------
  let pcfResponseJson;
  try {
    const pcfResp = await fetch(`${PCF_BASE_URL}/evaluate_login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_token,
        domain,
        login_ip
      })
    });

    if (!pcfResp.ok) {
      const errText = await pcfResp.text();
      console.error('[Site-A] PCF error:', pcfResp.status, errText);
      return res.status(500).send('PCF evaluate_login failed');
    }

    pcfResponseJson = await pcfResp.json();
  } catch (err) {
    console.error('[Site-A] Error calling PCF:', err);
    return res.status(500).send('Failed to call PCF backend');
  }

  const { login_event_id, domain_salt, run_sandbox } = pcfResponseJson || {};

  if (!login_event_id || domain_salt === undefined) {
    console.error('[Site-A] Invalid PCF response:', pcfResponseJson);
    return res.status(500).send('Invalid PCF evaluate_login response');
  }

  const runSandboxBool = Boolean(run_sandbox);

  console.log('[Site-A] PCF_CONTEXT → extension:', {
    login_event_id,
    run_sandbox: runSandboxBool,
    domain_salt
  });

  // ---------- (A) HTTP 헤더 전달 ----------
  // 🔹 헤더에는 X-PCF-Run-Sandbox 하나만 넣는다.
  res.set('X-PCF-Run-Sandbox', runSandboxBool ? '1' : '0');

  // 🔸 더 이상 아래 헤더들은 보내지 않음:
  // res.set('X-PCF-Login-Event-Id', String(login_event_id));
  // res.set('X-PCF-Domain-Salt', String(domain_salt));
  // res.set('X-PCF-Domain', domain);

  // ---------- (B) 페이지 PCF_CONTEXT ----------
  // domain 없음
  const html = `
    <html>
      <head><title>Site A</title></head>
      <body>
        <h1>Welcome, ${username}!</h1>

        <script>
          (function() {
            const pcfContext = {
              login_event_id: ${JSON.stringify(login_event_id)},
              run_sandbox: ${JSON.stringify(runSandboxBool)},
              domain_salt: ${JSON.stringify(domain_salt)}
            };

            console.log("Page PCF_CONTEXT:", pcfContext);

            // HELLO 받으면 CONTEXT 전송
            window.addEventListener("message", function(ev) {
              if (ev.source !== window) return;
              if (!ev.data || ev.data.type !== "PCF_EXTENSION_HELLO") return;

              console.log("HELLO → send PCF_CONTEXT");
              window.postMessage({ type: "PCF_CONTEXT", pcf: pcfContext }, "*");
            });

            // 확장이 늦게 붙을 경우 대비: 1초 뒤에도 한 번 더 전송
            setTimeout(() => {
              console.log("proactive PCF_CONTEXT");
              window.postMessage({ type: "PCF_CONTEXT", pcf: pcfContext }, "*");
            }, 1000);
          })();
        </script>
      </body>
    </html>
  `;

  return res.send(html);
});

app.listen(PORT, () => {
  console.log(`Site A server running at http://localhost:${PORT}`);
});
