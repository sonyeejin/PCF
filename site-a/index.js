// site-a/index.js

const express = require('express');
// Node 18+ 이면 fetch 내장이라 따로 node-fetch 필요 없음

const app = express();
const PORT = 4000;                       // Site A 서버 포트
const PCF_BASE_URL = 'http://localhost:3000'; // PCF 백엔드 주소

// 폼 데이터 파싱 (username / password 받기)
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

/**
 * 1) GET /  → 사이트 A 홈
 */
app.get('/', (req, res) => {
  res.send(`
    <html>
      <head><title>Site A - Home</title></head>
      <body>
        <h1>Welcome to Site A</h1>
        <p>사이트 A 메인 페이지입니다.</p>
        <a href="/login"><button>로그인 하기</button></a>
      </body>
    </html>
  `);
});

/**
 * 2) GET /login  → 로그인 폼
 */
app.get('/login', (req, res) => {
  const html = `
    <html>
      <head><title>Site A Login</title></head>
      <body>
        <h1>Site A - Login</h1>
        <form method="POST" action="/login">
          <label>
            Username:
            <input name="username" />
          </label>
          <br />
          <label>
            Password:
            <input type="password" name="password" />
          </label>
          <br />
          <button type="submit">Login</button>
        </form>
      </body>
    </html>
  `;
  res.send(html);
});

/**
 * 3) POST /login
 *  - 로그인 성공했다고 가정하고 PCF에 /evaluate_login 호출
 *  - 응답(login_event_id, domain_salt 등)을 페이지에 심고
 *  - content.js 와 HELLO ↔ CONTEXT 핸드셰이크
 */
app.post('/login', async (req, res) => {
  const { username, password } = req.body || {};

  // (데모용) username 없으면 에러, 있으면 무조건 로그인 성공
  if (!username) {
    return res.status(400).send('username is required');
  }

  const user_token = `user-${username}`; // 실제라면 DB user id / UUID
  const domain = 'a.com';
  const login_ip = req.ip || '1.2.3.4';

  console.log('[Site-A] Login success for', username);
  console.log('[Site-A] Call PCF /evaluate_login with', {
    user_token,
    domain,
    login_ip,
  });

  // PCF /evaluate_login 호출
  let pcfResponseJson;
  try {
    const pcfResp = await fetch(`${PCF_BASE_URL}/evaluate_login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_token,
        domain,
        login_ip,
      }),
    });

    if (!pcfResp.ok) {
      const text = await pcfResp.text();
      console.error('[Site-A] PCF /evaluate_login error:', pcfResp.status, text);
      return res.status(500).send('PCF evaluate_login failed');
    }

    pcfResponseJson = await pcfResp.json();
  } catch (err) {
    console.error('[Site-A] Error calling PCF /evaluate_login:', err);
    return res.status(500).send('Failed to call PCF backend');
  }

  console.log('[Site-A] PCF /evaluate_login response:', pcfResponseJson);

  const {
    login_event_id,
    run_sandbox,
    domain: pcfDomain,
    domain_salt,
  } = pcfResponseJson;

  // 로그인 후 페이지 HTML
  const html = `
    <html>
      <head><title>Site A - Home</title></head>
      <body>
        <h1>Welcome, ${username}!</h1>

        <p>로그인에 성공했습니다. 이제 PCF 샌드박스가 필요한 경우 브라우저 확장이 동작하게 됩니다.</p>

        <h2>PCF Context (for extension)</h2>
        <pre>${JSON.stringify(
          {
            login_event_id,
            run_sandbox,
            domain: pcfDomain,
            domain_salt,
            user_token,
          },
          null,
          2
        )}</pre>

        <script>
          (function() {
            // 페이지에서 알고 있는 PCF 컨텍스트
            const pcfContext = {
              login_event_id: ${JSON.stringify(login_event_id)},
              run_sandbox: ${JSON.stringify(run_sandbox)},
              domain: ${JSON.stringify(pcfDomain)},
              domain_salt: ${JSON.stringify(domain_salt)},
              user_token: ${JSON.stringify(user_token)}
            };

            console.log('PCF_CONTEXT set (page):', pcfContext);

            // content.js 가 "HELLO" 를 보내면, 그때 PCF_CONTEXT 를 돌려준다
            window.addEventListener('message', function(event) {
              if (event.source !== window) return;
              if (!event.data || event.data.type !== 'PCF_EXTENSION_HELLO') return;

              console.log('PCF_EXTENSION_HELLO received, sending PCF_CONTEXT');
              window.postMessage(
                {
                  type: 'PCF_CONTEXT',
                  pcf: pcfContext
                },
                '*'
              );
            });
          })();
        </script>
      </body>
    </html>
  `;

  return res.send(html);
});

// 서버 시작
app.listen(PORT, () => {
  console.log(`Site A server listening on http://localhost:${PORT}`);
});
