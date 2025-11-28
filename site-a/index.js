// site-a/index.js

const express = require('express');

const app = express();
const PORT = 4000;            // A사이트(서비스) 서버는 4000 포트
const PCF_BASE_URL = 'http://localhost:3000'; // PCF 백엔드 주소

// 폼 데이터 파싱 (사용자가 username, password 받기 용)
app.use(express.urlencoded({ extended: true }));
// JSON도 필요하면
app.use(express.json());

/**
 * 1) GET /  홈 페이지 (사이트 접속 시 맨 처음 화면)
 */
app.get('/', (req, res) => {
    res.send(`
      <html>
        <body>
          <h1>Welcome to Site A</h1>
          <p>사이트A 입니다.</p>
          <a href="/login"><button>로그인 하기</button></a>
        </body>
      </html>
    `);
  });
  
/**
 * 2) GET /login  → 간단한 로그인 폼 HTML
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
 *  - (1)  username/password로 서비스 서버에서 로그인 검증 (로그인 성공으로 가정 해 진행)
 *  - (2) user_token / domain / login_ip 만들기
 *  - (3) PCF 백엔드의 /evaluate_login 호출
 *  - (4) PCf백엔드로 부터 응답으로 받은 login_event_id, domain_salt, run_sandbox를
 *       HTML 응답 안의 window.PCF_CONTEXT 에 심어서 브라우저로 전달
 */
app.post('/login', async (req, res) => {
  const { username, password } = req.body || {};

  // 1) (데모용) 서비스 서버 자체의 로그인 검증은 생략하고, 그냥 성공했다고 가정
  if (!username) {
    return res.status(400).send('username is required');
  }

  // 2) user_token, domain, login_ip 구성
  const user_token = `user-${username}`;   // 데모용. 실제로는 DB ID나 UUID를 쓸 수 있음
  const domain = 'a.com';                  // 이 서비스의 도메인 
  const login_ip = req.ip || '1.2.3.4';    // 간단히 req.ip 사용 (프록시 뒤면 X-Forwarded-For 고려)

  console.log('[Site-A] Login success for', username);
  console.log('[Site-A] Call PCF /evaluate_login with', {
    user_token,
    domain,
    login_ip,
  });

  // 3) PCF 백엔드 /evaluate_login 호출
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

  // 4) HTML 응답 안에 window.PCF_CONTEXT로 PCF 정보를 심어줌
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
          },
          null,
          2
        )}</pre>

        <script>
          // 브라우저 확장(샌드박스)이 참조할 컨텍스트
          window.PCF_CONTEXT = {
            login_event_id: ${JSON.stringify(login_event_id)},
            run_sandbox: ${JSON.stringify(run_sandbox)},
            domain: ${JSON.stringify(pcfDomain)},
            domain_salt: ${JSON.stringify(domain_salt)},
          };

          console.log('PCF_CONTEXT set:', window.PCF_CONTEXT);
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

