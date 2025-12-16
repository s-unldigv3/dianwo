export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    await ensureTables(env);
    await cleanupExpiredAccounts(env);

    // Routing
    if (url.pathname === '/' || url.pathname === '/index.html') return htmlIndex(request, env);
    if (url.pathname.startsWith('/share/')) return handleShare(request, env);
    if (url.pathname.startsWith('/api/')) return handleApi(request, env);
    return new Response('Not Found', { status: 404 });
  }
};

// ---------- DB / KV helpers ----------
async function ensureTables(env) {
  // Create tables if not exist
  await env.db.prepare(
    `CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE,
      password_hash TEXT,
      role TEXT,
      expire_until INTEGER
    )`
  ).run();

  // ensure expire column exists for older DBs
  try{
    await env.db.prepare('ALTER TABLE users ADD COLUMN expire_until INTEGER').run();
  }catch(e){ /* ignore if column exists or not supported */ }

  await env.db.prepare(
    `CREATE TABLE IF NOT EXISTS notebooks (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      title TEXT,
      content TEXT,
      created_at INTEGER,
      updated_at INTEGER,
      shared_token TEXT
    )`
  ).run();

  // Ensure owner exists
  const owner = await env.db.prepare('SELECT * FROM users WHERE username = ?').bind('sunldigv3').first();
  if (!owner) {
    const pw = await hash('password');
    const id = genId();
    await env.db.prepare('INSERT INTO users (id, username, password_hash, role) VALUES (?,?,?,?)')
      .bind(id, 'sunldigv3', pw, '皇帝').run();
  }
}

async function cleanupExpiredAccounts(env){
  try{
    const now = Date.now();
    const rows = await env.db.prepare('SELECT id FROM users WHERE expire_until IS NOT NULL AND expire_until <= ? AND role != ?').bind(now, '皇帝').all();
    const list = (rows && rows.results) || [];
    for(const r of list){
      // ensure no notebooks
      const cnt = await env.db.prepare('SELECT COUNT(*) as c FROM notebooks WHERE user_id = ?').bind(r.id).first();
      if (!cnt || cnt.c === 0){
        await env.db.prepare('DELETE FROM notebooks WHERE user_id = ?').bind(r.id).run();
        await env.db.prepare('DELETE FROM users WHERE id = ?').bind(r.id).run();
      }
    }
  }catch(e){
    // ignore cleanup errors
  }
}

function genId() {
  const a = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(a).map(b => b.toString(16).padStart(2,'0')).join('');
}

async function hash(text) {
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(text));
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
}

async function createSession(env, userId) {
  const token = genId();
  // 7 days
  await env.SESSIONS.put('s:'+token, userId, { expirationTtl: 60*60*24*7 });
  return token;
}

async function getUserFromSession(env, request) {
  const cookie = (request.headers.get('cookie')||'').split(';').map(s=>s.trim()).find(s=>s.startsWith('session='));
  if (!cookie) return null;
  const token = cookie.split('=')[1];
  const userId = await env.SESSIONS.get('s:'+token);
  if (!userId) return null;
  const user = await env.db.prepare('SELECT id, username, role FROM users WHERE id = ?').bind(userId).first();
  return user || null;
}

// ---------- API Handlers ----------
async function handleApi(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.replace('/api','') || '/';
  try {
    if (path === '/register' && request.method === 'POST') return apiRegister(request, env);
    if (path === '/login' && request.method === 'POST') return apiLogin(request, env);
    if (path === '/logout' && request.method === 'POST') return apiLogout(request, env);
    if (path === '/me' && request.method === 'GET') return apiMe(request, env);
    if (path === '/change-password' && request.method === 'POST') return apiChangePassword(request, env);
    if (path === '/notebooks' && request.method === 'GET') return apiListNotebooks(request, env);
    if (path === '/notebooks' && request.method === 'POST') return apiCreateNotebook(request, env);
    if (path.startsWith('/notebooks/') ) {
      const id = path.split('/')[2];
      if (request.method === 'GET') return apiGetNotebook(request, env, id);
      if (request.method === 'PUT') return apiUpdateNotebook(request, env, id);
      if (request.method === 'DELETE') return apiDeleteNotebook(request, env, id);
      if (request.method === 'POST' && path.endsWith('/share')) return apiShareNotebook(request, env, id);
    }
    if (path === '/admin/users' && request.method === 'GET') return apiAdminListUsers(request, env);
    if (path.startsWith('/admin/users/') && request.method === 'POST') {
      const uid = path.split('/')[2];
      return apiAdminModifyUser(request, env, uid);
    }
  } catch (e) {
    return json({ error: e.message }, 500);
  }
  return json({ error: 'Not found' }, 404);
}

async function apiRegister(request, env) {
  const data = await request.json();
  const { username, password } = data;
  if (!username || !password) return json({ error: '用户名或密码缺失' }, 400);
  const exists = await env.db.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
  if (exists) return json({ error: '用户名已存在' }, 400);
  const id = genId();
  const pw = await hash(password);
  const role = '骑士';
  const expire = Date.now() + 1000*60*60*24*10; // 10 days
  await env.db.prepare('INSERT INTO users (id, username, password_hash, role, expire_until) VALUES (?,?,?,?,?)')
    .bind(id, username, pw, role, expire).run();
  const token = await createSession(env, id);
  const res = json({ ok: true });
  res.headers.set('Set-Cookie', `session=${token}; Path=/; HttpOnly; SameSite=Lax`);
  return res;
}

async function apiLogin(request, env) {
  const data = await request.json();
  const { username, password } = data;
  if (!username || !password) return json({ error: '用户名或密码缺失' }, 400);
  const row = await env.db.prepare('SELECT id, password_hash FROM users WHERE username = ?').bind(username).first();
  if (!row) return json({ error: '用户不存在' }, 400);
  const pw = await hash(password);
  if (pw !== row.password_hash) return json({ error: '密码错误' }, 400);
  const token = await createSession(env, row.id);
  const res = json({ ok: true });
  res.headers.set('Set-Cookie', `session=${token}; Path=/; HttpOnly; SameSite=Lax`);
  return res;
}

async function apiLogout(request, env) {
  const cookie = (request.headers.get('cookie')||'').split(';').map(s=>s.trim()).find(s=>s.startsWith('session='));
  if (cookie) {
    const token = cookie.split('=')[1];
    await env.SESSIONS.delete('s:'+token);
  }
  const res = json({ ok: true });
  res.headers.set('Set-Cookie', `session=; Path=/; HttpOnly; Max-Age=0`);
  return res;
}

async function apiListNotebooks(request, env) {
  const user = await getUserFromSession(env, request);
  if (!user) return json({ error: '未登录' }, 401);
  const rows = await env.db.prepare('SELECT id, title, updated_at FROM notebooks WHERE user_id = ? ORDER BY updated_at DESC')
    .bind(user.id).all();
  return json({ notebooks: rows.results || [] });
}

async function apiCreateNotebook(request, env) {
  const user = await getUserFromSession(env, request);
  if (!user) return json({ error: '未登录' }, 401);
  // enforce limits for 骑士: 8 notebooks
  if (user.role === '骑士') {
    const count = await env.db.prepare('SELECT COUNT(*) as c FROM notebooks WHERE user_id = ?').bind(user.id).first();
    if (count && count.c >= 8) return json({ error: '骑士账号限制 8 个笔记本' }, 403);
  }
  const data = await request.json();
  const title = data.title || '无标题笔记本';
  const content = data.content || '';
  const id = genId();
  const now = Date.now();
  await env.db.prepare('INSERT INTO notebooks (id, user_id, title, content, created_at, updated_at) VALUES (?,?,?,?,?,?)')
    .bind(id, user.id, title, content, now, now).run();
  // clear any pending expiration when user creates a notebook
  await env.db.prepare('UPDATE users SET expire_until = NULL WHERE id = ?').bind(user.id).run();
  return json({ ok: true, id });
}

async function apiGetNotebook(request, env, id) {
  const user = await getUserFromSession(env, request);
  if (!user) return json({ error: '未登录' }, 401);
  const row = await env.db.prepare('SELECT * FROM notebooks WHERE id = ? AND user_id = ?').bind(id, user.id).first();
  if (!row) return json({ error: '未找到笔记' }, 404);
  return json({ notebook: row });
}

async function apiUpdateNotebook(request, env, id) {
  const user = await getUserFromSession(env, request);
  if (!user) return json({ error: '未登录' }, 401);
  const data = await request.json();
  const row = await env.db.prepare('SELECT * FROM notebooks WHERE id = ? AND user_id = ?').bind(id, user.id).first();
  if (!row) return json({ error: '未找到笔记' }, 404);
  const title = data.title ?? row.title;
  const content = data.content ?? row.content;
  const now = Date.now();
  await env.db.prepare('UPDATE notebooks SET title = ?, content = ?, updated_at = ? WHERE id = ?')
    .bind(title, content, now, id).run();
  return json({ ok: true });
}

async function apiDeleteNotebook(request, env, id) {
  const user = await getUserFromSession(env, request);
  if (!user) return json({ error: '未登录' }, 401);
  await env.db.prepare('DELETE FROM notebooks WHERE id = ? AND user_id = ?').bind(id, user.id).run();
  // if user has no more notebooks, set account to expire in 10 days (except 皇帝)
  const cnt = await env.db.prepare('SELECT COUNT(*) as c FROM notebooks WHERE user_id = ?').bind(user.id).first();
  if ((cnt && cnt.c === 0) && user.role !== '皇帝'){
    const expire = Date.now() + 1000*60*60*24*10;
    await env.db.prepare('UPDATE users SET expire_until = ? WHERE id = ?').bind(expire, user.id).run();
  }
  return json({ ok: true });
}

async function apiShareNotebook(request, env, id) {
  const user = await getUserFromSession(env, request);
  if (!user) return json({ error: '未登录' }, 401);
  const row = await env.db.prepare('SELECT * FROM notebooks WHERE id = ? AND user_id = ?').bind(id, user.id).first();
  if (!row) return json({ error: '未找到笔记' }, 404);
  const token = genId();
  await env.SHARES.put('sh:'+token, JSON.stringify({ id }), { expirationTtl: 60*60*24*30 });
  // also store token in notebook for direct lookup
  await env.db.prepare('UPDATE notebooks SET shared_token = ? WHERE id = ?').bind(token, id).run();
  const origin = new URL(request.url).origin;
  return json({ ok: true, link: origin + '/share/' + token });
}

async function apiMe(request, env) {
  const user = await getUserFromSession(env, request);
  if (!user) return json({ user: null });
  return json({ user });
}

async function apiChangePassword(request, env) {
  const user = await getUserFromSession(env, request);
  if (!user) return json({ error: '未登录' }, 401);
  const body = await request.json();
  const { oldPassword, newPassword } = body || {};
  if (!oldPassword || !newPassword) return json({ error: '参数缺失' }, 400);
  const row = await env.db.prepare('SELECT password_hash FROM users WHERE id = ?').bind(user.id).first();
  const oldHash = await hash(oldPassword);
  if (!row || row.password_hash !== oldHash) return json({ error: '原密码错误' }, 400);
  const newHash = await hash(newPassword);
  await env.db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').bind(newHash, user.id).run();
  return json({ ok: true });
}

async function apiAdminListUsers(request, env) {
  const user = await getUserFromSession(env, request);
  if (!user || user.role !== '皇帝') return json({ error: '权限不足' }, 403);
  const rows = await env.db.prepare('SELECT id, username, role FROM users').all();
  return json({ users: rows.results || [] });
}

async function apiAdminModifyUser(request, env, uid) {
  const user = await getUserFromSession(env, request);
  if (!user || user.role !== '皇帝') return json({ error: '权限不足' }, 403);
  const data = await request.json();
  if (data.action === 'delete') {
    // delete user and their notebooks
    await env.db.prepare('DELETE FROM notebooks WHERE user_id = ?').bind(uid).run();
    await env.db.prepare('DELETE FROM users WHERE id = ?').bind(uid).run();
    return json({ ok: true });
  }
  if (data.action === 'demote') {
    await env.db.prepare('UPDATE users SET role = NULL WHERE id = ?').bind(uid).run();
    // delete notebooks
    await env.db.prepare('DELETE FROM notebooks WHERE user_id = ?').bind(uid).run();
    return json({ ok: true });
  }
  return json({ error: '未知操作' }, 400);
}

// ---------- Share handler (public) ----------
async function handleShare(request, env) {
  const token = request.url.split('/share/')[1];
  if (!token) return new Response('分享不存在', { status: 404 });
  const data = await env.SHARES.get('sh:'+token);
  if (!data) return new Response('分享不存在或已过期', { status: 404 });
  const obj = JSON.parse(data);
  const row = await env.db.prepare('SELECT title, content FROM notebooks WHERE id = ?').bind(obj.id).first();
  if (!row) return new Response('未找到内容', { status: 404 });
  // render simple read-only page showing notebook
  return new Response(renderHtmlShare(row.title, row.content), { headers: { 'content-type':'text/html; charset=utf-8' } });
}

// ---------- HTML / Frontend ----------
function htmlIndex(request, env) {
  // 默认中文页面
  return new Response(renderHtmlApp(), { headers: { 'content-type':'text/html; charset=utf-8' } });
}

function json(obj, status=200) {
  return new Response(JSON.stringify(obj), { status, headers: { 'content-type':'application/json' } });
}

function renderHtmlShare(title, content) {
  return `<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title><style>body{font-family:Inter,system-ui,Segoe UI,Arial;background:#f3f8ff;color:#0b2545;padding:20px}pre{white-space:pre-wrap;background:#fff;padding:16px;border-radius:8px;box-shadow:0 6px 18px rgba(11,37,69,.06)}</style></head><body><h1>${escapeHtml(title)}</h1><pre>${escapeHtml(content)}</pre></body></html>`;
}

function renderHtmlApp(){
  // 仅保留中文文案
  const L = {
    title: '点我！-萌萌哒的在线记事本', newBtn: '新建', save: '保存', share: '分享', del: '删除', login: '登录/注册', myNotebooks: '我的笔记本', enterNotebooks: '进入笔记本', changePw: '修改密码', logout: '退出', noNotes: '请新建笔记本喵~', clickHint: '请点左侧笔记本或新建喵~', createHint: '请输入内容喵~', confirmDelete: '确认删除？'
  };

  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${L.title}</title>
  <style>
    :root{--bg:#eaf6ff;--card:#fff;--accent:#3b82f6;--text:#07304a;--muted:rgba(7,48,74,.6);--shadow:0 10px 30px rgba(3,60,122,.08)}
    html,body{height:100%;margin:0;font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial}
    body{background:var(--bg);color:var(--text);display:flex;align-items:center;justify-content:center;padding:20px}
    .app{width:100%;max-width:980px;background:linear-gradient(180deg,rgba(255,255,255,.6),rgba(255,255,255,.4));border-radius:12px;padding:18px;box-shadow:0 10px 30px rgba(3,60,122,.08);overflow:hidden}
    header{display:flex;justify-content:space-between;align-items:center}
    h1{margin:0;font-size:20px}
    .controls{display:flex;gap:8px;align-items:center}
    button{background:var(--card);border:0;padding:8px 12px;border-radius:10px;cursor:pointer;box-shadow:0 6px 18px rgba(11,37,69,.04);transition:transform .12s,box-shadow .12s}
    button:active{transform:translateY(1px)}
    .main{display:flex;gap:14px;margin-top:14px}
    .sidebar{width:300px;background:var(--card);padding:12px;border-radius:10px;height:560px;overflow:auto;border:1px solid rgba(0,0,0,.03)}
    .editor{flex:1;background:var(--card);padding:12px;border-radius:10px;height:560px;display:flex;flex-direction:column}
    .notebook{display:flex;align-items:center;justify-content:space-between;padding:10px;border-radius:10px;margin-bottom:10px;cursor:pointer;background:linear-gradient(180deg,transparent,rgba(0,0,0,0.02));border:1px solid rgba(0,0,0,0.03);transition:transform .12s,box-shadow .12s,background .12s}
    .notebook:hover{transform:translateY(-3px);box-shadow:var(--shadow);background:linear-gradient(180deg,rgba(255,255,255,0.02),transparent)}
    .notebook .meta{font-size:12px;color:var(--muted)}
    .notebook.selected{outline:2px solid var(--accent);box-shadow:0 10px 30px rgba(59,130,246,.12)}
    .empty{opacity:.6;padding:20px;text-align:center;color:var(--muted)}
    .title-input{font-size:18px;padding:8px;border-radius:8px;border:1px solid rgba(0,0,0,.06);margin-bottom:8px}
    textarea{flex:1;border:0;outline:none;background:transparent;font-family:inherit;font-size:15px}
    /* account menu */
    .account-menu {min-width:160px;border-radius:8px;padding:6px;background:var(--card);box-shadow:var(--shadow);}
    .account-menu div{padding:8px;border-radius:6px}
    .account-menu div:hover{background:rgba(0,0,0,0.04)}
    #accountArea button{border-radius:10px;padding:8px 12px}
    .small{font-size:12px;color:rgba(0,0,0,.5)}
    /* modal styles */
    .modal-backdrop{position:fixed;left:0;top:0;right:0;bottom:0;background:rgba(0,0,0,.4);display:flex;align-items:center;justify-content:center;z-index:99999}
    .modal{background:var(--card);padding:18px;border-radius:12px;box-shadow:var(--shadow);max-width:480px;width:92%;}
    .modal .message{margin-bottom:12px;white-space:pre-wrap;word-break:break-word;overflow-wrap:anywhere}
    .auth-tabs{display:flex;gap:8px;margin-bottom:12px}
    .auth-tabs button{flex:1}
    .auth-field{display:flex;flex-direction:column;gap:6px;margin-bottom:10px}
    .auth-field input{padding:10px;border-radius:8px;border:1px solid rgba(0,0,0,.06)}
    .modal .actions{display:flex;gap:8px;justify-content:space-between}
    /* confirm buttons: primary on left */
    .btn-primary{background:var(--accent);color:#fff}
  </style>
</head>
<body>
  <div class="app" id="app">
    <header>
      <h1>${L.title}</h1>
      <div class="controls">
        <div id="accountArea">
          <button id="authBtn">${L.login}</button>
        </div>
      </div>
    </header>
    <div class="main" id="mainArea">
      <div class="sidebar" id="sidebar">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
          <strong>${L.myNotebooks}</strong>
          <div>
            <button id="newBtn">${L.newBtn}</button>
          </div>
        </div>
        <div id="list"></div>
      </div>
      <div class="editor" id="editor">
        <input class="title-input" id="titleInput" placeholder="${L.clickHint}">
        <textarea id="content" placeholder="${L.createHint}"></textarea>
        <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:8px">
          <button id="shareBtn">${L.share}</button>
          <button id="deleteBtn">${L.del}</button>
          <button id="saveBtn">${L.save}</button>
        </div>
      </div>
    </div>
  </div>
  <script>
    // 只支持中文
    const STR = ${JSON.stringify(L)};

    // 显示分享链接（无输入框）
    function showShareLink(link){
      return new Promise((resolve)=>{
        const o = document.createElement('div'); o.className='modal-backdrop';
        const m = document.createElement('div'); m.className='modal';
        const msg = document.createElement('div'); msg.className='message'; msg.textContent = '分享链接（直接打开可查看）';
        const linkEl = document.createElement('div'); linkEl.style.padding='10px'; linkEl.style.background='#f6f9ff'; linkEl.style.borderRadius='8px'; linkEl.style.wordBreak='break-all'; linkEl.style.marginBottom='12px'; linkEl.textContent = link;
        const btns = document.createElement('div'); btns.style.display='flex'; btns.style.justifyContent='flex-end'; btns.style.gap='8px';
        const copyBtn = document.createElement('button'); copyBtn.textContent='复制链接'; copyBtn.onclick = async ()=>{ try{ await navigator.clipboard.writeText(link); copyBtn.textContent='已复制'; setTimeout(()=>copyBtn.textContent='复制链接',1200);}catch(e){ copyBtn.textContent='复制失败'; setTimeout(()=>copyBtn.textContent='复制链接',1200);} };
        const closeBtn = document.createElement('button'); closeBtn.textContent='关闭'; closeBtn.onclick = ()=>{ _removeModal(o); resolve(); };
        btns.appendChild(copyBtn); btns.appendChild(closeBtn);
        m.appendChild(msg); m.appendChild(linkEl); m.appendChild(btns); o.appendChild(m); document.body.appendChild(o);
      });
    }

    const api = {
      get: (p) => fetch('/api'+p, { credentials: 'same-origin' }).then(r=>r.json()),
      post: (p, b) => fetch('/api'+p, {method:'POST',credentials:'same-origin',headers:{'content-type':'application/json'},body:JSON.stringify(b)}).then(r=>r.json()),
      put: (p, b) => fetch('/api'+p, {method:'PUT',credentials:'same-origin',headers:{'content-type':'application/json'},body:JSON.stringify(b)}).then(r=>r.json()),
      del: (p) => fetch('/api'+p, {method:'DELETE',credentials:'same-origin'}).then(r=>r.json())
    };

    let current = null;
    let me = null;

    function _removeModal(m){ try{ if(document.body.contains(m)) document.body.removeChild(m);}catch(e){} }

    function showModalAlert(message){
      return new Promise((resolve)=>{
        const o = document.createElement('div'); o.className='modal-backdrop';
        const m = document.createElement('div'); m.className='modal';
        const msg = document.createElement('div'); msg.className='message'; msg.textContent = message;
        const btn = document.createElement('button'); btn.textContent='确定'; btn.onclick = ()=>{ _removeModal(o); resolve(); };
        m.appendChild(msg); m.appendChild(btn); o.appendChild(m); document.body.appendChild(o);
      });
    }

    function showModalPrompt(message, defaultVal){
      return new Promise((resolve)=>{
        const o = document.createElement('div'); o.className='modal-backdrop';
        const m = document.createElement('div'); m.className='modal';
        const msg = document.createElement('div'); msg.className='message'; msg.textContent = message;
        const input = document.createElement('input'); input.style.width='100%'; input.style.padding='8px'; input.value = defaultVal || '';
        const btns = document.createElement('div'); btns.style.display='flex'; btns.style.justifyContent='flex-end'; btns.style.gap='8px';
        const copyBtn = document.createElement('button'); copyBtn.textContent='复制'; copyBtn.onclick = async ()=>{ try{ await navigator.clipboard.writeText(input.value); copyBtn.textContent='已复制'; setTimeout(()=>copyBtn.textContent='复制',1200);}catch(e){} };
        const ok = document.createElement('button'); ok.textContent='确定'; ok.onclick = ()=>{ _removeModal(o); resolve(input.value); };
        const cancel = document.createElement('button'); cancel.textContent='取消'; cancel.onclick = ()=>{ _removeModal(o); resolve(null); };
        btns.appendChild(copyBtn); btns.appendChild(cancel); btns.appendChild(ok);
        m.appendChild(msg); m.appendChild(input); m.appendChild(btns); o.appendChild(m); document.body.appendChild(o);
        setTimeout(()=>input.focus(),50);
      });
    }

    // confirm: primary action (确定) on the LEFT as requested
    function showModalConfirm(message){
      return new Promise((resolve)=>{
        const o = document.createElement('div'); o.className='modal-backdrop';
        const m = document.createElement('div'); m.className='modal';
        const msg = document.createElement('div'); msg.className='message'; msg.textContent = message;
        const btns = document.createElement('div'); btns.className='actions';
        const ok = document.createElement('button'); ok.textContent='确定'; ok.className='btn-primary'; ok.onclick = ()=>{ _removeModal(o); resolve(true); };
        const cancel = document.createElement('button'); cancel.textContent='取消'; cancel.onclick = ()=>{ _removeModal(o); resolve(false); };
        // left-primary layout
        btns.appendChild(ok); btns.appendChild(cancel);
        m.appendChild(msg); m.appendChild(btns); o.appendChild(m); document.body.appendChild(o);
      });
    }

    // AUTH modal (nice login/register UI)
    function showAuthModal(){
      return new Promise((resolve)=>{
        const o = document.createElement('div'); o.className='modal-backdrop';
        const m = document.createElement('div'); m.className='modal';
        const tabs = document.createElement('div'); tabs.className='auth-tabs';
        const btnLogin = document.createElement('button'); btnLogin.textContent='登录';
        const btnReg = document.createElement('button'); btnReg.textContent='注册';
        tabs.appendChild(btnLogin); tabs.appendChild(btnReg);
        const fields = document.createElement('div'); fields.className='auth-field';
        const userInput = document.createElement('input'); userInput.placeholder='用户名';
        const pwInput = document.createElement('input'); pwInput.type='password'; pwInput.placeholder='密码';
        fields.appendChild(userInput); fields.appendChild(pwInput);
        const actions = document.createElement('div'); actions.className='actions';
        const submit = document.createElement('button'); submit.textContent='提交'; submit.className='btn-primary';
        const cancel = document.createElement('button'); cancel.textContent='取消';
        actions.appendChild(submit); actions.appendChild(cancel);
        m.appendChild(tabs); m.appendChild(fields); m.appendChild(actions); o.appendChild(m); document.body.appendChild(o);

        let mode = 'login';
        function updateActive(){
          btnLogin.style.opacity = mode==='login'?1:0.6;
          btnReg.style.opacity = mode==='reg'?1:0.6;
        }
        btnLogin.onclick = ()=>{ mode='login'; updateActive(); }
        btnReg.onclick = ()=>{ mode='reg'; updateActive(); }
        cancel.onclick = ()=>{ _removeModal(o); resolve(null); }
        submit.onclick = async ()=>{
          const username = userInput.value && userInput.value.trim();
          const password = pwInput.value && pwInput.value.trim();
          if (!username || !password) { alert('请完整填写'); return }
          if (mode==='reg'){
            const r = await api.post('/register', { username, password });
            if (r.ok){ _removeModal(o); resolve({ok:true}); } else { alert(r.error||'注册失败'); }
          } else {
            const r = await api.post('/login', { username, password });
            if (r.ok){ _removeModal(o); resolve({ok:true}); } else { alert(r.error||'登录失败'); }
          }
        }
        updateActive(); setTimeout(()=>userInput.focus(),50);
      });
    }

    function updateAccountArea(){
      const area = document.getElementById('accountArea');
      area.innerHTML = '';
      if (me && me.username){
        const btn = document.createElement('button'); btn.textContent = me.username + (me.role?(' ('+me.role+')'): '');
        btn.id = 'accountBtn'; btn.onclick = ()=>{ showAccountMenu(btn); };
        area.appendChild(btn);
      } else {
        const b = document.createElement('button'); b.id='authBtn'; b.textContent = STR.login; b.onclick = async ()=>{ const r = await showAuthModal(); if (r && r.ok){ await initAuth(); await refreshList(); } };
        area.appendChild(b);
      }
    }

    async function initAuth(){ const r = await api.get('/me'); if (r && r.user) { me = r.user } else me = null; updateAccountArea(); }

    function showAccountMenu(targetBtn){
      const m = document.createElement('div'); m.className='account-menu'; m.style.position='absolute'; m.style.background='var(--card)'; m.style.padding='8px'; m.style.borderRadius='8px'; m.style.boxShadow='0 6px 18px rgba(0,0,0,.08)'; m.style.zIndex=9999; m.style.minWidth='160px';
      const btnNotes = document.createElement('div'); btnNotes.textContent=STR.enterNotebooks; btnNotes.style.padding='8px'; btnNotes.style.cursor='pointer'; btnNotes.onclick=()=>{ try{ document.body.removeChild(m);}catch(e){} };
      const btnSettings = document.createElement('div'); btnSettings.textContent=STR.changePw; btnSettings.style.padding='8px'; btnSettings.style.cursor='pointer'; btnSettings.onclick = async ()=>{ try{ document.body.removeChild(m);}catch(e){}; await accountSettings(); };
      const btnLogout = document.createElement('div'); btnLogout.textContent=STR.logout; btnLogout.style.padding='8px'; btnLogout.style.cursor='pointer'; btnLogout.onclick = async ()=>{ await api.post('/logout',{}); me=null; updateAccountArea(); await refreshList(); try{ if(document.body.contains(m)) document.body.removeChild(m);}catch(e){} };
      m.appendChild(btnNotes); m.appendChild(btnSettings); m.appendChild(btnLogout);
      document.body.appendChild(m);
      try{ const rect = targetBtn.getBoundingClientRect(); m.style.left = (rect.left + window.scrollX) + 'px'; m.style.top = (rect.bottom + window.scrollY + 8) + 'px'; }catch(e){ m.style.right='20px'; m.style.top='60px'; }
      setTimeout(()=>document.addEventListener('click', ()=>{ try{ if(document.body.contains(m)) document.body.removeChild(m);}catch(e){} }, { once:true }), 50);
    }

    async function accountSettings(){ if(!me) { await showModalAlert('未登录'); return };
      const newPw = prompt('输入新密码（留空取消）'); if(!newPw) return; const oldPw = prompt('输入原密码以确认'); if(!oldPw) return; const res = await api.post('/change-password', { oldPassword: oldPw, newPassword: newPw }); if (res.ok) alert('密码已修改'); else alert(res.error||'失败'); }

    async function refreshList(){
      const res = await api.get('/notebooks');
      const list = document.getElementById('list'); list.innerHTML='';
      if (!res.notebooks || res.notebooks.length===0){ list.innerHTML = '<div class="empty">' + STR.noNotes + '</div>'; return }
      res.notebooks.forEach(nb=>{
        const el = document.createElement('div'); el.className='notebook';
        const left = document.createElement('div');
        const title = document.createElement('div'); title.textContent = nb.title || '无标题'; title.style.fontWeight='600';
        const meta = document.createElement('div'); meta.className='meta'; meta.textContent = nb.updated_at? (new Date(nb.updated_at).toLocaleString()):'';
        left.appendChild(title); left.appendChild(meta);
        el.appendChild(left);
        el.onclick=()=>{ document.querySelectorAll('.notebook').forEach(n=>n.classList.remove('selected')); el.classList.add('selected'); openNotebook(nb.id); };
        list.appendChild(el);
      })
    }

    async function openNotebook(id){
      const res = await api.get('/notebooks/'+id);
      if (res.notebook){ current = res.notebook; document.getElementById('titleInput').value=current.title; document.getElementById('content').value=current.content; }
      else if (res.error) { if (res.error==='未登录') { await showModalAlert('请先登录'); const ar = await showAuthModal(); if (ar && ar.ok){ await initAuth(); await refreshList(); } } else await showModalAlert(res.error); }
    }

    document.getElementById('newBtn').onclick = async ()=>{
      const res = await api.post('/notebooks', { title: '新笔记本', content: '' });
      if (res.id) { await refreshList(); openNotebook(res.id); }
      else await showModalAlert(res.error||'失败');
    }
    document.getElementById('saveBtn').onclick = async ()=>{
      if (!current) return await showModalAlert('请选中笔记本');
      const title = document.getElementById('titleInput').value;
      const content = document.getElementById('content').value;
      const res = await api.put('/notebooks/'+current.id, { title, content });
      if (res.ok) { await refreshList(); await showModalAlert('已保存'); } else { if (res.error==='未登录'){ await showModalAlert('请先登录'); const ar = await showAuthModal(); if (ar && ar.ok){ await initAuth(); await refreshList(); } } else await showModalAlert(res.error||'保存失败'); }
    }
    document.getElementById('deleteBtn').onclick = async ()=>{
      if (!current) return await showModalAlert('请选中笔记本');
      const ok = await showModalConfirm(STR.confirmDelete); if (!ok) return;
      const res = await api.del('/notebooks/'+current.id);
      if (res.ok) { current = null; document.getElementById('titleInput').value=''; document.getElementById('content').value=''; await refreshList(); }
      else await showModalAlert(res.error||'删除失败');
    }
    document.getElementById('shareBtn').onclick = async ()=>{
      if (!current) return await showModalAlert('请选中笔记本');
      const res = await api.post('/notebooks/'+current.id+'/share');
      if (res.link) { await showShareLink(res.link); }
      else await showModalAlert(res.error||'失败');
    }

    // init
    (async ()=>{ await initAuth(); await refreshList(); })().catch(()=>{});
  </script>
</body>
</html>`;
}

function escapeHtml(s){ if (!s) return ''; return s.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;'); }