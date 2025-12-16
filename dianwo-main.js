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

  // 安全检查列是否存在，避免重复添加
  try {
    const columnCheck = await env.db.prepare(`
      PRAGMA table_info(users)
    `).all();
    const hasExpireColumn = columnCheck.results.some(col => col.name === 'expire_until');
    if (!hasExpireColumn) {
      await env.db.prepare('ALTER TABLE users ADD COLUMN expire_until INTEGER').run();
    }
  } catch (e) {
    console.warn('添加expire_until列失败（可能已存在）:', e.message);
  }

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
  
  // 使用名为 db1 的 SQL 数据库存储原先的 KV（sessions, shares）
  try {
    await env.db1.prepare(
      `CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id TEXT,
        expire_at INTEGER
      )`
    ).run();

    await env.db1.prepare(
      `CREATE TABLE IF NOT EXISTS shares (
        token TEXT PRIMARY KEY,
        notebook_id TEXT,
        expire_at INTEGER
      )`
    ).run();
  } catch (e) {
    console.warn('创建 db1 表失败（可能环境未提供 db1）:', e.message);
  }

  // Ensure owner exists
  const owner = await env.db.prepare('SELECT * FROM users WHERE username = ?').bind('sunldigv3').first();
  if (!owner) {
    const pw = await hash('password');
    const id = genId();
    await env.db.prepare('INSERT INTO users (id, username, password_hash, role) VALUES (?,?,?,?)')
      .bind(id, 'sunldigv3', pw, '皇帝').run();
  }
}

async function cleanupExpiredAccounts(env) {
  try {
    const now = Date.now();
    const rows = await env.db.prepare(
      'SELECT id FROM users WHERE expire_until IS NOT NULL AND expire_until <= ? AND role != ?'
    ).bind(now, '皇帝').all();
    
    const list = (rows && rows.results) || [];
    for (const r of list) {
      // 检查用户是否有笔记
      const cnt = await env.db.prepare(
        'SELECT COUNT(*) as c FROM notebooks WHERE user_id = ?'
      ).bind(r.id).first();
      
      if (cnt && cnt.c === 0) {
        // 先删除笔记（防御性），再删除用户
        await env.db.prepare('DELETE FROM notebooks WHERE user_id = ?').bind(r.id).run();
        await env.db.prepare('DELETE FROM users WHERE id = ?').bind(r.id).run();
      }
    }
  } catch (e) {
    console.error('清理过期账户失败:', e);
  }
}

function genId() {
  const a = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(a).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hash(text) {
  if (!text) return '';
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(text));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function createSession(env, userId) {
  if (!userId) throw new Error('用户ID不能为空');
  const token = genId();
  // 7 days
  const expire = Date.now() + 1000 * 60 * 60 * 24 * 7;
  await env.db1.prepare('INSERT OR REPLACE INTO sessions (token, user_id, expire_at) VALUES (?,?,?)')
    .bind(token, userId, expire).run();
  return token;
}

async function getUserFromSession(env, request) {
  try {
    const cookieHeader = request.headers.get('cookie') || '';
    const cookie = cookieHeader.split(';').map(s => s.trim()).find(s => s.startsWith('session='));
    if (!cookie) return null;
    
    const token = cookie.split('=')[1];
    if (!token) return null;
    // 从 db1.sessions 中查找，优先使用 SQL 存储
    let userId = null;
    try {
      const now = Date.now();
      const row = await env.db1.prepare('SELECT user_id FROM sessions WHERE token = ? AND (expire_at IS NULL OR expire_at > ?)')
        .bind(token, now).first();
      if (row && row.user_id) userId = row.user_id;
    } catch (e) {
      console.error('从 db1 读取会话失败:', e);
      return null;
    }

    if (!userId) return null;

    const user = await env.db.prepare('SELECT id, username, role FROM users WHERE id = ?').bind(userId).first();
    return user || null;
  } catch (e) {
    console.error('获取会话用户失败:', e);
    return null;
  }
}

function escapeHtml(s) {
  if (!s) return '';
  return s.replaceAll('&', '&amp;')
          .replaceAll('<', '&lt;')
          .replaceAll('>', '&gt;')
          .replaceAll('"', '&quot;')
          .replaceAll("'", '&#039;');
}

// ---------- 工具函数 ----------
function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { 
    status, 
    headers: { 
      'content-type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    } 
  });
}

// ---------- API Handlers ----------
async function apiRegister(request, env) {
  try {
    const data = await request.json().catch(() => ({}));
    const { username, password } = data;
    
    if (!username || !password) return json({ error: '用户名或密码缺失' }, 400);
    if (typeof username !== 'string' || typeof password !== 'string') {
      return json({ error: '用户名和密码必须是字符串' }, 400);
    }
    
    // 验证用户名格式
    if (username.length < 3 || username.length > 20) {
      return json({ error: '用户名长度必须在3-20个字符之间' }, 400);
    }
    
    const exists = await env.db.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
    if (exists) return json({ error: '用户名已存在' }, 400);
    
    const id = genId();
    const pw = await hash(password);
    const role = '骑士';
    const expire = Date.now() + 1000 * 60 * 60 * 24 * 10; // 10 days
    
    await env.db.prepare(
      'INSERT INTO users (id, username, password_hash, role, expire_until) VALUES (?,?,?,?,?)'
    ).bind(id, username, pw, role, expire).run();
    
    const token = await createSession(env, id);
    const res = json({ ok: true });
    res.headers.set('Set-Cookie', `session=${token}; Path=/; HttpOnly; SameSite=Lax; Secure`);
    return res;
  } catch (e) {
    console.error('注册失败:', e);
    return json({ error: '注册失败: ' + e.message }, 500);
  }
}

async function apiLogin(request, env) {
  try {
    const data = await request.json().catch(() => ({}));
    const { username, password } = data;
    
    if (!username || !password) return json({ error: '用户名或密码缺失' }, 400);
    
    const row = await env.db.prepare('SELECT id, password_hash FROM users WHERE username = ?').bind(username).first();
    if (!row) return json({ error: '用户不存在' }, 400);
    
    const pw = await hash(password);
    if (pw !== row.password_hash) return json({ error: '密码错误' }, 400);
    
    const token = await createSession(env, row.id);
    const res = json({ ok: true });
    res.headers.set('Set-Cookie', `session=${token}; Path=/; HttpOnly; SameSite=Lax; Secure`);
    return res;
  } catch (e) {
    console.error('登录失败:', e);
    return json({ error: '登录失败: ' + e.message }, 500);
  }
}

async function apiLogout(request, env) {
  try {
    const cookieHeader = request.headers.get('cookie') || '';
    const cookie = cookieHeader.split(';').map(s => s.trim()).find(s => s.startsWith('session='));
    
    if (cookie) {
      const token = cookie.split('=')[1];
      try {
        await env.db1.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
      } catch (e) {
        console.error('删除 session 失败:', e);
      }
    }
    
    const res = json({ ok: true });
    res.headers.set('Set-Cookie', `session=; Path=/; HttpOnly; Max-Age=0; Secure`);
    return res;
  } catch (e) {
    console.error('登出失败:', e);
    return json({ error: '登出失败: ' + e.message }, 500);
  }
}

async function apiListNotebooks(request, env) {
  const user = await getUserFromSession(env, request);
  if (!user) return json({ error: '未登录' }, 401);
  
  try {
    const rows = await env.db.prepare(
      'SELECT id, title, updated_at FROM notebooks WHERE user_id = ? ORDER BY updated_at DESC'
    ).bind(user.id).all();
    
    return json({ notebooks: rows.results || [] });
  } catch (e) {
    console.error('获取笔记列表失败:', e);
    return json({ error: '获取笔记列表失败: ' + e.message }, 500);
  }
}

async function apiCreateNotebook(request, env) {
  const user = await getUserFromSession(env, request);
  if (!user) return json({ error: '未登录' }, 401);
  
  try {
    // enforce limits for 骑士: 8 notebooks
    if (user.role === '骑士') {
      const count = await env.db.prepare(
        'SELECT COUNT(*) as c FROM notebooks WHERE user_id = ?'
      ).bind(user.id).first();
      
      if (count && count.c >= 8) {
        return json({ error: '骑士账号限制 8 个笔记本' }, 403);
      }
    }
    
    const data = await request.json().catch(() => ({}));
    const title = data.title || '无标题笔记本';
    const content = data.content || '';
    const id = genId();
    const now = Date.now();
    
    await env.db.prepare(
      'INSERT INTO notebooks (id, user_id, title, content, created_at, updated_at) VALUES (?,?,?,?,?,?)'
    ).bind(id, user.id, title, content, now, now).run();
    
    // clear any pending expiration when user creates a notebook
    await env.db.prepare('UPDATE users SET expire_until = NULL WHERE id = ?').bind(user.id).run();
    
    return json({ ok: true, id });
  } catch (e) {
    console.error('创建笔记失败:', e);
    return json({ error: '创建笔记失败: ' + e.message }, 500);
  }
}

async function apiGetNotebook(request, env, id) {
  const user = await getUserFromSession(env, request);
  if (!user) return json({ error: '未登录' }, 401);
  
  try {
    const row = await env.db.prepare(
      'SELECT * FROM notebooks WHERE id = ? AND user_id = ?'
    ).bind(id, user.id).first();
    
    if (!row) return json({ error: '未找到笔记' }, 404);
    
    return json({ notebook: row });
  } catch (e) {
    console.error('获取笔记失败:', e);
    return json({ error: '获取笔记失败: ' + e.message }, 500);
  }
}

async function apiUpdateNotebook(request, env, id) {
  const user = await getUserFromSession(env, request);
  if (!user) return json({ error: '未登录' }, 401);
  
  try {
    const data = await request.json().catch(() => ({}));
    const row = await env.db.prepare(
      'SELECT * FROM notebooks WHERE id = ? AND user_id = ?'
    ).bind(id, user.id).first();
    
    if (!row) return json({ error: '未找到笔记' }, 404);
    
    const title = data.title ?? row.title;
    const content = data.content ?? row.content;
    const now = Date.now();
    
    await env.db.prepare(
      'UPDATE notebooks SET title = ?, content = ?, updated_at = ? WHERE id = ?'
    ).bind(title, content, now, id).run();
    
    return json({ ok: true });
  } catch (e) {
    console.error('更新笔记失败:', e);
    return json({ error: '更新笔记失败: ' + e.message }, 500);
  }
}

async function apiDeleteNotebook(request, env, id) {
  const user = await getUserFromSession(env, request);
  if (!user) return json({ error: '未登录' }, 401);
  
  try {
    await env.db.prepare(
      'DELETE FROM notebooks WHERE id = ? AND user_id = ?'
    ).bind(id, user.id).run();
    
    // if user has no more notebooks, set account to expire in 10 days (except 皇帝)
    const cnt = await env.db.prepare(
      'SELECT COUNT(*) as c FROM notebooks WHERE user_id = ?'
    ).bind(user.id).first();
    
    if ((cnt && cnt.c === 0) && user.role !== '皇帝') {
      const expire = Date.now() + 1000 * 60 * 60 * 24 * 10;
      await env.db.prepare('UPDATE users SET expire_until = ? WHERE id = ?').bind(expire, user.id).run();
    }
    
    return json({ ok: true });
  } catch (e) {
    console.error('删除笔记失败:', e);
    return json({ error: '删除笔记失败: ' + e.message }, 500);
  }
}

async function apiShareNotebook(request, env, id) {
  const user = await getUserFromSession(env, request);
  if (!user) return json({ error: '未登录' }, 401);
  
  try {
    const row = await env.db.prepare(
      'SELECT * FROM notebooks WHERE id = ? AND user_id = ?'
    ).bind(id, user.id).first();
    
    if (!row) return json({ error: '未找到笔记' }, 404);
    
    const token = genId();
    const expire = Date.now() + 1000 * 60 * 60 * 24 * 30;
    await env.db1.prepare('INSERT OR REPLACE INTO shares (token, notebook_id, expire_at) VALUES (?,?,?)')
      .bind(token, id, expire).run();

    // also store token in notebook for direct lookup
    await env.db.prepare('UPDATE notebooks SET shared_token = ? WHERE id = ?').bind(token, id).run();
    
    const origin = new URL(request.url).origin;
    return json({ ok: true, link: origin + '/share/' + token });
  } catch (e) {
    console.error('分享笔记失败:', e);
    return json({ error: '分享笔记失败: ' + e.message }, 500);
  }
}

async function apiMe(request, env) {
  try {
    const user = await getUserFromSession(env, request);
    return json({ user: user || null });
  } catch (e) {
    console.error('获取用户信息失败:', e);
    return json({ user: null }, 500);
  }
}

async function apiChangePassword(request, env) {
  const user = await getUserFromSession(env, request);
  if (!user) return json({ error: '未登录' }, 401);
  
  try {
    const body = await request.json().catch(() => ({}));
    const { oldPassword, newPassword } = body || {};
    
    if (!oldPassword || !newPassword) return json({ error: '参数缺失' }, 400);
    
    const row = await env.db.prepare('SELECT password_hash FROM users WHERE id = ?').bind(user.id).first();
    const oldHash = await hash(oldPassword);
    
    if (!row || row.password_hash !== oldHash) {
      return json({ error: '原密码错误' }, 400);
    }
    
    const newHash = await hash(newPassword);
    await env.db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').bind(newHash, user.id).run();
    
    return json({ ok: true });
  } catch (e) {
    console.error('修改密码失败:', e);
    return json({ error: '修改密码失败: ' + e.message }, 500);
  }
}

async function apiAdminListUsers(request, env) {
  const user = await getUserFromSession(env, request);
  if (!user || user.role !== '皇帝') return json({ error: '权限不足' }, 403);
  
  try {
    const rows = await env.db.prepare('SELECT id, username, role FROM users').all();
    return json({ users: rows.results || [] });
  } catch (e) {
    console.error('管理员获取用户列表失败:', e);
    return json({ error: '获取用户列表失败: ' + e.message }, 500);
  }
}

async function apiAdminModifyUser(request, env, uid) {
  const user = await getUserFromSession(env, request);
  if (!user || user.role !== '皇帝') return json({ error: '权限不足' }, 403);
  
  try {
    const data = await request.json().catch(() => ({}));
    const targetUser = await env.db.prepare('SELECT * FROM users WHERE id = ?').bind(uid).first();
    
    if (!targetUser) return json({ error: '用户不存在' }, 404);
    if (targetUser.role === '皇帝') return json({ error: '无法修改皇帝账号' }, 403);

    if (data.action === 'delete') {
      await env.db.prepare('DELETE FROM notebooks WHERE user_id = ?').bind(uid).run();
      await env.db.prepare('DELETE FROM users WHERE id = ?').bind(uid).run();
      return json({ ok: true });
    }
    
    if (data.action === 'demote') {
      await env.db.prepare('UPDATE users SET role = "骑士" WHERE id = ?').bind(uid).run();
      // delete notebooks
      await env.db.prepare('DELETE FROM notebooks WHERE user_id = ?').bind(uid).run();
      return json({ ok: true });
    }
    
    if (data.action === 'set-expire') {
      const days = parseInt(data.days) || 7;
      const expireUntil = Date.now() + 1000 * 60 * 60 * 24 * days;
      await env.db.prepare('UPDATE users SET expire_until = ? WHERE id = ?').bind(expireUntil, uid).run();
      return json({ ok: true });
    }
    
    if (data.action === 'reset-password') {
      const newPw = data.newPassword || 'password123';
      const pwHash = await hash(newPw);
      await env.db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').bind(pwHash, uid).run();
      return json({ ok: true, newPassword: newPw });
    }
    
    if (data.action === 'change-role') {
      const newRole = ['骑士', '贵族'].includes(data.role) ? data.role : '骑士';
      await env.db.prepare('UPDATE users SET role = ? WHERE id = ?').bind(newRole, uid).run();
      return json({ ok: true });
    }
    
    return json({ error: '未知操作' }, 400);
  } catch (e) {
    console.error('管理员修改用户失败:', e);
    return json({ error: '修改用户失败: ' + e.message }, 500);
  }
}

async function handleApi(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.replace('/api', '') || '/';
  
  try {
    if (path === '/register' && request.method === 'POST') return apiRegister(request, env);
    if (path === '/login' && request.method === 'POST') return apiLogin(request, env);
    if (path === '/logout' && request.method === 'POST') return apiLogout(request, env);
    if (path === '/me' && request.method === 'GET') return apiMe(request, env);
    if (path === '/change-password' && request.method === 'POST') return apiChangePassword(request, env);
    if (path === '/notebooks' && request.method === 'GET') return apiListNotebooks(request, env);
    if (path === '/notebooks' && request.method === 'POST') return apiCreateNotebook(request, env);
    
    if (path.startsWith('/notebooks/')) {
      const parts = path.split('/').filter(Boolean);
      if (parts.length < 2) return json({ error: '无效的笔记ID' }, 400);
      
      const id = parts[1];
      if (request.method === 'GET') return apiGetNotebook(request, env, id);
      if (request.method === 'PUT') return apiUpdateNotebook(request, env, id);
      if (request.method === 'DELETE') return apiDeleteNotebook(request, env, id);
      if (request.method === 'POST' && path.endsWith('/share')) return apiShareNotebook(request, env, id);
    }
    
    if (path === '/admin/users' && request.method === 'GET') return apiAdminListUsers(request, env);
    if (path.startsWith('/admin/users/') && request.method === 'POST') {
      const parts = path.split('/').filter(Boolean);
      const uid = parts[2];
      return apiAdminModifyUser(request, env, uid);
    }
    
    return json({ error: 'API端点不存在' }, 404);
  } catch (e) {
    console.error('API处理错误:', e);
    return json({ error: '服务器内部错误: ' + e.message }, 500);
  }
}

// ---------- Share handler (public) ----------
async function handleShare(request, env) {
  try {
    const token = request.url.split('/share/')[1]?.split('?')[0]?.split('#')[0];
    if (!token) return new Response('分享不存在', { status: 404 });
    // 优先使用 db1.shares
    let obj = null;
    try {
      const now = Date.now();
      const row = await env.db1.prepare('SELECT notebook_id FROM shares WHERE token = ? AND (expire_at IS NULL OR expire_at > ?)')
        .bind(token, now).first();
      if (!row || !row.notebook_id) return new Response('分享不存在或已过期', { status: 404 });
      obj = { id: row.notebook_id };
    } catch (e) {
      console.error('读取 share 失败:', e);
      return new Response('分享链接无效', { status: 500 });
    }
    const row = await env.db.prepare('SELECT title, content FROM notebooks WHERE id = ?').bind(obj.id).first();
    
    if (!row) return new Response('未找到内容', { status: 404 });
    
    // render simple read-only page showing notebook
    return new Response(renderHtmlShare(row.title, row.content), { 
      headers: { 
        'content-type': 'text/html; charset=utf-8',
        'Cache-Control': 'public, max-age=3600'
      } 
    });
  } catch (e) {
    console.error('处理分享失败:', e);
    return new Response('分享链接无效', { status: 500 });
  }
}

// ---------- HTML / Frontend ----------
function renderHtmlShare(title, content) {
  return `<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title><style>body{font-family:Inter,system-ui,Segoe UI,Arial;background:#f3f8ff;color:#0b2545;padding:20px}pre{white-space:pre-wrap;background:#fff;padding:16px;border-radius:8px;box-shadow:0 6px 18px rgba(11,37,69,.06)}</style></head><body><h1>${escapeHtml(title)}</h1><pre>${escapeHtml(content)}</pre></body></html>`;
}

function htmlIndex(request, env) {
  // 默认中文页面
  return new Response(renderHtmlApp(), { 
    headers: { 
      'content-type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache'
    } 
  });
}

function renderHtmlApp() {
  // 仅保留中文文案
  const L = {
    title: '点我! 记事本', 
    newBtn: '新建', 
    save: '保存', 
    share: '分享', 
    del: '删除', 
    login: '登录/注册', 
    myNotebooks: '我的笔记本', 
    enterNotebooks: '进入笔记本', 
    changePw: '修改密码', 
    logout: '退出', 
    noNotes: '请新建笔记本喵~', 
    clickHint: '请点左侧笔记本或新建喵~', 
    createHint: '请输入内容喵~', 
    confirmDelete: '确认删除？'
  };

  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
  <title>${L.title}</title>
  <style>
    :root{
      --primary: #64b5f6;
      --primary-dark: #2b8fd6;
      --primary-light: #bfe9ff;
      --secondary: #03dac6;
      --background: #f5f5f5;
      --surface: #ffffff;
      --error: #b00020;
      --on-primary: #ffffff;
      --on-secondary: #000000;
      --on-background: #000000;
      --on-surface: #000000;
      --on-error: #ffffff;
      --shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
      --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }
    
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    
    html, body {
      height: 100%;
      font-family: 'Roboto', 'Noto Sans SC', system-ui, -apple-system, sans-serif;
      background-color: var(--background);
      color: var(--on-background);
      overflow: hidden;
    }
    
    body {
      display: flex;
      flex-direction: column;
    }
    
    .app-bar {
      background-color: var(--primary);
      color: var(--on-primary);
      padding: 0 16px;
      height: 56px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      box-shadow: var(--shadow);
      z-index: 10;
    }
    
    .app-bar h1 {
      font-size: 20px;
      font-weight: 500;
    }
    
    .main-container {
      display: flex;
      flex: 1;
      overflow: hidden;
    }
    
    .sidebar {
      width: 300px;
      background-color: var(--surface);
      box-shadow: 1px 0 3px rgba(0, 0, 0, 0.1);
      display: flex;
      flex-direction: column;
      transform: translateX(0);
      transition: var(--transition);
      z-index: 5;
    }
    
    @media (max-width: 768px) {
      .sidebar {
        position: absolute;
        height: calc(100% - 56px);
        top: 56px;
        left: 0;
        transform: translateX(-100%);
      }
      
      .sidebar.open {
        transform: translateX(0);
      }
      
      .overlay {
        position: absolute;
        top: 56px;
        left: 0;
        right: 0;
        bottom: 0;
        background-color: rgba(0, 0, 0, 0.5);
        z-index: 4;
        opacity: 0;
        pointer-events: none;
        transition: var(--transition);
      }
      
      .overlay.active {
        opacity: 1;
        pointer-events: all;
      }
    }
    
    .sidebar-header {
      padding: 16px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid rgba(0, 0, 0, 0.1);
    }
    
    .sidebar-header strong {
      font-size: 16px;
      font-weight: 500;
    }
    
    .notebooks-list {
      flex: 1;
      overflow-y: auto;
    }
    
    .notebook {
      padding: 16px;
      border-bottom: 1px solid rgba(0, 0, 0, 0.05);
      cursor: pointer;
      transition: var(--transition);
      display: flex;
      flex-direction: column;
      position: relative;
      overflow: hidden;
    }
    
    .notebook::after {
      content: '';
      position: absolute;
      left: 0;
      top: 0;
      width: 4px;
      height: 100%;
      background-color: var(--primary);
      transform: translateX(-100%);
      transition: var(--transition);
    }
    
    .notebook:hover {
      background-color: rgba(0, 0, 0, 0.03);
    }
    
    .notebook.selected {
      background-color: rgba(100, 181, 246, 0.05);
    }
    
    .notebook.selected::after {
      transform: translateX(0);
    }
    
    .notebook .title {
      font-weight: 500;
      margin-bottom: 4px;
      color: var(--on-surface);
    }
    
    .notebook .meta {
      font-size: 12px;
      color: rgba(0, 0, 0, 0.54);
    }
    
    .empty-state {
      padding: 24px;
      text-align: center;
      color: rgba(0, 0, 0, 0.54);
      font-size: 14px;
    }
    
    .editor-container {
      flex: 1;
      display: flex;
      flex-direction: column;
      background-color: var(--surface);
      overflow: hidden;
      position: relative;
    }
    
    .editor-toolbar {
      padding: 16px;
      border-bottom: 1px solid rgba(0, 0, 0, 0.1);
    }
    
    .title-input {
      width: 100%;
      border: none;
      outline: none;
      font-size: 18px;
      font-weight: 500;
      background: transparent;
      color: var(--on-surface);
      padding: 8px 0;
      border-bottom: 2px solid transparent;
      transition: var(--transition);
    }
    
    .title-input:focus {
      border-bottom: 2px solid var(--primary);
    }
    
    .content-input {
      flex: 1;
      border: none;
      outline: none;
      padding: 16px;
      resize: none;
      font-family: inherit;
      font-size: 16px;
      line-height: 1.5;
      background: transparent;
      color: var(--on-surface);
    }
    
    .editor-actions {
      padding: 16px;
      border-top: 1px solid rgba(0, 0, 0, 0.1);
      display: flex;
      justify-content: flex-end;
      gap: 8px;
    }
    
    .btn {
      background-color: transparent;
      border: none;
      border-radius: 4px;
      padding: 8px 16px;
      font-size: 14px;
      font-weight: 500;
      cursor: pointer;
      transition: var(--transition);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
    }
    
    .btn i {
      font-size: 18px;
    }
    
    .btn:hover {
      background-color: rgba(0, 0, 0, 0.05);
    }
    
    .btn:active {
      background-color: rgba(0, 0, 0, 0.1);
      transform: translateY(1px);
    }
    
    .btn-primary {
      background-color: var(--primary);
      color: var(--on-primary);
    }
    
    .btn-primary:hover {
      background-color: var(--primary-dark);
    }
    
    .btn-primary:active {
      background-color: var(--primary-dark);
    }
    
    .btn-icon {
      width: 40px;
      height: 40px;
      padding: 0;
      border-radius: 50%;
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }
    
    .menu-btn {
      width: 40px;
      height: 40px;
      display: flex;
      align-items: center;
      justify-content: center;
      border-radius: 50%;
      background: transparent;
      border: none;
      cursor: pointer;
      transition: var(--transition);
    }
    
    .menu-btn:hover {
      background-color: rgba(255, 255, 255, 0.1);
    }
    
    .menu-btn .line {
      width: 24px;
      height: 2px;
      background-color: white;
      position: relative;
    }
    
    .menu-btn .line::before,
    .menu-btn .line::after {
      content: '';
      position: absolute;
      width: 24px;
      height: 2px;
      background-color: white;
      left: 0;
      transition: var(--transition);
    }
    
    .menu-btn .line::before {
      top: -8px;
    }
    
    .menu-btn .line::after {
      top: 8px;
    }
    
    .menu-btn.active .line {
      background-color: transparent;
    }
    
    .menu-btn.active .line::before {
      transform: rotate(45deg) translate(5px, 5px);
    }
    
    .menu-btn.active .line::after {
      transform: rotate(-45deg) translate(5px, -5px);
    }
    
    .account-area {
      display: flex;
      align-items: center;
    }
    
    .account-btn {
      color: var(--on-primary);
      background: transparent;
      border: none;
      font-size: 14px;
      font-weight: 500;
      cursor: pointer;
      padding: 8px 12px;
      border-radius: 4px;
      transition: var(--transition);
    }
    
    .account-btn:hover {
      background-color: rgba(255, 255, 255, 0.1);
    }
    
    .modal-backdrop {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background-color: rgba(0, 0, 0, 0.5);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 100;
      opacity: 0;
      pointer-events: none;
      transition: var(--transition);
    }
    
    .modal-backdrop.active {
      opacity: 1;
      pointer-events: all;
    }
    
    .modal {
      background-color: var(--surface);
      border-radius: 12px;
      width: 90%;
      max-width: 560px;
      max-height: 80vh;
      overflow-y: auto;
      transform: translateY(20px);
      transition: var(--transition);
      box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
    }
    
    .modal-backdrop.active .modal {
      transform: translateY(0);
    }
    
    .modal-header {
      padding: 24px 24px 16px;
      border-bottom: 1px solid rgba(0, 0, 0, 0.1);
    }
    
    .modal-title {
      font-size: 20px;
      font-weight: 500;
      color: var(--on-surface);
    }
    
    .modal-body {
      padding: 24px;
    }
    
    .modal-footer {
      padding: 16px 24px;
      border-top: 1px solid rgba(0, 0, 0, 0.1);
      display: flex;
      justify-content: flex-end;
      gap: 8px;
    }
    
    .message {
      margin-bottom: 16px;
      color: var(--on-surface);
      line-height: 1.5;
    }
    
    .auth-tabs {
      display: flex;
      margin-bottom: 24px;
      border-bottom: 1px solid rgba(0, 0, 0, 0.1);
    }
    
    .auth-tabs button {
      flex: 1;
      padding: 12px;
      background: transparent;
      border: none;
      font-size: 16px;
      font-weight: 500;
      color: rgba(0, 0, 0, 0.54);
      cursor: pointer;
      position: relative;
      transition: var(--transition);
    }
    
    .auth-tabs button.active {
      color: var(--primary);
    }
    
    .auth-tabs button.active::after {
      content: '';
      position: absolute;
      bottom: -1px;
      left: 0;
      width: 100%;
      height: 2px;
      background-color: var(--primary);
    }
    
    .auth-field {
      margin-bottom: 16px;
    }
    
    .auth-field input {
      width: 100%;
      padding: 12px 16px;
      border: 1px solid rgba(0, 0, 0, 0.2);
      border-radius: 4px;
      font-size: 16px;
      transition: var(--transition);
    }
    
    .auth-field input:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(100, 181, 246, 0.2);
    }
    
    .account-menu {
      position: absolute;
      right: 16px;
      top: 64px;
      background-color: var(--surface);
      border-radius: 4px;
      box-shadow: var(--shadow);
      min-width: 200px;
      z-index: 100;
      transform-origin: top right;
      transform: scale(0.9);
      opacity: 0;
      pointer-events: none;
      transition: var(--transition);
    }
    
    .account-menu.active {
      transform: scale(1);
      opacity: 1;
      pointer-events: all;
    }
    
    .account-menu-item {
      padding: 12px 16px;
      cursor: pointer;
      transition: var(--transition);
      display: flex;
      align-items: center;
      gap: 12px;
      font-size: 14px;
    }
    
    .account-menu-item:hover {
      background-color: rgba(0, 0, 0, 0.05);
    }
    
    .account-menu-divider {
      height: 1px;
      background-color: rgba(0, 0, 0, 0.1);
      margin: 8px 0;
    }
    
    .loader {
      width: 48px;
      height: 48px;
      border: 3px solid var(--primary-light);
      border-bottom-color: transparent;
      border-radius: 50%;
      display: inline-block;
      box-sizing: border-box;
      animation: rotation 1s linear infinite;
    }
    
    @keyframes rotation {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
    
    .fade-in {
      animation: fadeIn 0.3s ease forwards;
    }
    
    @keyframes fadeIn {
      from { opacity: 0; }
      to { opacity: 1; }
    }
    
    .slide-in {
      animation: slideIn 0.3s ease forwards;
    }
    
    @keyframes slideIn {
      from { transform: translateX(-20px); opacity: 0; }
      to { transform: translateX(0); opacity: 1; }
    }
    
    .empty-editor {
      flex: 1;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 24px;
      color: rgba(0, 0, 0, 0.54);
      text-align: center;
    }
    
    .empty-editor i {
      font-size: 48px;
      margin-bottom: 16px;
      color: rgba(0, 0, 0, 0.3);
    }
    
    .toast {
      position: fixed;
      bottom: 24px;
      left: 50%;
      transform: translateX(-50%) translateY(100px);
      background-color: rgba(0, 0, 0, 0.8);
      color: white;
      padding: 12px 24px;
      border-radius: 4px;
      font-size: 14px;
      z-index: 1000;
      transition: var(--transition);
    }
    
    .toast.active {
      transform: translateX(-50%) translateY(0);
    }
  </style>
  <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
</head>
<body>
  <header class="app-bar">
    <button class="menu-btn" id="menuBtn">
      <span class="line"></span>
    </button>
    <h1>${L.title}</h1>
    <div class="account-area" id="accountArea">
      <button class="account-btn" id="authBtn">${L.login}</button>
    </div>
  </header>
  
  <div class="overlay" id="sidebarOverlay"></div>
  
  <div class="main-container">
    <div class="sidebar" id="sidebar">
      <div class="sidebar-header">
        <strong>${L.myNotebooks}</strong>
        <button class="btn btn-primary" id="newBtn">
          <i class="material-icons">add</i> ${L.newBtn}
        </button>
      </div>
      <div class="notebooks-list" id="list"></div>
    </div>
    
    <div class="editor-container" id="editorContainer">
      <div class="editor-toolbar">
        <input class="title-input" id="titleInput" placeholder="${L.clickHint}">
      </div>
      <textarea class="content-input" id="content" placeholder="${L.createHint}"></textarea>
      <div class="editor-actions">
        <button class="btn" id="shareBtn">
          <i class="material-icons">share</i> ${L.share}
        </button>
        <button class="btn" id="deleteBtn">
          <i class="material-icons">delete</i> ${L.del}
        </button>
        <button class="btn btn-primary" id="saveBtn">
          <i class="material-icons">save</i> ${L.save}
        </button>
      </div>
    </div>
  </div>
  
  <div class="account-menu" id="accountMenu">
    <div class="account-menu-item" id="enterNotebooksItem">
      <i class="material-icons">note</i>
      <span>${L.enterNotebooks}</span>
    </div>
    <div class="account-menu-item" id="changePwItem">
      <i class="material-icons">settings</i>
      <span>${L.changePw}</span>
    </div>
    <div class="account-menu-divider"></div>
    <div class="account-menu-item" id="logoutItem">
      <i class="material-icons">exit_to_app</i>
      <span>${L.logout}</span>
    </div>
  </div>
  
  <div class="toast" id="toast"></div>

  <script>
    const STR = ${JSON.stringify(L)};
    
    const menuBtn = document.getElementById('menuBtn');
    const sidebar = document.getElementById('sidebar');
    const sidebarOverlay = document.getElementById('sidebarOverlay');
    const accountMenu = document.getElementById('accountMenu');
    const toast = document.getElementById('toast');
    
    function showToast(message, duration = 3000) {
      toast.textContent = message;
      toast.classList.add('active');
      setTimeout(() => {
        toast.classList.remove('active');
      }, duration);
    }
    
    function showShareLink(link){
      return new Promise((resolve)=>{
        const backdrop = document.createElement('div');
        backdrop.className = 'modal-backdrop';
        const modal = document.createElement('div');
        modal.className = 'modal';
        
        const header = document.createElement('div');
        header.className = 'modal-header';
        const title = document.createElement('div');
        title.className = 'modal-title';
        title.textContent = '分享链接';
        header.appendChild(title);
        
        const body = document.createElement('div');
        body.className = 'modal-body';
        const msg = document.createElement('div');
        msg.className = 'message';
        msg.textContent = '分享链接（直接打开可查看）';
        const linkEl = document.createElement('div');
        linkEl.style.padding = '12px';
        linkEl.style.background = '#f5f5f5';
        linkEl.style.borderRadius = '4px';
        linkEl.style.wordBreak = 'break-all';
        linkEl.style.margin = '16px 0';
        linkEl.textContent = link;
        body.appendChild(msg);
        body.appendChild(linkEl);
        
        const footer = document.createElement('div');
        footer.className = 'modal-footer';
        const copyBtn = document.createElement('button');
        copyBtn.className = 'btn';
        copyBtn.innerHTML = '<i class="material-icons">content_copy</i> 复制链接';
        copyBtn.onclick = async ()=>{
          try {
            await navigator.clipboard.writeText(link);
            showToast('已复制到剪贴板');
          } catch(e) {
            showToast('复制失败，请手动复制');
          }
        };
        const closeBtn = document.createElement('button');
        closeBtn.className = 'btn btn-primary';
        closeBtn.textContent = '关闭';
        closeBtn.onclick = ()=>{
          backdrop.classList.remove('active');
          setTimeout(() => {
            document.body.removeChild(backdrop);
          }, 300);
          resolve();
        };
        footer.appendChild(copyBtn);
        footer.appendChild(closeBtn);
        
        modal.appendChild(header);
        modal.appendChild(body);
        modal.appendChild(footer);
        backdrop.appendChild(modal);
        document.body.appendChild(backdrop);
        
        setTimeout(() => {
          backdrop.classList.add('active');
        }, 10);
      });
    }

    const api = {
      get: (p) => fetch('/api'+p, { credentials: 'same-origin' }).then(r=>r.json()).catch(err => {
        console.error('GET请求失败:', p, err);
        return { error: '网络错误' };
      }),
      post: (p, b) => fetch('/api'+p, {
        method:'POST',
        credentials:'same-origin',
        headers:{'content-type':'application/json'},
        body:JSON.stringify(b)
      }).then(r=>r.json()).catch(err => {
        console.error('POST请求失败:', p, err);
        return { error: '网络错误' };
      }),
      put: (p, b) => fetch('/api'+p, {
        method:'PUT',
        credentials:'same-origin',
        headers:{'content-type':'application/json'},
        body:JSON.stringify(b)
      }).then(r=>r.json()).catch(err => {
        console.error('PUT请求失败:', p, err);
        return { error: '网络错误' };
      }),
      del: (p) => fetch('/api'+p, {
        method:'DELETE',
        credentials:'same-origin'
      }).then(r=>r.json()).catch(err => {
        console.error('DELETE请求失败:', p, err);
        return { error: '网络错误' };
      })
    };

    let current = null;
    let me = null;

    function showModal(options) {
      return new Promise((resolve) => {
        const backdrop = document.createElement('div');
        backdrop.className = 'modal-backdrop';
        const modal = document.createElement('div');
        modal.className = 'modal';
        
        if (options.title) {
          const header = document.createElement('div');
          header.className = 'modal-header';
          const title = document.createElement('div');
          title.className = 'modal-title';
          title.textContent = options.title;
          header.appendChild(title);
          modal.appendChild(header);
        }
        
        const body = document.createElement('div');
        body.className = 'modal-body';
        if (typeof options.content === 'string') {
          const msg = document.createElement('div');
          msg.className = 'message';
          msg.textContent = options.content;
          body.appendChild(msg);
        } else if (options.content) {
          body.appendChild(options.content);
        }
        modal.appendChild(body);
        
        if (options.actions) {
          const footer = document.createElement('div');
          footer.className = 'modal-footer';
          options.actions.forEach(action => {
            const btn = document.createElement('button');
            btn.className = action.primary ? 'btn btn-primary' : 'btn';
            btn.textContent = action.text;
            btn.onclick = () => {
              backdrop.classList.remove('active');
              setTimeout(() => {
                document.body.removeChild(backdrop);
              }, 300);
              action.callback && action.callback();
              resolve(action.value);
            };
            footer.appendChild(btn);
          });
          modal.appendChild(footer);
        }
        
        backdrop.appendChild(modal);
        document.body.appendChild(backdrop);
        
        if (options.closable !== false) {
          backdrop.addEventListener('click', (e) => {
            if (e.target === backdrop) {
              backdrop.classList.remove('active');
              setTimeout(() => {
                document.body.removeChild(backdrop);
              }, 300);
              resolve(null);
            }
          });
        }
        
        setTimeout(() => {
          backdrop.classList.add('active');
        }, 10);
      });
    }

    function showModalConfirm(message) {
      return showModal({
        title: '确认',
        content: message,
        actions: [
          { text: '确定', primary: true, value: true },
          { text: '取消', value: false }
        ]
      });
    }

    function showModalAlert(message) {
      return showModal({
        title: '提示',
        content: message,
        actions: [
          { text: '确定', primary: true }
        ]
      });
    }

    function showAuthModal(){
      return new Promise((resolve)=>{
        const content = document.createElement('div');
        
        const tabs = document.createElement('div');
        tabs.className = 'auth-tabs';
        const btnLogin = document.createElement('button');
        btnLogin.textContent = '登录';
        btnLogin.className = 'active';
        const btnReg = document.createElement('button');
        btnReg.textContent = '注册';
        tabs.appendChild(btnLogin);
        tabs.appendChild(btnReg);
        
        const fields = document.createElement('div');
        fields.className = 'auth-fields';
        
        const userField = document.createElement('div');
        userField.className = 'auth-field';
        const userInput = document.createElement('input');
        userInput.placeholder = '用户名';
        userField.appendChild(userInput);
        
        const pwField = document.createElement('div');
        pwField.className = 'auth-field';
        const pwInput = document.createElement('input');
        pwInput.type = 'password';
        pwInput.placeholder = '密码';
        pwField.appendChild(pwInput);
        
        fields.appendChild(userField);
        fields.appendChild(pwField);
        
        content.appendChild(tabs);
        content.appendChild(fields);
        
        let mode = 'login';
        
        btnLogin.addEventListener('click', () => {
          mode = 'login';
          btnLogin.classList.add('active');
          btnReg.classList.remove('active');
        });
        
        btnReg.addEventListener('click', () => {
          mode = 'reg';
          btnReg.classList.add('active');
          btnLogin.classList.remove('active');
        });
        
        showModal({
          title: mode === 'login' ? '登录' : '注册',
          content: content,
          actions: [
            { 
              text: '提交', 
              primary: true,
              callback: async () => {
                const username = userInput.value && userInput.value.trim();
                const password = pwInput.value && pwInput.value.trim();
                
                if (!username || !password) {
                  showToast('请完整填写信息');
                  return false;
                }
                
                if (mode === 'reg') {
                  const r = await api.post('/register', { username, password });
                  if (r.ok) {
                    showToast('注册成功');
                    resolve({ ok: true });
                  } else {
                    showToast(r.error || '注册失败');
                  }
                } else {
                  const r = await api.post('/login', { username, password });
                  if (r.ok) {
                    showToast('登录成功');
                    resolve({ ok: true });
                  } else {
                    showToast(r.error || '登录失败');
                  }
                }
              }
            },
            { text: '取消' }
          ]
        });
        
        setTimeout(() => userInput.focus(), 300);
      });
    }

    function updateAccountArea(){
      const area = document.getElementById('accountArea');
      area.innerHTML = '';
      
      if (me && me.username) {
        const btn = document.createElement('button');
        btn.className = 'account-btn';
        btn.textContent = me.username + (me.role ? (' (' + me.role + ')') : '');
        btn.id = 'accountBtn';
        btn.onclick = (e) => {
          e.stopPropagation();
          accountMenu.classList.toggle('active');
        };
        area.appendChild(btn);
      } else {
        const b = document.createElement('button');
        b.className = 'account-btn';
        b.id = 'authBtn';
        b.textContent = STR.login;
        b.onclick = async () => {
          const r = await showAuthModal();
          if (r && r.ok) {
            await initAuth();
            await refreshList();
          }
        };
        area.appendChild(b);
      }
    }

    async function initAuth() {
      const r = await api.get('/me');
      if (r && r.user) {
        me = r.user;
      } else {
        me = null;
      }
      updateAccountArea();
    }

    async function accountSettings() {
      if (!me) {
        await showModalAlert('未登录');
        return;
      }
      
      const newPw = prompt('输入新密码（留空取消）');
      if (!newPw) return;
      
      const oldPw = prompt('输入原密码以确认');
      if (!oldPw) return;
      
      const res = await api.post('/change-password', { oldPassword: oldPw, newPassword: newPw });
      if (res.ok) {
        showToast('密码已修改');
      } else {
        showToast(res.error || '修改失败');
      }
    }

    async function refreshList() {
      const listEl = document.getElementById('list');
      listEl.innerHTML = '<div style="display: flex; justify-content: center; padding: 24px;"><span class="loader"></span></div>';
      
      try {
        const res = await api.get('/notebooks');
        
        listEl.innerHTML = '';
        
        if (!res.notebooks || res.notebooks.length === 0) {
          listEl.innerHTML = \`
            <div class="empty-state fade-in">
              <i class="material-icons" style="font-size: 48px; margin-bottom: 16px; color: rgba(0,0,0,0.3);">note_add</i>
              <div>\${STR.noNotes}</div>
            </div>
          \`;
          return;
        }
        
        res.notebooks.forEach((nb, index) => {
          const el = document.createElement('div');
          el.className = 'notebook';
          el.style.animationDelay = \`\${index * 50}ms\`;
          
          const title = document.createElement('div');
          title.className = 'title';
          title.textContent = nb.title || '无标题';
          
          const meta = document.createElement('div');
          meta.className = 'meta';
          meta.textContent = nb.updated_at ? new Date(nb.updated_at).toLocaleString() : '';
          
          el.appendChild(title);
          el.appendChild(meta);
          
          el.addEventListener('click', () => {
            document.querySelectorAll('.notebook').forEach(n => n.classList.remove('selected'));
            el.classList.add('selected');
            openNotebook(nb.id);
            
            if (window.innerWidth <= 768) {
              toggleSidebar(false);
            }
          });
          
          setTimeout(() => {
            el.classList.add('slide-in');
          }, 10);
          
          listEl.appendChild(el);
        });
      } catch (e) {
        console.error('刷新列表失败:', e);
        listEl.innerHTML = \`
          <div class="empty-state">
            <i class="material-icons" style="font-size: 48px; margin-bottom: 16px; color: rgba(0,0,0,0.3);">error</i>
            <div>加载失败，请重试</div>
          </div>
        \`;
      }
    }

    async function openNotebook(id) {
      const titleInput = document.getElementById('titleInput');
      const contentInput = document.getElementById('content');
      
      titleInput.disabled = true;
      contentInput.disabled = true;
      titleInput.placeholder = '加载中...';
      
      try {
        const res = await api.get('/notebooks/' + id);
        
        if (res.notebook) {
          current = res.notebook;
          
          titleInput.style.opacity = '0';
          contentInput.style.opacity = '0';
          
          setTimeout(() => {
            titleInput.value = current.title;
            contentInput.value = current.content;
            
            titleInput.style.transition = 'opacity 0.3s ease';
            contentInput.style.transition = 'opacity 0.3s ease';
            titleInput.style.opacity = '1';
            contentInput.style.opacity = '1';
          }, 200);
        } else if (res.error) {
          if (res.error === '未登录') {
            await showModalAlert('请先登录');
            const ar = await showAuthModal();
            if (ar && ar.ok) {
              await initAuth();
              await refreshList();
            }
          } else {
            await showModalAlert(res.error);
          }
        }
      } catch (e) {
        console.error('打开笔记失败:', e);
        await showModalAlert('加载失败: ' + e.message);
      } finally {
        titleInput.disabled = false;
        contentInput.disabled = false;
        titleInput.placeholder = STR.clickHint;
      }
    }

    function toggleSidebar(forceState) {
      const isOpen = sidebar.classList.contains('open');
      const shouldOpen = forceState !== undefined ? forceState : !isOpen;
      
      if (shouldOpen) {
        sidebar.classList.add('open');
        sidebarOverlay.classList.add('active');
        menuBtn.classList.add('active');
      } else {
        sidebar.classList.remove('open');
        sidebarOverlay.classList.remove('active');
        menuBtn.classList.remove('active');
      }
    }

    document.addEventListener('DOMContentLoaded', () => {
      menuBtn.addEventListener('click', () => {
        toggleSidebar();
      });
      
      sidebarOverlay.addEventListener('click', () => {
        toggleSidebar(false);
      });
      
      document.addEventListener('click', () => {
        accountMenu.classList.remove('active');
      });
      
      accountMenu.addEventListener('click', (e) => {
        e.stopPropagation();
      });
      
      document.getElementById('enterNotebooksItem').addEventListener('click', () => {
        accountMenu.classList.remove('active');
        if (window.innerWidth <= 768) {
          toggleSidebar(true);
        }
      });
      
      document.getElementById('changePwItem').addEventListener('click', async () => {
        accountMenu.classList.remove('active');
        await accountSettings();
      });
      
      document.getElementById('logoutItem').addEventListener('click', async () => {
        accountMenu.classList.remove('active');
        await api.post('/logout', {});
        me = null;
        current = null;
        document.getElementById('titleInput').value = '';
        document.getElementById('content').value = '';
        updateAccountArea();
        await refreshList();
        showToast('已退出登录');
      });
      
      document.getElementById('newBtn').addEventListener('click', async () => {
        if (!me) {
          await showModalAlert('请先登录');
          const ar = await showAuthModal();
          if (!ar || !ar.ok) return;
        }
        
        const res = await api.post('/notebooks', { title: '新笔记本', content: '' });
        if (res.id) {
          await refreshList();
          openNotebook(res.id);
          showToast('已创建新笔记本');
        } else {
          showToast(res.error || '创建失败');
        }
      });
      
      document.getElementById('saveBtn').addEventListener('click', async () => {
        if (!current) {
          return showToast('请选中笔记本');
        }
        
        if (!me) {
          await showModalAlert('请先登录');
          const ar = await showAuthModal();
          if (!ar || !ar.ok) return;
        }
        
        const title = document.getElementById('titleInput').value;
        const content = document.getElementById('content').value;
        
        const saveBtn = document.getElementById('saveBtn');
        const originalText = saveBtn.innerHTML;
        saveBtn.disabled = true;
        saveBtn.innerHTML = '<span class="loader" style="width: 16px; height: 16px; border-width: 2px;"></span> 保存中...';
        
        try {
          const res = await api.put('/notebooks/' + current.id, { title, content });
          if (res.ok) {
            await refreshList();
            showToast('已保存');
          } else {
            if (res.error === '未登录') {
              await showModalAlert('请先登录');
              const ar = await showAuthModal();
              if (ar && ar.ok) {
                await initAuth();
                await refreshList();
              }
            } else {
              showToast(res.error || '保存失败');
            }
          }
        } catch (e) {
          showToast('保存失败: ' + e.message);
        } finally {
          saveBtn.disabled = false;
          saveBtn.innerHTML = originalText;
        }
      });
      
      document.getElementById('deleteBtn').addEventListener('click', async () => {
        if (!current) {
          return showToast('请选中笔记本');
        }
        
        if (!me) {
          await showModalAlert('请先登录');
          return;
        }
        
        const ok = await showModalConfirm(STR.confirmDelete);
        if (!ok) return;
        
        try {
          const res = await api.del('/notebooks/' + current.id);
          if (res.ok) {
            current = null;
            document.getElementById('titleInput').value = '';
            document.getElementById('content').value = '';
            await refreshList();
            showToast('已删除');
          } else {
            showToast(res.error || '删除失败');
          }
        } catch (e) {
          showToast('删除失败: ' + e.message);
        }
      });
      
      document.getElementById('shareBtn').addEventListener('click', async () => {
        if (!current) {
          return showToast('请选中笔记本');
        }
        
        if (!me) {
          await showModalAlert('请先登录');
          return;
        }
        
        const shareBtn = document.getElementById('shareBtn');
        const originalText = shareBtn.innerHTML;
        shareBtn.disabled = true;
        shareBtn.innerHTML = '<span class="loader" style="width: 16px; height: 16px; border-width: 2px;"></span> 处理中...';
        
        try {
          const res = await api.post('/notebooks/' + current.id + '/share');
          if (res.link) {
            await showShareLink(res.link);
          } else {
            showToast(res.error || '分享失败');
          }
        } catch (e) {
          showToast('分享失败: ' + e.message);
        } finally {
          shareBtn.disabled = false;
          shareBtn.innerHTML = originalText;
        }
      });
      
      window.addEventListener('resize', () => {
        if (window.innerWidth > 768) {
          sidebar.classList.remove('open');
          sidebarOverlay.classList.remove('active');
          menuBtn.classList.remove('active');
        }
      });
      
      (async () => {
        await initAuth();
        await refreshList();
      })().catch((err) => {
        console.error('初始化失败:', err);
        showToast('初始化失败，请刷新页面');
      });
    });
  </script>
</body>
</html>`;
}

// ---------- 管理员页面 ----------
function renderAdminPage() {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>管理员面板 - 记事本系统</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: system-ui, -apple-system, sans-serif; background: #f5f5f5; padding: 20px; }
    .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); padding: 24px; }
    h1 { color: #333; margin-bottom: 24px; border-bottom: 1px solid #eee; padding-bottom: 16px; }
    .user-list { margin-top: 20px; }
    .user-item { padding: 16px; border: 1px solid #eee; border-radius: 4px; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center; }
    .user-info { flex: 1; }
    .user-actions { display: flex; gap: 8px; }
    .btn { padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; }
    .btn-danger { background: #ff4444; color: white; }
    .btn-warning { background: #ff8800; color: white; }
    .btn-primary { background: #64b5f6; color: white; }
    .btn-outline { background: transparent; border: 1px solid #6200ee; color: #6200ee; }
    .modal { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 1000; display: none; }
    .modal-content { background: white; border-radius: 8px; padding: 24px; min-width: 400px; }
    .modal-header { margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center; }
    .modal-close { cursor: pointer; font-size: 20px; color: #666; }
    .form-group { margin-bottom: 16px; }
    label { display: block; margin-bottom: 8px; font-weight: 500; }
    input, select { width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; }
    .toast { position: fixed; bottom: 20px; right: 20px; padding: 12px 24px; background: #333; color: white; border-radius: 4px; z-index: 1001; display: none; }
    .loader { text-align: center; padding: 40px; color: #666; }
  </style>
</head>
<body>
  <div class="container">
    <h1>管理员面板 <span style="font-size: 14px; color: #666; font-weight: normal;">皇帝专属</span></h1>
    <div class="loader" id="loader">加载用户列表中...</div>
    <div class="user-list" id="userList"></div>
  </div>

  <div class="modal" id="actionModal">
    <div class="modal-content">
      <div class="modal-header">
        <h3 id="modalTitle">操作用户</h3>
        <span class="modal-close" onclick="closeModal()">&times;</span>
      </div>
      <div class="form-group">
        <label>用户ID</label>
        <input type="text" id="userId" readonly>
      </div>
      <div class="form-group">
        <label>操作类型</label>
        <select id="actionType">
          <option value="set-expire">设置过期时间</option>
          <option value="reset-password">重置密码</option>
          <option value="change-role">修改角色</option>
          <option value="demote">降级并清空笔记</option>
          <option value="delete">删除用户</option>
        </select>
      </div>
      <div class="form-group" id="expireDaysGroup" style="display: none;">
        <label>过期天数</label>
        <input type="number" id="expireDays" value="7" min="1">
      </div>
      <div class="form-group" id="newRoleGroup" style="display: none;">
        <label>新角色</label>
        <select id="newRole">
          <option value="骑士">骑士</option>
          <option value="贵族">贵族</option>
        </select>
      </div>
      <button class="btn btn-primary" onclick="submitAction()">确认操作</button>
    </div>
  </div>

  <div class="toast" id="toast"></div>

  <script>
    let currentUserId = '';
    const toast = document.getElementById('toast');
    const modal = document.getElementById('actionModal');
    const actionType = document.getElementById('actionType');
    const expireDaysGroup = document.getElementById('expireDaysGroup');
    const newRoleGroup = document.getElementById('newRoleGroup');

    function showToast(msg, duration = 3000) {
      toast.textContent = msg;
      toast.style.display = 'block';
      setTimeout(() => {
        toast.style.display = 'none';
      }, duration);
    }

    function openModal(uid, username) {
      currentUserId = uid;
      document.getElementById('modalTitle').textContent = \`操作用户: \${username}\`;
      document.getElementById('userId').value = uid;
      modal.style.display = 'flex';
      toggleActionGroups();
    }

    function closeModal() {
      modal.style.display = 'none';
      currentUserId = '';
    }

    function toggleActionGroups() {
      expireDaysGroup.style.display = 'none';
      newRoleGroup.style.display = 'none';
      
      switch(actionType.value) {
        case 'set-expire':
          expireDaysGroup.style.display = 'block';
          break;
        case 'change-role':
          newRoleGroup.style.display = 'block';
          break;
      }
    }

    async function submitAction() {
      if (!currentUserId) return;
      
      const action = actionType.value;
      let data = { action };
      
      switch(action) {
        case 'set-expire':
          data.days = document.getElementById('expireDays').value;
          break;
        case 'reset-password':
          data.newPassword = 'password123';
          break;
        case 'change-role':
          data.role = document.getElementById('newRole').value;
          break;
      }

      try {
        const res = await fetch(\`/api/admin/users/\${currentUserId}\`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify(data)
        });
        
        const result = await res.json();
        if (result.ok) {
          showToast('操作成功');
          closeModal();
          loadUserList();
        } else {
          showToast('操作失败: ' + (result.error || '未知错误'));
        }
      } catch (err) {
        showToast('请求失败: ' + err.message);
      }
    }

    async function loadUserList() {
      document.getElementById('loader').style.display = 'block';
      document.getElementById('userList').style.display = 'none';
      
      try {
        const res = await fetch('/api/admin/users', { credentials: 'same-origin' });
        const result = await res.json();
        
        if (result.error) {
          document.getElementById('loader').textContent = '加载失败: ' + result.error;
          return;
        }

        const userList = document.getElementById('userList');
        userList.innerHTML = '';
        
        result.users.forEach(user => {
          if (user.role === '皇帝') return;
          
          const item = document.createElement('div');
          item.className = 'user-item';
          item.innerHTML = \`
            <div class="user-info">
              <h4>\${user.username}</h4>
              <p>ID: \${user.id} | 角色: \${user.role || '骑士'}</p>
            </div>
            <div class="user-actions">
              <button class="btn btn-outline" onclick="openModal('\${user.id}', '\${user.username}')">操作</button>
            </div>
          \`;
          userList.appendChild(item);
        });

        document.getElementById('loader').style.display = 'none';
        document.getElementById('userList').style.display = 'block';
      } catch (err) {
        document.getElementById('loader').textContent = '加载失败: ' + err.message;
      }
    }

    actionType.addEventListener('change', toggleActionGroups);

    window.addEventListener('click', (e) => {
      if (e.target === modal) closeModal();
    });

    loadUserList();
  </script>
</body>
</html>`;
}

// ---------- OPTIONS 处理 ----------
function handleOptions(request) {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Cookie',
    'Access-Control-Max-Age': '86400'
  };
  return new Response(null, { headers, status: 204 });
}

// ---------- 主入口 ----------
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    
    if (request.method === 'OPTIONS') {
      return handleOptions(request);
    }

    try {
      await ensureTables(env);
      await cleanupExpiredAccounts(env);
    } catch (e) {
      console.error('初始化数据库失败:', e);
    }

    // 路由
    if (url.pathname === '/' || url.pathname === '/index.html') return htmlIndex(request, env);
    if (url.pathname.startsWith('/share/')) return handleShare(request, env);
    if (url.pathname.startsWith('/api/')) return handleApi(request, env);
    
    // 管理员页面
    if (url.pathname === '/admin' && request.method === 'GET') {
      const user = await getUserFromSession(env, request);
      if (!user || user.role !== '皇帝') {
        return new Response('权限不足', { status: 403 });
      }
      return new Response(renderAdminPage(), {
        headers: { 'content-type': 'text/html; charset=utf-8' }
      });
    }
    
    return new Response('Not Found', { status: 404 });
  }
};
