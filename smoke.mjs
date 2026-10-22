#!/usr/bin/env node
// 后端冒烟：注册 → 登录 → 写 blob → 读回 → 删掉。
// 用来判断「KV 到底绑没绑上」，以及发布后接口有没有被改坏。
//
//   node smoke.mjs https://cf-pebble-backend.pages.dev
//
// 只依赖 node 内置 fetch（18+）。账号名带时间戳，跑完不留垃圾。

const BASE = (process.argv[2] || 'https://cf-pebble-backend.pages.dev').replace(/\/+$/, '');
const USER = 'smoke_' + Date.now().toString(36);
const PASS = 'pw-' + Math.random().toString(36).slice(2, 10);

let pass = 0;
let fail = 0;

// 标记用纯 ASCII 而不是 ANSI 颜色：cmd 控制台不一定支持 VT 转义，
// 不支持的话会直接把 [32m 当字面量打出来，看着像坏了。
function ok(name, detail = '') {
  pass++;
  console.log(`  [OK]   ${name}${detail ? '  ' + detail : ''}`);
}
function bad(name, detail = '') {
  fail++;
  console.log(`  [FAIL] ${name}${detail ? '  ' + detail : ''}`);
}
function check(name, cond, detail = '') {
  if (cond) ok(name, detail);
  else bad(name, detail);
  return cond;
}

async function raw(method, path, { token, body } = {}) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (token) headers['Authorization'] = 'Bearer ' + token;
  const res = await fetch(BASE + path, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try {
    data = await res.json();
  } catch {
    /* 非 JSON 就留 null */
  }
  return { status: res.status, data };
}

/**
 * 带重试的请求。
 *
 * 为什么必须重试：实测这台机器到 *.pages.dev 的链路会间歇超时
 * （同一个 Cloudflare 上的官网静态文件 8 次里有 3 次连不上，
 * 而同样时刻 GitHub 5 次全通）。这种抖动会让脚本"假失败"，
 * 让人以为后端坏了 —— 重试 3 次再判失败才是可信的。
 * HTTP 状态码（4xx/5xx）不算失败，直接返回，那才是后端真的有问题。
 */
async function req(method, path, opts = {}) {
  let last = null;
  for (let i = 0; i < 3; i++) {
    try {
      return await raw(method, path, opts);
    } catch (e) {
      last = e;
      await new Promise((r) => setTimeout(r, 600 * (i + 1)));
    }
  }
  const why = (last && (last.cause?.code || last.code)) || (last && last.message) || '未知原因';
  throw new Error(`${method} ${path} 连了 3 次都不通（${why}）—— 先怀疑本机到 Cloudflare 的网络，再怀疑后端`);
}

/** KV 最终一致：写完立刻读可能读不到，给它几秒钟 */
async function until(fn, tries = 8, gap = 400) {
  for (let i = 0; i < tries; i++) {
    const v = await fn();
    if (v) return v;
    await new Promise((r) => setTimeout(r, gap));
  }
  return null;
}

(async () => {
  console.log(`\n目标  ${BASE}\n账号  ${USER}\n`);

  /* 0. 第一道门：KV 绑没绑 */
  const me = await req('GET', '/api/me');
  if (me.status === 503) {
    bad('KV 绑定', me.data?.error || '503');
    console.log('\n  → 去 Pages 项目绑 KV 命名空间到变量名 KV，然后【重新部署一次】。\n');
    process.exit(1);
  }
  check('KV 已绑定（接口不再 503）', me.status !== 503, `HTTP ${me.status}`);

  /* 1. 未登录必须被拒 */
  check('未登录访问 /api/me 返回 401', me.status === 401, `HTTP ${me.status}`);

  /* 2. 注册 */
  const reg = await req('POST', '/api/auth/register', { body: { username: USER, password: PASS } });
  if (!check('注册成功', reg.status === 200 && reg.data?.ok === true, `HTTP ${reg.status} ${reg.data?.error || ''}`)) {
    console.log('\n  注册没过，后面的用例没有意义，先停。\n');
    process.exit(1);
  }

  /* 3. 重复注册必须 409（顺带验证 KV 真的写进去了） */
  const dup = await req('POST', '/api/auth/register', { body: { username: USER, password: PASS } });
  check('重复注册被拒 409', dup.status === 409, `HTTP ${dup.status}`);

  /* 4. 弱口令要被拦 */
  const weak = await req('POST', '/api/auth/register', { body: { username: 'x', password: '1' } });
  check('弱口令/短用户名被拒 400', weak.status === 400, `HTTP ${weak.status}`);

  /* 5. 错密码 */
  const badLogin = await req('POST', '/api/auth/login', { body: { username: USER, password: PASS + 'x' } });
  check('错误密码被拒 401', badLogin.status === 401, `HTTP ${badLogin.status}`);

  /* 6. 正确登录 */
  const login = await req('POST', '/api/auth/login', { body: { username: USER, password: PASS } });
  const token = login.data?.token;
  if (!check('登录返回 token', !!token, `HTTP ${login.status}`)) {
    console.log('\n  拿不到 token，后面跳过。\n');
    process.exit(1);
  }

  /* 7. token 可用 */
  const me2 = await req('GET', '/api/me', { token });
  check('带 token 读 /api/me', me2.status === 200 && me2.data?.username === USER, `HTTP ${me2.status}`);

  /* 8. 假 token 必须被拒 */
  const fake = await req('GET', '/api/me', { token: 'not-a-real-token' });
  check('伪造 token 被拒 401', fake.status === 401, `HTTP ${fake.status}`);

  /* 9. blob 写 → 读 → 列表 → 删 */
  const key = 'smoke/hello';
  const payload = { msg: '你好，Pebble', n: 42 };
  const w = await req('PUT', '/api/blob/item?key=' + encodeURIComponent(key), { token, body: { data: payload } });
  check('写入 blob', w.status === 200 && w.data?.ok === true, `HTTP ${w.status}`);

  const got = await until(async () => {
    const r = await req('GET', '/api/blob/item?key=' + encodeURIComponent(key), { token });
    return r.data?.exists ? r : null;
  });
  check('读回 blob 且内容一致', !!got && JSON.stringify(got.data.data) === JSON.stringify(payload));

  const list = await until(async () => {
    const r = await req('GET', '/api/blob', { token });
    return r.data?.keys?.includes(key) ? r : null;
  });
  check('列表里能看到该 key', !!list);

  const d = await req('DELETE', '/api/blob/item?key=' + encodeURIComponent(key), { token });
  check('删除 blob', d.status === 200, `HTTP ${d.status}`);

  /* 10. CORS 预检 */
  const pre = await fetch(BASE + '/api/me', { method: 'OPTIONS' });
  check(
    'CORS 预检 204 + 允许来源',
    pre.status === 204 && pre.headers.get('access-control-allow-origin') === '*',
    `HTTP ${pre.status}`,
  );

  /* 11. 健康检查 */
  const health = await req('GET', '/api/health');
  check(
    '健康检查 ok + KV 可用',
    health.status === 200 && health.data?.ok === true && health.data?.kv === true,
    `HTTP ${health.status}`,
  );

  /* 12. 公告：读不要登录，写必须管理员 */
  const ann = await req('GET', '/api/announcement');
  check('公告可匿名读取', ann.status === 200 && ann.data?.ok === true, `HTTP ${ann.status}`);

  const annPut = await req('PUT', '/api/announcement', { body: { text: 'smoke test', level: 'info' } });
  check(
    '写公告被管理员校验挡住（401/503 都算对）',
    annPut.status === 401 || annPut.status === 503,
    `HTTP ${annPut.status}`,
  );

  /* 13. 云端配置：登录后整包往返 */
  const cfg0 = await req('GET', '/api/config', { token });
  check('读云端配置', cfg0.status === 200 && cfg0.data?.ok === true, `HTTP ${cfg0.status}`);

  const cfgObj = { lang: 'zh-CN', autoUpdate: true, stamp: Date.now() };
  const cfgPut = await req('PUT', '/api/config', { token, body: { config: cfgObj } });
  check('写云端配置', cfgPut.status === 200 && cfgPut.data?.ok === true, `HTTP ${cfgPut.status}`);

  const cfg1 = await until(async () => {
    const r = await req('GET', '/api/config', { token });
    return r.data?.config && r.data.config.stamp === cfgObj.stamp ? r : null;
  });
  check('配置读回与写入一致', !!cfg1);

  /* 14. 边界：超大 payload、含冒号的 key */
  const huge = { text: 'x'.repeat(1024 * 1024 + 64) };
  const hugeRes = await req('PUT', '/api/blob/item?key=smoke/huge', { token, body: { data: huge } });
  check('超过 1MB 的 blob 被拒 413', hugeRes.status === 413, `HTTP ${hugeRes.status}`);

  const colonPut = await req('PUT', '/api/blob/item?key=' + encodeURIComponent('a:b'), {
    token,
    body: { data: 1 },
  });
  check('含冒号的 key 被拒 400', colonPut.status === 400, `HTTP ${colonPut.status}`);

  /* 15. 根路径应该回到静态页 */
  const root = await fetch(BASE + '/');
  check(
    '根路径返回 HTML（functions/api 不再拦截静态资源）',
    root.status === 200 && (root.headers.get('content-type') || '').includes('text/html'),
    `HTTP ${root.status}`,
  );

  /* 16. 未知路径 */
  // 注意鉴权在路由判断之前：不带 token 一律先 401（连"这路径存不存在"都不告诉你，
  // 这是故意的，别改成 404）。所以拿 token 再问才是 404。
  const nf = await req('GET', '/api/nope');
  check('未知路径未登录时先挡在鉴权上 401', nf.status === 401, `HTTP ${nf.status}`);
  const nf2 = await req('GET', '/api/nope', { token });
  check('已登录的未知路径返回 404', nf2.status === 404, `HTTP ${nf2.status}`);

  console.log(`\n通过 ${pass}  失败 ${fail}\n`);
  process.exit(fail ? 1 : 0);
})().catch((e) => {
  console.error('\n冒烟脚本自己炸了：', e.message, '\n');
  process.exit(2);
});
