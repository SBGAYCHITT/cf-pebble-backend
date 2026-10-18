// ============================================================
// PeBble_lunchar 云端后端 —— Cloudflare Pages Functions 版
// （免费 · 不绑卡 · 走 *.pages.dev）
//
// 与旧 Deno 版的区别：存储从 Deno KV 换成 Cloudflare Workers KV。
// 登录 / PBKDF2 哈希 / 转发逻辑全部复用，只改了存储层。
//
// 部署前准备（Cloudflare 控制台）：
//   1. 建一个 Workers KV 命名空间（随便起名，例如 pebble-kv）。
//   2. 在 Cloudflare Pages 项目里 → Settings → Functions → KV namespace bindings，
//      把上面那个命名空间绑定到变量名 KV（必须叫 KV，代码里就用它）。
//   3. 连 GitHub 仓库，Framework preset 选 None，
//      Build command 留空，Output directory 填 public。
// ============================================================

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};
function send(data, status = 200, extra) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS, ...(extra || {}) },
  });
}
function preflight() { return new Response(null, { status: 204, headers: CORS }); }

// ---------- KV 键：用 ":" 拼接（用户名里别用冒号） ----------
const keyOf = (...parts) => parts.join(":");
// KV 绑定名固定叫 KV（见文件头说明）
function kvOf(env) { return env && env.KV; }

// ---------- 密码哈希 (PBKDF2, Web Crypto，和 Deno 版完全一致) ----------
const enc = new TextEncoder();
async function hashPassword(pw, salt) {
  const key = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, key, 256);
  return Array.from(new Uint8Array(bits)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
const newSalt = () => crypto.getRandomValues(new Uint8Array(16));
const b64 = (u) => btoa(String.fromCharCode.apply(null, u));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

// ---------- 鉴权：解析 Bearer token（从 KV 读） ----------
async function authUser(req, kv) {
  const m = (req.headers.get("Authorization") || "").match(/^Bearer\s+(.+)$/);
  if (!m) return null;
  const v = await kv.get("token:" + m[1], "json");
  if (!v) return null;
  if (v.exp && Date.now() > v.exp) { await kv.delete("token:" + m[1]); return null; }
  return v.username;
}

export async function onRequest(context) {
  const req = context.request;
  if (req.method === "OPTIONS") return preflight();

  const kv = kvOf(context.env);
  if (!kv) {
    return send({ error: "KV 未绑定：请在 Cloudflare Pages 项目里把 Workers KV 命名空间绑定到变量名 KV（见文件头说明）。" }, 503);
  }

  const url = new URL(req.url);
  const p = url.pathname;

  // 注册
  if (p === "/api/auth/register" && req.method === "POST") {
    const { username, password } = await req.json().catch(() => ({}));
    if (typeof username !== "string" || username.length < 3) return send({ error: "用户名至少3位" }, 400);
    if (typeof password !== "string" || password.length < 6) return send({ error: "密码至少6位" }, 400);
    if (await kv.get(keyOf("user", username), "json")) return send({ error: "用户名已存在" }, 409);
    const salt = newSalt();
    const hash = await hashPassword(password, salt);
    await kv.put(keyOf("user", username), JSON.stringify({ username, salt: b64(salt), hash, createdAt: Date.now() }));
    return send({ ok: true });
  }

  // 登录 → 返回 token（30天有效）
  if (p === "/api/auth/login" && req.method === "POST") {
    const { username, password } = await req.json().catch(() => ({}));
    const u = await kv.get(keyOf("user", username), "json");
    if (!u) return send({ error: "用户不存在" }, 404);
    const hash = await hashPassword(password, unb64(u.salt));
    if (hash !== u.hash) return send({ error: "密码错误" }, 401);
    const token = crypto.randomUUID();
    const ttlSec = 30 * 24 * 3600; // 30 天
    await kv.put(keyOf("token", token), JSON.stringify({ username, exp: Date.now() + ttlSec * 1000 }), { expirationTtl: ttlSec });
    return send({ ok: true, token, username });
  }

  // 以下接口都需要登录
  const username = await authUser(req, kv);
  if (!username) return send({ error: "unauthorized" }, 401);

  if (p === "/api/me" && req.method === "GET") return send({ ok: true, username });

  // 列出该账号下所有 blob key
  if (p === "/api/blob" && req.method === "GET") {
    const prefix = keyOf("blob", username) + ":";
    const listed = await kv.list({ prefix });
    const keys = (listed.keys || []).map((e) => e.name.slice(prefix.length));
    return send({ ok: true, keys });
  }

  // 读/写/删 单个 blob (?key=xxx)
  if (p === "/api/blob/item") {
    const key = url.searchParams.get("key") || "";
    if (!key) return send({ error: "missing key" }, 400);
    const k = keyOf("blob", username, key);
    if (req.method === "GET") {
      const v = await kv.get(k, "json");
      return send({ ok: true, exists: !!v, data: v ? v.data : null });
    }
    if (req.method === "PUT") {
      const body = await req.json().catch(() => ({}));
      await kv.put(k, JSON.stringify({ data: body.data != null ? body.data : body, updatedAt: Date.now() }));
      return send({ ok: true });
    }
    if (req.method === "DELETE") {
      await kv.delete(k);
      return send({ ok: true });
    }
  }

  return send({ error: "not found" }, 404);
}
