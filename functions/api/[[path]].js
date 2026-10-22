// ============================================================
// Pebble Launcher 云端后端 —— Cloudflare Pages Functions
// （免费 · 不绑卡 · 走 *.pages.dev）
//
// 文件放在 functions/api/ 下，所以只接管 /api/*；
// 其余路径交回静态资源，访问根路径会正常看到 public/index.html。
//
// 部署前准备（Cloudflare 控制台）：
//   1. 建一个 Workers KV 命名空间（例如 pebble-kv）。
//   2. Pages 项目 → Settings → Functions → KV namespace bindings，
//      绑定到变量名 KV（必须叫 KV，代码里就用它）。
//   3. （可选）Settings → Environment variables 加 ADMIN_TOKEN，
//      用来保护 PUT /api/announcement。不配的话写公告接口直接 503，
//      读公告不受影响。
//   4. 连 GitHub 仓库，Framework preset 选 None，
//      Build command 留空，Output directory 填 public。
//
// 接口一览（★ 需要登录 / ☆ 无需登录 / ⚙ 需要 ADMIN_TOKEN）
//   ☆ GET    /api/health                 存活 + KV 是否可用
//   ☆ POST   /api/auth/register          注册
//   ☆ POST   /api/auth/login             登录，返回 30 天 token
//   ☆ GET    /api/announcement           读公共公告
//   ⚙ PUT    /api/announcement           写公告 {text, level}
//   ⚙ DELETE /api/announcement           清公告
//   ★ GET    /api/me                     当前用户
//   ★ GET    /api/config                 读云端配置
//   ★ PUT    /api/config                 写云端配置（≤100KB）
//   ★ GET    /api/blob                   列出该账号所有 key
//   ★ GET    /api/blob/item?key=         读
//   ★ PUT    /api/blob/item?key=         写（≤1MB）
//   ★ DELETE /api/blob/item?key=         删
// ============================================================

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Max-Age": "86400",
};

/** KV value 上限是 25MB，但启动器没理由传那么大 —— 故意卡在 1MB，防滥用 */
const MAX_BLOB_BYTES = 1024 * 1024;
/** 云端配置是启动器设置，100KB 已经很宽裕 */
const MAX_CONFIG_BYTES = 100 * 1024;
/** 公告是一句话，500 字够用 */
const MAX_ANNOUNCEMENT_CHARS = 500;

function send(data, status = 200, extra) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS, ...(extra || {}) },
  });
}
function preflight() {
  return new Response(null, { status: 204, headers: CORS });
}

// ---------- KV 键：用 ":" 拼接（用户名/key 里不许出现冒号） ----------
const keyOf = (...parts) => parts.join(":");
function kvOf(env) {
  return env && env.KV;
}

// ---------- 密码哈希 (PBKDF2, Web Crypto，和 Deno 版完全一致) ----------
const enc = new TextEncoder();
async function hashPassword(pw, salt) {
  const key = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    key,
    256,
  );
  return Array.from(new Uint8Array(bits))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
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
  if (v.exp && Date.now() > v.exp) {
    await kv.delete("token:" + m[1]);
    return null;
  }
  return v.username;
}

/**
 * 管理员鉴权：直接比环境变量里的 ADMIN_TOKEN。
 *
 * 为什么不复用用户 token：管理员不该是一个"特权账号"，
 * 那意味着要在 KV 里存一份特权凭证、还要处理它被盗的情况。
 * 一个只能通过控制台修改的环境变量更简单，也不会出现在任何客户端里。
 */
function isAdmin(req, env) {
  const want = env && env.ADMIN_TOKEN;
  if (!want) return null; // 未配置
  const got = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "").trim();
  return got && got === want ? true : false;
}

/** blob key 的合法性：非空、≤128、不含冒号（会打乱 kv 前缀） */
function badKey(key) {
  if (!key || typeof key !== "string") return "missing key";
  if (key.length > 128) return "key 太长（上限 128）";
  if (key.includes(":")) return "key 不能包含冒号";
  return null;
}

async function handle(context) {
  const req = context.request;
  if (req.method === "OPTIONS") return preflight();

  const kv = kvOf(context.env);
  if (!kv) {
    return send(
      { error: "KV 未绑定：请在 Cloudflare Pages 项目里把 Workers KV 命名空间绑定到变量名 KV（见文件头说明）。" },
      503,
    );
  }

  const url = new URL(req.url);
  const p = url.pathname.replace(/\/+$/, "") || "/api";

  /* ---------- 存活检查（不鉴权，运维和监控用） ---------- */
  if (p === "/api/health") {
    let kvOk = true;
    let detail = "ok";
    try {
      await kv.get("__probe__");
    } catch (e) {
      kvOk = false;
      detail = String((e && e.message) || e);
    }
    return send(
      { ok: kvOk, service: "pebble-backend", kv: kvOk, detail, time: new Date().toISOString() },
      kvOk ? 200 : 503,
    );
  }

  /* ---------- 公告：读不需要登录，启动器没账号也能看到 ---------- */
  if (p === "/api/announcement" && req.method === "GET") {
    const a = await kv.get("announcement:current", "json");
    return send({ ok: true, announcement: a || null });
  }

  if (p === "/api/announcement" && (req.method === "PUT" || req.method === "DELETE")) {
    const admin = isAdmin(req, context.env);
    if (admin === null) return send({ error: "服务端未配置 ADMIN_TOKEN，公告接口已关闭" }, 503);
    if (admin === false) return send({ error: "unauthorized" }, 401);

    if (req.method === "DELETE") {
      await kv.delete("announcement:current");
      return send({ ok: true, announcement: null });
    }

    const body = await req.json().catch(() => ({}));
    const text = String(body.text == null ? "" : body.text).trim();
    if (!text) return send({ error: "text 不能为空（清空请用 DELETE）" }, 400);
    if (text.length > MAX_ANNOUNCEMENT_CHARS) {
      return send({ error: `公告太长（上限 ${MAX_ANNOUNCEMENT_CHARS} 字）` }, 413);
    }
    const level = body.level === "warn" ? "warn" : "info";
    const a = { id: crypto.randomUUID(), text, level, updatedAt: Date.now() };
    await kv.put("announcement:current", JSON.stringify(a));
    return send({ ok: true, announcement: a });
  }

  /* ---------- 注册 ---------- */
  if (p === "/api/auth/register" && req.method === "POST") {
    const { username, password } = await req.json().catch(() => ({}));
    if (typeof username !== "string" || username.length < 3) return send({ error: "用户名至少3位" }, 400);
    if (typeof password !== "string" || password.length < 6) return send({ error: "密码至少6位" }, 400);
    if (username.length > 32) return send({ error: "用户名最长32位" }, 400);
    if (username.includes(":")) return send({ error: "用户名不能包含冒号" }, 400);
    if (await kv.get(keyOf("user", username), "json")) return send({ error: "用户名已存在" }, 409);
    const salt = newSalt();
    const hash = await hashPassword(password, salt);
    await kv.put(
      keyOf("user", username),
      JSON.stringify({ username, salt: b64(salt), hash, createdAt: Date.now() }),
    );
    return send({ ok: true });
  }

  /* ---------- 登录 → token（30 天） ---------- */
  if (p === "/api/auth/login" && req.method === "POST") {
    const { username, password } = await req.json().catch(() => ({}));
    if (typeof username !== "string" || typeof password !== "string") {
      return send({ error: "缺少用户名或密码" }, 400);
    }
    const u = await kv.get(keyOf("user", username), "json");
    if (!u) return send({ error: "用户不存在" }, 404);
    const hash = await hashPassword(password, unb64(u.salt));
    if (hash !== u.hash) return send({ error: "密码错误" }, 401);
    const token = crypto.randomUUID();
    const ttlSec = 30 * 24 * 3600;
    await kv.put(keyOf("token", token), JSON.stringify({ username, exp: Date.now() + ttlSec * 1000 }), {
      expirationTtl: ttlSec,
    });
    return send({ ok: true, token, username });
  }

  /* ---------- 以下都要登录 ---------- */
  const username = await authUser(req, kv);
  if (!username) return send({ error: "unauthorized" }, 401);

  if (p === "/api/me" && req.method === "GET") return send({ ok: true, username });

  /* ---------- 云端配置：整包读写，客户端自己决定里面放什么 ---------- */
  if (p === "/api/config") {
    if (req.method === "GET") {
      const c = await kv.get(keyOf("config", username), "json");
      return send({ ok: true, config: c ? c.config : null, updatedAt: c ? c.updatedAt : null });
    }
    if (req.method === "PUT") {
      const body = await req.json().catch(() => ({}));
      const config = body.config != null ? body.config : body;
      const raw = JSON.stringify(config);
      const bytes = enc.encode(raw).length;
      if (bytes > MAX_CONFIG_BYTES) {
        return send({ error: `配置太大（上限 ${MAX_CONFIG_BYTES} 字节，实际 ${bytes}）` }, 413);
      }
      const updatedAt = Date.now();
      await kv.put(keyOf("config", username), JSON.stringify({ config, updatedAt }));
      return send({ ok: true, updatedAt });
    }
    return send({ error: "method not allowed" }, 405);
  }

  /* ---------- blob：按 key 存任意 JSON ---------- */
  if (p === "/api/blob" && req.method === "GET") {
    const prefix = keyOf("blob", username) + ":";
    const listed = await kv.list({ prefix });
    const keys = (listed.keys || []).map((e) => e.name.slice(prefix.length));
    return send({ ok: true, keys });
  }

  if (p === "/api/blob/item") {
    const key = url.searchParams.get("key") || "";
    const problem = badKey(key);
    if (problem) return send({ error: problem }, 400);
    const k = keyOf("blob", username, key);

    if (req.method === "GET") {
      const v = await kv.get(k, "json");
      return send({ ok: true, exists: !!v, data: v ? v.data : null });
    }
    if (req.method === "PUT") {
      const body = await req.json().catch(() => ({}));
      const data = body.data != null ? body.data : body;
      const raw = JSON.stringify(data);
      const bytes = enc.encode(raw).length;
      if (bytes > MAX_BLOB_BYTES) {
        return send({ error: `数据太大（上限 ${MAX_BLOB_BYTES} 字节，实际 ${bytes}）` }, 413);
      }
      await kv.put(k, JSON.stringify({ data, updatedAt: Date.now() }));
      return send({ ok: true, bytes });
    }
    if (req.method === "DELETE") {
      await kv.delete(k);
      return send({ ok: true });
    }
    return send({ error: "method not allowed" }, 405);
  }

  return send({ error: "not found" }, 404);
}

export async function onRequest(context) {
  try {
    return await handle(context);
  } catch (e) {
    // 兜底：宁可回一段能看懂的 JSON，也别让用户拿到 Cloudflare 的空白错误页
    return send({ error: "internal", message: String((e && e.message) || e) }, 500);
  }
}
