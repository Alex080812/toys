// Серверная часть сайта (Netlify Function).
// Хранит каталог игрушек и фото в Netlify Blobs, пускает в админку только по паролю.
//
// Пароль задаётся в Netlify: Project configuration → Environment variables → ADMIN_PASSWORD.
// Здесь пароля нет, поэтому этот файл можно спокойно хранить на GitHub.

import { getStore } from "@netlify/blobs";
import { createHash, createHmac, timingSafeEqual, randomUUID } from "node:crypto";

const TOKEN_DAYS = 14;
const MAX_IMG_BYTES = 2 * 1024 * 1024;

/* ---------- вспомогательное ---------- */
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });

const sha = (s) => createHash("sha256").update(String(s)).digest();
const b64u = (buf) => Buffer.from(buf).toString("base64url");

const password = () => process.env.ADMIN_PASSWORD || "";
const secret = () => process.env.ADMIN_SECRET || password();

function sign(body) {
  return b64u(createHmac("sha256", secret()).update(body).digest());
}
function makeToken() {
  const body = b64u(JSON.stringify({ exp: Date.now() + TOKEN_DAYS * 864e5 }));
  return body + "." + sign(body);
}
function tokenValid(req) {
  if (!secret()) return false;
  const h = req.headers.get("authorization") || "";
  const t = h.startsWith("Bearer ") ? h.slice(7) : "";
  const [body, sig] = t.split(".");
  if (!body || !sig) return false;
  const good = sign(body);
  const a = Buffer.from(sig), b = Buffer.from(good);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return false;
  try {
    return JSON.parse(Buffer.from(body, "base64url").toString()).exp > Date.now();
  } catch {
    return false;
  }
}

/* простая защита от подбора пароля (в пределах одного экземпляра функции) */
const fails = new Map();
function tooManyFails(ip) {
  const r = fails.get(ip);
  return r && r.n >= 8 && Date.now() - r.t < 15 * 60 * 1000;
}
function noteFail(ip) {
  const r = fails.get(ip);
  if (!r || Date.now() - r.t > 15 * 60 * 1000) fails.set(ip, { n: 1, t: Date.now() });
  else r.n++;
}

/* ---------- проверка данных каталога ---------- */
const str = (v, max) => (typeof v === "string" ? v.trim().slice(0, max) : "");
const tri = (o, max) => ({ ru: str(o?.ru, max), am: str(o?.am, max), en: str(o?.en, max) });

class Bad extends Error {}

function sanitize(body) {
  if (!body || typeof body !== "object") throw new Bad("Пустые данные");

  const categories = {};
  const rawCats = body.categories && typeof body.categories === "object" ? body.categories : {};
  for (const [k, v] of Object.entries(rawCats).slice(0, 30)) {
    if (!/^[a-z0-9_]{1,30}$/.test(k)) continue;
    const t = tri(v, 40);
    if (t.ru) categories[k] = t;
  }

  if (!Array.isArray(body.products)) throw new Bad("Нет списка игрушек");
  if (body.products.length > 100) throw new Bad("Слишком много игрушек (максимум 100)");

  const seen = new Set();
  const products = body.products.map((p, i) => {
    const id = String(p?.id ?? "");
    if (!/^[A-Za-z0-9_-]{1,40}$/.test(id) || seen.has(id)) throw new Bad(`Неверный номер игрушки №${i + 1}`);
    seen.add(id);
    const name = tri(p.name, 80);
    if (!name.ru) throw new Bad(`У игрушки №${i + 1} нет названия`);
    const images = (Array.isArray(p.images) ? p.images : [])
      .slice(0, 12)
      .filter((u) => typeof u === "string" && (/^\/api\/img\/[a-f0-9]{32}$/.test(u) || /^[a-z0-9_]{1,40}$/.test(u)));
    const price = Math.max(0, Math.min(100000000, Math.round(Number(p.price) || 0)));
    const status = ["available", "soldout", "hidden"].includes(p.status) ? p.status : "available";
    const cat = typeof p.cat === "string" && categories[p.cat] ? p.cat : "";
    const out = { id, price, cat, status, emoji: str(p.emoji, 8), images, name, desc: tri(p.desc, 1000) };
    const badge = tri(p.badge, 40);
    if (badge.ru || badge.am || badge.en) out.badge = badge;
    return out;
  });

  const settings = {
    telegram: str(body.settings?.telegram, 64).replace(/^@/, "").replace(/[^A-Za-z0-9_]/g, ""),
    whatsapp: str(body.settings?.whatsapp, 20).replace(/\D/g, ""),
  };

  return { products, categories, settings };
}

/* ---------- обработчик ---------- */
export default async (req) => {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/(\.netlify\/functions\/api|api)/, "") || "/";
  const data = () => getStore({ name: "site", consistency: "strong" });
  const images = () => getStore({ name: "images" });

  try {
    /* Фото: открыто всем, кэшируется навсегда (у каждого фото свой уникальный адрес) */
    if (req.method === "GET" && path.startsWith("/img/")) {
      const id = path.slice(5);
      if (!/^[a-f0-9]{32}$/.test(id)) return new Response("Not found", { status: 404 });
      const buf = await images().get(id, { type: "arrayBuffer" });
      if (!buf) return new Response("Not found", { status: 404 });
      return new Response(buf, {
        headers: { "Content-Type": "image/jpeg", "Cache-Control": "public, max-age=31536000, immutable" },
      });
    }

    /* Вход */
    if (req.method === "POST" && path === "/login") {
      if (!password()) return json({ error: "На сервере не задан пароль ADMIN_PASSWORD" }, 500);
      const ip = req.headers.get("x-nf-client-connection-ip") || req.headers.get("x-forwarded-for") || "?";
      if (tooManyFails(ip)) return json({ error: "Слишком много попыток. Попробуйте позже." }, 429);
      const body = await req.json().catch(() => ({}));
      const ok = timingSafeEqual(sha(body.password ?? ""), sha(password()));
      if (!ok) {
        noteFail(ip);
        await new Promise((r) => setTimeout(r, 700));
        return json({ error: "Неверный пароль" }, 401);
      }
      return json({ token: makeToken() });
    }

    /* Чтение каталога: посетителям без скрытых игрушек, администратору всё */
    if (req.method === "GET" && path === "/data") {
      const admin = tokenValid(req);
      const saved = await data().get("catalog", { type: "json" });
      if (!saved) return json({ products: null, admin });
      const products = admin ? saved.products : saved.products.filter((p) => p.status !== "hidden");
      return json({ products, categories: saved.categories, settings: saved.settings, admin });
    }

    /* Дальше только для администратора */
    if (!tokenValid(req)) return json({ error: "Нужно войти" }, 401);

    if (req.method === "PUT" && path === "/data") {
      const clean = sanitize(await req.json().catch(() => null));
      await data().setJSON("catalog", clean);
      return json({ ...clean, admin: true });
    }

    if (req.method === "POST" && path === "/upload") {
      const buf = await req.arrayBuffer();
      if (buf.byteLength < 100 || buf.byteLength > MAX_IMG_BYTES) return json({ error: "Фото слишком большое" }, 413);
      const h = new Uint8Array(buf, 0, 3);
      if (!(h[0] === 0xff && h[1] === 0xd8 && h[2] === 0xff)) return json({ error: "Нужен файл JPEG" }, 400);
      const id = randomUUID().replace(/-/g, "");
      await images().set(id, buf);
      return json({ url: `/api/img/${id}` });
    }

    return json({ error: "Не найдено" }, 404);
  } catch (e) {
    if (e instanceof Bad) return json({ error: e.message }, 400);
    console.error(e);
    return json({ error: "Ошибка сервера" }, 500);
  }
};

export const config = { path: ["/api/*"] };
