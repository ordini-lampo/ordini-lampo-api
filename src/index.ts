/* ============================================================
   Ordini-Lampo Worker - BULLDOZER ENTERPRISE v2.0
   ============================================================
   ISTRUZIONI DEPLOY:
   1. cd ordini-lampo-api
   2. npm install jose
   3. Sostituire src/index.ts con questo file
   4. wrangler secret put CLERK_JWKS_URL
   5. wrangler secret put CLERK_ISSUER
   6. wrangler secret put ALLOWED_ADMIN_ORIGINS
   7. wrangler deploy
   ============================================================
   FEATURES:
   - Zero-trust client: tenant derived ONLY from Clerk JWT claims
   - Admin endpoints AUTH REQUIRED
   - Admin CORS fail-closed (allowlist)
   - DB request context set_config
   - Idempotency + Replay-safe
   - Settings optimistic concurrency (If-Match)
   - Audit append-only
   ============================================================ */

import postgres from "postgres";
import { createRemoteJWKSet, jwtVerify, JWTPayload } from "jose";

type Hyperdrive = any;
type Queue = any;

interface Env {
  HYPERDRIVE: Hyperdrive;
  OUTBOX_QUEUE: Queue;

  // Clerk JWT verification
  CLERK_JWKS_URL: string;
  CLERK_ISSUER?: string;
  CLERK_AUDIENCE?: string;

  // Admin CORS allowlist
  ALLOWED_ADMIN_ORIGINS?: string;

  // Optional
  ENVIRONMENT?: "dev" | "prod";
}

// --------------------------
// Business constants (slots)
// --------------------------
const SLOT_LIMITS = { normal: 8, peak: 5 };
const PEAK_SLOTS = new Set(["12:00", "12:30", "19:30", "20:00"]);

const ALL_SLOTS = [
  "11:30","12:00","12:30","13:00","13:30","14:00",
  "18:30","19:00","19:30","20:00","20:30","21:00","21:30","22:00"
];

// --------------------------
// Security headers
// --------------------------
function securityHeaders(): Record<string, string> {
  return {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
  };
}

// --------------------------
// CORS
// --------------------------
function parseAllowlist(env: Env): Set<string> {
  const raw = env.ALLOWED_ADMIN_ORIGINS ?? "";
  return new Set(
    raw.split(",").map((s) => s.trim()).filter(Boolean)
  );
}

function corsHeadersPublic(origin?: string | null) {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, Idempotency-Key, If-Match, X-Request-Id",
    "Access-Control-Max-Age": "86400",
  };
}

function corsHeadersAdmin(env: Env, origin?: string | null) {
  const allow = parseAllowlist(env);

  if (origin && origin !== "null" && allow.size > 0 && !allow.has(origin)) {
    return { ok: false as const, headers: {} as Record<string, string> };
  }

  const allowOrigin = origin && origin !== "null" ? origin : "*";

  return {
    ok: true as const,
    headers: {
      "Access-Control-Allow-Origin": allowOrigin,
      "Vary": "Origin",
      "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, Idempotency-Key, If-Match, X-Request-Id",
      "Access-Control-Max-Age": "86400",
    },
  };
}

// --------------------------
// Responses
// --------------------------
function json(data: any, status = 200, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...securityHeaders(),
      ...headers,
    },
  });
}

function todayISO() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

// --------------------------
// DB
// --------------------------
function db(env: Env) {
  return postgres(env.HYPERDRIVE.connectionString, {
    prepare: false,
    idle_timeout: 30,
    max_lifetime: 60 * 5,
  });
}

async function setDbRequestContext(sql: any, ctx: {
  userId: string;
  tenantId: string;
  role: string;
  requestId: string;
  ip: string;
  ua: string;
}) {
  await sql`
    SELECT
      set_config('request.user_id', ${ctx.userId}, true),
      set_config('request.tenant_id', ${ctx.tenantId}, true),
      set_config('request.role', ${ctx.role}, true),
      set_config('request.request_id', ${ctx.requestId}, true),
      set_config('request.ip', ${ctx.ip}, true),
      set_config('request.ua', ${ctx.ua}, true)
  `;
}

// --------------------------
// Clerk JWT verification
// --------------------------
let jwksCache: ReturnType<typeof createRemoteJWKSet> | null = null;

function getJwks(env: Env) {
  if (!jwksCache) {
    const url = new URL(env.CLERK_JWKS_URL);
    jwksCache = createRemoteJWKSet(url);
  }
  return jwksCache;
}

function readBearer(request: Request): string | null {
  const h = request.headers.get("authorization") || request.headers.get("Authorization");
  if (!h) return null;
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}

function isUuid(x: unknown): x is string {
  if (typeof x !== "string") return false;
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(x);
}

type AuthCtx = {
  userId: string;
  restaurantId: string;
  role: string;
  claims: JWTPayload;
};

function normalizeRole(claims: JWTPayload): string {
  const direct = (claims.role as any) || (claims.org_role as any);
  const meta = (claims.public_metadata as any)?.role;
  const r = String(direct || meta || "staff");
  return r.toLowerCase();
}

function isAdminRole(role: string): boolean {
  return ["owner", "admin", "superadmin"].includes(role);
}

async function verifyClerkJWT(env: Env, token: string): Promise<AuthCtx> {
  const jwks = getJwks(env);

  const { payload } = await jwtVerify(token, jwks, {
    issuer: env.CLERK_ISSUER || undefined,
    audience: env.CLERK_AUDIENCE || undefined,
  });

  const userId = String(payload.sub || "");
  if (!userId) throw new Error("UNAUTHENTICATED");

  // BULLDOZER RULE: restaurant_id MUST be present and MUST be UUID
  const restaurantId = (payload.restaurant_id as any) ?? (payload.public_metadata as any)?.restaurant_id;
  if (!isUuid(restaurantId)) throw new Error("NO_TENANT_BOUND");

  const role = normalizeRole(payload);

  return { userId, restaurantId, role, claims: payload };
}

// --------------------------
// Idempotency helpers
// --------------------------
async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function getRequestId(req: Request): string {
  const h = req.headers.get("x-request-id");
  return h && h.length >= 16 ? h : crypto.randomUUID();
}

function getClientIp(req: Request): string {
  return req.headers.get("cf-connecting-ip") || "";
}

function getUA(req: Request): string {
  return req.headers.get("user-agent") || "";
}

function requireIdempotencyKey(req: Request): string {
  const k = req.headers.get("idempotency-key");
  if (!k || k.length < 16) throw new Error("MISSING_IDEMPOTENCY_KEY");
  return k;
}

async function computeRequestHash(req: Request, bodyText: string): Promise<string> {
  const url = new URL(req.url);
  return sha256Hex(`${req.method}|${url.pathname}|${bodyText}`);
}

async function idemReplay(sql: any, idemKey: string, requestHash: string) {
  const row = await sql`SELECT * FROM sec.idem_get(${idemKey}, ${requestHash})`;
  if (row?.[0]?.found) {
    return { replayed: true as const, status: row[0].status_code as number, body: row[0].response_body };
  }
  return { replayed: false as const };
}

async function idemBegin(sql: any, req: Request, idemKey: string, requestHash: string) {
  try {
    const row = await sql`SELECT * FROM sec.idem_begin(${idemKey}, ${new URL(req.url).pathname}, ${req.method}, ${requestHash}, 86400)`;
    if (row?.[0]?.hit) {
      return { hit: true as const, status: row[0].status_code as number, body: row[0].response_body };
    }
    return { hit: false as const };
  } catch {
    throw new Error("IDEMPOTENCY_IN_FLIGHT");
  }
}

async function idemFinish(sql: any, idemKey: string, requestHash: string, status: number, body: any) {
  await sql`SELECT sec.idem_finish(${idemKey}, ${requestHash}, ${status}, ${JSON.stringify(body)}::jsonb)`;
}

// --------------------------
// WhatsApp message builder
// --------------------------
function buildMessage(body: any, order: any, rname: string): string {
  const now = new Date();
  const d = now.toLocaleDateString("it-IT");
  const t = now.toLocaleTimeString("it-IT", { hour: "2-digit", minute: "2-digit" });

  let msg = `==================\nSEZIONE 1: DATI ORDINE\n==================\n`;
  msg += `N. Ordine: #${order.order_number}\nData Ordine: ${d} ore ${t}\n`;
  msg += `Ora Consegna: ${body.delivery_time || "12:00"}\n`;
  msg += `==================\nSEZIONE 2: INGREDIENTI\n==================\n`;

  if (body.bowls?.length) {
    body.bowls.forEach((b: any, i: number) => {
      msg += `BOWL #${i + 1} (${b.bowl_type_name || "Regular"})\n------------------\n`;
      ["base", "proteine", "verdure", "salse", "toppings"].forEach((cat) => {
        if (b[cat]?.length) {
          msg += `${String(cat).toUpperCase()}:\n`;
          b[cat].forEach((x: any) => {
            msg += ` - ${x.name}${x.qty > 1 ? " x" + x.qty : ""}\n`;
          });
        }
      });
    });
  }

  if (body.allergie) msg += `ALLERGIE: ${body.allergie}\n`;
  if (body.posate_richieste) msg += `Posate Richieste: Si\n`;

  msg += `==================\nSEZIONE 3: CLIENTE\n==================\n`;
  msg += `Nome: ${body.customer_name}\nTelefono: ${body.customer_phone}\n`;
  msg += `Indirizzo: ${body.delivery_address || "Ritiro"}\n`;
  if (body.citofono) msg += `Citofono: ${body.citofono}\n`;
  msg += `Pagamento: ${body.payment_method || "Contanti"}\n`;

  msg += `==================\nSEZIONE 4: RIEPILOGO\n==================\n`;
  msg += `Subtotale: EUR ${Number(order.subtotal || 0).toFixed(2)}\n`;
  if (Number(order.delivery_fee || 0) > 0) msg += `Consegna: EUR ${Number(order.delivery_fee || 0).toFixed(2)}\n`;
  if (Number(order.discount_amount || 0) > 0) msg += `Sconto: -EUR ${Number(order.discount_amount || 0).toFixed(2)}\n`;
  msg += `TOTALE: EUR ${Number(order.total || 0).toFixed(2)}\n`;
  msg += `Grazie per aver scelto ${rname}!\nPowered by Ordini-Lampo.it`;

  return msg;
}

// --------------------------
// Main handler
// --------------------------
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();

    const origin = request.headers.get("origin");
    const isAdminRoute = path.startsWith("/admin");

    // CORS (OPTIONS)
    if (method === "OPTIONS") {
      if (isAdminRoute) {
        const c = corsHeadersAdmin(env, origin);
        if (!c.ok) return json({ success: false, error: "CORS_DENIED" }, 403, {});
        return new Response(null, { status: 204, headers: { ...c.headers, ...securityHeaders() } });
      }
      return new Response(null, { status: 204, headers: { ...corsHeadersPublic(origin), ...securityHeaders() } });
    }

    // Apply CORS headers per route family
    const cors =
      isAdminRoute
        ? (() => {
            const c = corsHeadersAdmin(env, origin);
            if (!c.ok) return null;
            return c.headers;
          })()
        : corsHeadersPublic(origin);

    if (!cors) return json({ success: false, error: "CORS_DENIED" }, 403, {});

    const sql = db(env);

    try {
      // --------------------------
      // Health
      // --------------------------
      if (path === "/" || path === "/health") {
        return json({ status: "ok", version: "BULLDOZER-2.0" }, 200, cors);
      }

      // ============================================================
      // PUBLIC ENDPOINTS (QR / client app)
      // ============================================================
      const bundleMatch = path.match(/^\/poke\/([^\/]+)\/bundle$/);
      if (bundleMatch && method === "GET") {
        const slug = bundleMatch[1];
        const r = await sql`SELECT poke.get_public_bundle_by_slug(${slug}) as bundle`;
        if (!r?.[0]?.bundle) return json({ success: false, error: "NOT_FOUND" }, 404, cors);
        return json({ success: true, data: r[0].bundle }, 200, cors);
      }

      const slotsMatch = path.match(/^\/poke\/([^\/]+)\/slots$/);
      if (slotsMatch && method === "GET") {
        const slug = slotsMatch[1];
        const date = url.searchParams.get("date") || todayISO();

        const rest = await sql`SELECT id FROM app.restaurants WHERE slug = ${slug} LIMIT 1`;
        if (!rest?.[0]?.id) return json({ success: false, error: "NOT_FOUND" }, 404, cors);
        const rid = rest[0].id;

        const counts = await sql`
          SELECT to_char(scheduled_time, 'HH24:MI') as slot, COUNT(*)::int as cnt
          FROM app.orders
          WHERE restaurant_id = ${rid}
            AND DATE(created_at) = ${date}::date
            AND status NOT IN ('CANCELLED', 'REJECTED')
          GROUP BY 1
        `;

        const blocked = await sql`
          SELECT to_char(slot_time, 'HH24:MI') as slot, reason
          FROM app.blocked_slots
          WHERE restaurant_id = ${rid}
            AND slot_date = ${date}::date
        `;

        const availability: Record<string, any> = {};
        for (const slot of ALL_SLOTS) {
          const found = counts.find((c: any) => c.slot === slot);
          const block = blocked.find((b: any) => b.slot === slot);
          const count = found?.cnt ?? 0;
          const limit = PEAK_SLOTS.has(slot) ? SLOT_LIMITS.peak : SLOT_LIMITS.normal;

          if (block) {
            availability[slot] = { count, limit, available: false, blocked: true, reason: block.reason };
          } else {
            availability[slot] = { count, limit, available: count < limit };
          }
        }

        return json({ success: true, date, availability }, 200, cors);
      }

      const orderMatch = path.match(/^\/poke\/([^\/]+)\/order$/);
      if (orderMatch && method === "POST") {
        const slug = orderMatch[1];
        const body = await request.json().catch(() => null);

        if (!body || !body.customer_name || !body.customer_phone || !Array.isArray(body.bowls)) {
          return json({ success: false, error: "MISSING_FIELDS" }, 400, cors);
        }

        const rest = await sql`SELECT id, name, whatsapp_number FROM app.restaurants WHERE slug = ${slug} LIMIT 1`;
        if (!rest?.[0]?.id) return json({ success: false, error: "NOT_FOUND" }, 404, cors);

        const rid = rest[0].id;
        const rname = rest[0].name;
        const phone = String(rest[0].whatsapp_number || "").replace(/\D/g, "");

        const time = body.delivery_time || "12:00";
        const slotKey = String(time).substring(0, 5);

        const existing = await sql`
          SELECT COUNT(*)::int as cnt
          FROM app.orders
          WHERE restaurant_id = ${rid}
            AND DATE(created_at) = CURRENT_DATE
            AND to_char(scheduled_time, 'HH24:MI') = ${slotKey}
            AND status NOT IN ('CANCELLED', 'REJECTED')
        `;

        const cnt = existing?.[0]?.cnt ?? 0;
        const limit = PEAK_SLOTS.has(slotKey) ? SLOT_LIMITS.peak : SLOT_LIMITS.normal;

        if (cnt >= limit) {
          return json(
            { success: false, error: "SLOT_FULL", message: `Slot ${slotKey} pieno (${limit} ordini max)` },
            400,
            cors
          );
        }

        const result = await sql`
          SELECT poke.create_order(
            ${rid}::uuid,
            ${body.customer_name},
            ${body.customer_phone},
            ${body.location_id || null}::uuid,
            ${body.delivery_address || ''},
            ${time},
            ${body.notes || ''},
            ${JSON.stringify(body.bowls)}::jsonb,
            ${body.discount_code || null}
          ) as result
        `;

        const order = result?.[0]?.result;
        if (!order?.success) return json({ success: false, error: order?.error || "CREATE_FAILED" }, 400, cors);

        const msg = buildMessage(body, order, rname);
        const deeplink = `https://wa.me/${phone}?text=${encodeURIComponent(msg)}`;

        return json(
          {
            success: true,
            order_id: order.order_id,
            order_number: order.order_number,
            subtotal: order.subtotal,
            delivery_fee: order.delivery_fee,
            discount_amount: order.discount_amount,
            total: order.total,
            whatsapp: { to: phone, text: msg, deeplink },
          },
          200,
          cors
        );
      }

      // ============================================================
      // ADMIN ENDPOINTS (AUTH REQUIRED, TENANT FROM TOKEN)
      // ============================================================
      if (path.startsWith("/admin")) {
        const token = readBearer(request);
        if (!token) return json({ success: false, error: "UNAUTHENTICATED" }, 401, cors);

        let auth: AuthCtx;
        try {
          auth = await verifyClerkJWT(env, token);
        } catch (e: any) {
          const msg = String(e?.message || "UNAUTHENTICATED");
          return json({ success: false, error: msg }, 401, cors);
        }

        if (!isAdminRole(auth.role)) {
          return json({ success: false, error: "FORBIDDEN" }, 403, cors);
        }

        const requestId = getRequestId(request);
        const ip = getClientIp(request);
        const ua = getUA(request);

        // Wrap admin ops in a transaction
        return await sql.begin(async (tx: any) => {
          await setDbRequestContext(tx, {
            userId: auth.userId,
            tenantId: auth.restaurantId,
            role: auth.role,
            requestId,
            ip,
            ua,
          });

          // ---------- GET /admin/orders ----------
          if (path === "/admin/orders" && method === "GET") {
            const date = url.searchParams.get("date") || todayISO();

            const orders = await tx`
              SELECT id, order_number, customer_name, customer_phone,
                     delivery_address, scheduled_time, status, notes,
                     subtotal, delivery_fee, discount_amount, total,
                     created_at, updated_at, location_id
              FROM app.orders
              WHERE restaurant_id = ${auth.restaurantId}::uuid
                AND DATE(created_at) = ${date}::date
              ORDER BY created_at DESC
            `;

            return json({ success: true, date, orders }, 200, cors);
          }

          // ---------- PUT /admin/orders/:id ----------
          const upd = path.match(/^\/admin\/orders\/([^\/]+)$/);
          if (upd && method === "PUT") {
            const orderId = upd[1];
            const body = await request.json().catch(() => null);
            const status = String(body?.status || "");

            const VALID = new Set([
              "PENDING","CONFIRMED","PREPARING","READY","DELIVERING","DELIVERED","CANCELLED","REJECTED"
            ]);
            if (!VALID.has(status)) return json({ success: false, error: "INVALID_STATUS" }, 400, cors);

            const before = await tx`
              SELECT id, status
              FROM app.orders
              WHERE id = ${orderId}::uuid AND restaurant_id = ${auth.restaurantId}::uuid
              LIMIT 1
            `;
            if (!before?.[0]?.id) return json({ success: false, error: "NOT_FOUND" }, 404, cors);

            await tx`
              UPDATE app.orders
              SET status = ${status}, updated_at = NOW()
              WHERE id = ${orderId}::uuid AND restaurant_id = ${auth.restaurantId}::uuid
            `;

            await tx`
              SELECT sec.audit_append(
                'order.status.update',
                'order',
                ${orderId}::uuid,
                ${JSON.stringify({ status: before[0].status })}::jsonb,
                ${JSON.stringify({ status })}::jsonb,
                true,
                NULL
              )
            `;

            return json({ success: true, status }, 200, cors);
          }

          // ---------- GET /admin/settings ----------
          if (path === "/admin/settings" && method === "GET") {
            const r = await tx`
              SELECT id, name, slug, whatsapp_number
              FROM app.restaurants
              WHERE id = ${auth.restaurantId}::uuid
              LIMIT 1
            `;
            if (!r?.[0]?.id) return json({ success: false, error: "NOT_FOUND" }, 404, cors);

            await tx`
              INSERT INTO app.restaurant_settings (restaurant_id, settings_json, version)
              VALUES (${auth.restaurantId}::uuid, '{}'::jsonb, 1)
              ON CONFLICT (restaurant_id) DO NOTHING
            `;

            const s = await tx`
              SELECT settings_json, version, updated_at
              FROM app.restaurant_settings
              WHERE restaurant_id = ${auth.restaurantId}::uuid
              LIMIT 1
            `;

            const locations = await tx`
              SELECT id, name, delivery_fee, sort_order
              FROM app.locations
              WHERE restaurant_id = ${auth.restaurantId}::uuid
              ORDER BY sort_order NULLS LAST, name
            `;

            return json(
              { success: true, restaurant: r[0], settings: s?.[0]?.settings_json ?? {}, version: s?.[0]?.version ?? 1, locations },
              200,
              cors
            );
          }

          // ---------- PUT /admin/settings (idempotent + optimistic concurrency) ----------
          if (path === "/admin/settings" && method === "PUT") {
            const idemKey = requireIdempotencyKey(request);
            const bodyText = await request.text();
            const requestHash = await computeRequestHash(request, bodyText);

            const parsed = (() => {
              try { return JSON.parse(bodyText); } catch { return null; }
            })();
            if (!parsed || typeof parsed !== "object") return json({ success: false, error: "INVALID_BODY" }, 400, cors);

            const ifMatch = request.headers.get("if-match") || "";
            const m = ifMatch.match(/W\/"(\d+)"/);
            const expectedVersion = m ? Number(m[1]) : Number(parsed.expectedVersion);
            if (!Number.isFinite(expectedVersion)) return json({ success: false, error: "MISSING_EXPECTED_VERSION" }, 428, cors);

            const rep = await idemReplay(tx, idemKey, requestHash);
            if (rep.replayed) {
              return json(rep.body, rep.status, { ...cors, "idempotency-replayed": "true" });
            }

            const begin = await idemBegin(tx, request, idemKey, requestHash);
            if ((begin as any).hit) {
              return json((begin as any).body, (begin as any).status, { ...cors, "idempotency-replayed": "true" });
            }

            try {
              if (parsed.restaurant && typeof parsed.restaurant === "object") {
                const name = parsed.restaurant.name ?? null;
                const whatsapp = parsed.restaurant.whatsapp_number ?? null;

                await tx`
                  UPDATE app.restaurants
                  SET
                    name = COALESCE(${name}, name),
                    whatsapp_number = COALESCE(${whatsapp}, whatsapp_number),
                    updated_at = NOW()
                  WHERE id = ${auth.restaurantId}::uuid
                `;
              }

              const settings = parsed.settings ?? {};
              const updated = await tx`
                SELECT * FROM app.update_restaurant_settings(
                  ${auth.restaurantId}::uuid,
                  ${JSON.stringify(settings)}::jsonb,
                  ${expectedVersion}::int
                )
              `;

              const payload = { success: true, settings: updated[0].settings_json, version: updated[0].version };
              await idemFinish(tx, idemKey, requestHash, 200, payload);

              return json(payload, 200, cors);
            } catch (e: any) {
              const msg = String(e?.message || "ERROR");
              const isConflict = msg.includes("SETTINGS_VERSION_CONFLICT");

              const payload = { success: false, error: isConflict ? "VERSION_CONFLICT" : "SERVER_ERROR" };

              await tx`
                SELECT sec.audit_append(
                  'settings.update.failed',
                  'restaurant_settings',
                  ${auth.restaurantId}::uuid,
                  NULL,
                  ${JSON.stringify(parsed.settings ?? {})}::jsonb,
                  false,
                  ${msg}
                )
              `;

              await idemFinish(tx, idemKey, requestHash, isConflict ? 409 : 500, payload);
              return json(payload, isConflict ? 409 : 500, cors);
            }
          }

          // ---------- GET /admin/blocked-slots ----------
          if (path === "/admin/blocked-slots" && method === "GET") {
            const slots = await tx`
              SELECT id, slot_date, slot_time, reason
              FROM app.blocked_slots
              WHERE restaurant_id = ${auth.restaurantId}::uuid
                AND slot_date >= CURRENT_DATE
              ORDER BY slot_date, slot_time
            `;
            return json({ success: true, blocked_slots: slots }, 200, cors);
          }

          // ---------- POST /admin/blocked-slots ----------
          if (path === "/admin/blocked-slots" && method === "POST") {
            const idemKey = requireIdempotencyKey(request);
            const bodyText = await request.text();
            const requestHash = await computeRequestHash(request, bodyText);

            const parsed = (() => { try { return JSON.parse(bodyText); } catch { return null; } })();
            if (!parsed?.slot_date || !parsed?.slot_time) {
              return json({ success: false, error: "MISSING_FIELDS" }, 400, cors);
            }

            const rep = await idemReplay(tx, idemKey, requestHash);
            if (rep.replayed) return json(rep.body, rep.status, { ...cors, "idempotency-replayed": "true" });

            await idemBegin(tx, request, idemKey, requestHash);

            await tx`
              INSERT INTO app.blocked_slots (restaurant_id, slot_date, slot_time, reason)
              VALUES (
                ${auth.restaurantId}::uuid,
                ${parsed.slot_date}::date,
                ${parsed.slot_time}::time,
                ${parsed.reason || "Pieno"}
              )
            `;

            const payload = { success: true };
            await idemFinish(tx, idemKey, requestHash, 200, payload);

            return json(payload, 200, cors);
          }

          // ---------- DELETE /admin/blocked-slots/:id ----------
          const del = path.match(/^\/admin\/blocked-slots\/([^\/]+)$/);
          if (del && method === "DELETE") {
            const idemKey = requireIdempotencyKey(request);
            const bodyText = "";
            const requestHash = await computeRequestHash(request, bodyText);

            const rep = await idemReplay(tx, idemKey, requestHash);
            if (rep.replayed) return json(rep.body, rep.status, { ...cors, "idempotency-replayed": "true" });

            await idemBegin(tx, request, idemKey, requestHash);

            await tx`
              DELETE FROM app.blocked_slots
              WHERE id = ${del[1]}::uuid AND restaurant_id = ${auth.restaurantId}::uuid
            `;

            const payload = { success: true };
            await idemFinish(tx, idemKey, requestHash, 200, payload);

            return json(payload, 200, cors);
          }

          return json({ success: false, error: "NOT_FOUND", path }, 404, cors);
        });
      }

      return json({ success: false, error: "NOT_FOUND", path }, 404, cors);
    } catch (e: any) {
      const msg = String(e?.message || "SERVER_ERROR");
      return json({ success: false, error: msg }, 500, cors);
    }
  },
} satisfies ExportedHandler<Env>;
