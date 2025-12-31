/* ============================================================
   Ordini-Lampo API - RAILWAY EXPRESS v1.0
   Converted from Cloudflare Workers BULLDOZER v2.2
   ============================================================ */

const express = require('express');
const cors = require('cors');
const postgres = require('postgres');
const { createRemoteJWKSet, jwtVerify } = require('jose');

const app = express();
const PORT = process.env.PORT || 3000;

// --------------------------
// Business constants
// --------------------------
const SLOT_LIMITS = { normal: 8, peak: 5 };
const PEAK_SLOTS = new Set(["12:00", "12:30", "19:30", "20:00"]);
const ALL_SLOTS = [
  "11:30","12:00","12:30","13:00","13:30","14:00",
  "18:30","19:00","19:30","20:00","20:30","21:00","21:30","22:00"
];

// --------------------------
// Database connection
// --------------------------
let sql;
function getDb() {
  if (!sql) {
    sql = postgres(process.env.DATABASE_URL, {
      prepare: false,
      idle_timeout: 30,
      max_lifetime: 60 * 5,
      ssl: process.env.DATABASE_SSL === 'false' ? false : 'require',
    });
  }
  return sql;
}

// --------------------------
// Middleware
// --------------------------
app.use(express.json());
app.use(express.text({ type: 'application/json' }));

// Security headers
app.use((req, res, next) => {
  res.set({
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
  });
  next();
});

// CORS configuration
const allowedOrigins = (process.env.ALLOWED_ADMIN_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, curl, etc)
    if (!origin) return callback(null, true);
    
    // For admin routes, check allowlist
    if (allowedOrigins.length > 0 && !allowedOrigins.includes(origin)) {
      // Still allow for non-admin routes
      return callback(null, true);
    }
    return callback(null, true);
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Idempotency-Key', 'If-Match', 'X-Request-Id', 'Stripe-Signature'],
  maxAge: 86400,
  credentials: true,
}));

// --------------------------
// Helpers
// --------------------------
function todayISO() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

function isUuid(x) {
  if (typeof x !== "string") return false;
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(x);
}

function getRequestId(req) {
  const h = req.headers['x-request-id'];
  return h && h.length >= 16 ? h : require('crypto').randomUUID();
}

function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0] || req.ip || '';
}

function getUA(req) {
  return req.headers['user-agent'] || '';
}

// --------------------------
// Clerk JWT verification
// --------------------------
let jwksCache = null;

function getJwks() {
  if (!jwksCache && process.env.CLERK_JWKS_URL) {
    const url = new URL(process.env.CLERK_JWKS_URL);
    jwksCache = createRemoteJWKSet(url);
  }
  return jwksCache;
}

function readBearer(req) {
  const h = req.headers['authorization'] || req.headers['Authorization'];
  if (!h) return null;
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}

function normalizeRole(claims) {
  const direct = claims.role || claims.org_role;
  const meta = claims.public_metadata?.role;
  const r = String(direct || meta || "staff");
  return r.toLowerCase();
}

function isAdminRole(role) {
  return ["owner", "admin", "superadmin"].includes(role);
}

async function verifyClerkJWT(token) {
  const jwks = getJwks();
  if (!jwks) throw new Error("CLERK_NOT_CONFIGURED");
  
  const { payload } = await jwtVerify(token, jwks, {
    issuer: process.env.CLERK_ISSUER || undefined,
    audience: process.env.CLERK_AUDIENCE || undefined,
  });

  const userId = String(payload.sub || "");
  if (!userId) throw new Error("UNAUTHENTICATED");

  const restaurantId = payload.restaurant_id ?? payload.public_metadata?.restaurant_id;
  if (!isUuid(restaurantId)) throw new Error("NO_TENANT_BOUND");

  const tenantId = payload.tenant_id ?? payload.public_metadata?.tenant_id ?? restaurantId;
  const role = normalizeRole(payload);

  return { userId, restaurantId, tenantId, role, claims: payload };
}

// --------------------------
// DB Context (RLS)
// --------------------------
async function setDbRequestContext(sql, ctx) {
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
// Stripe API Helper
// --------------------------
async function stripeRequest(endpoint, method, body) {
  const url = `https://api.stripe.com/v1${endpoint}`;
  const headers = {
    "Authorization": `Bearer ${process.env.STRIPE_SECRET_KEY}`,
    "Content-Type": "application/x-www-form-urlencoded",
  };

  const options = { method, headers };
  
  if (body) {
    const params = new URLSearchParams();
    flattenObject(body, params);
    options.body = params.toString();
  }

  const res = await fetch(url, options);
  return res.json();
}

function flattenObject(obj, params, prefix = "") {
  for (const key of Object.keys(obj)) {
    const value = obj[key];
    const fullKey = prefix ? `${prefix}[${key}]` : key;
    
    if (value === null || value === undefined) continue;
    
    if (typeof value === "object" && !Array.isArray(value)) {
      flattenObject(value, params, fullKey);
    } else if (Array.isArray(value)) {
      value.forEach((item, index) => {
        if (typeof item === "object") {
          flattenObject(item, params, `${fullKey}[${index}]`);
        } else {
          params.append(`${fullKey}[${index}]`, String(item));
        }
      });
    } else {
      params.append(fullKey, String(value));
    }
  }
}

// --------------------------
// WhatsApp message builder
// --------------------------
function buildMessage(body, order, rname) {
  const now = new Date();
  const d = now.toLocaleDateString("it-IT");
  const t = now.toLocaleTimeString("it-IT", { hour: "2-digit", minute: "2-digit" });

  let msg = `==================\nSEZIONE 1: DATI ORDINE\n==================\n`;
  msg += `N. Ordine: #${order.order_number}\nData Ordine: ${d} ore ${t}\n`;
  msg += `Ora Consegna: ${body.delivery_time || "12:00"}\n`;
  msg += `==================\nSEZIONE 2: INGREDIENTI\n==================\n`;

  if (body.bowls?.length) {
    body.bowls.forEach((b, i) => {
      msg += `BOWL #${i + 1} (${b.bowl_type_name || "Regular"})\n------------------\n`;
      ["base", "proteine", "verdure", "salse", "toppings"].forEach((cat) => {
        if (b[cat]?.length) {
          msg += `${String(cat).toUpperCase()}:\n`;
          b[cat].forEach((x) => {
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
// Auth Middleware
// --------------------------
async function authMiddleware(req, res, next) {
  const token = readBearer(req);
  if (!token) return res.status(401).json({ success: false, error: "UNAUTHENTICATED" });

  try {
    req.auth = await verifyClerkJWT(token);
    if (!isAdminRole(req.auth.role)) {
      return res.status(403).json({ success: false, error: "FORBIDDEN" });
    }
    next();
  } catch (e) {
    return res.status(401).json({ success: false, error: String(e?.message || "UNAUTHENTICATED") });
  }
}

// ============================================================
// ROUTES
// ============================================================

// Health check
app.get('/', (req, res) => {
  res.json({ status: "ok", version: "RAILWAY-EXPRESS-1.0" });
});

app.get('/health', (req, res) => {
  res.json({ status: "ok", version: "RAILWAY-EXPRESS-1.0" });
});

// ============================================================
// STRIPE WEBHOOK
// ============================================================
app.post('/webhooks/stripe', async (req, res) => {
  const sql = getDb();
  let event;
  
  try {
    const body = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
    event = JSON.parse(body);
  } catch {
    return res.status(400).json({ error: "Invalid JSON" });
  }

  console.log(`Stripe webhook: ${event.type}`, event.id);

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    const metadata = session.metadata || {};
    
    const planCode = metadata.plan_code;
    const restaurantId = metadata.restaurant_id;
    const tenantId = metadata.tenant_id;
    
    if (!planCode || !restaurantId) {
      console.error("Missing metadata in checkout session", metadata);
      return res.json({ received: true, warning: "missing_metadata" });
    }

    const [plan] = await sql`SELECT * FROM billing.plans WHERE code = ${planCode}`;
    if (!plan) {
      console.error("Plan not found:", planCode);
      return res.json({ received: true, error: "plan_not_found" });
    }

    const totalCredits = plan.credits_included + plan.bonus_credits;

    let [subscription] = await sql`
      SELECT * FROM billing.subscriptions 
      WHERE restaurant_id = ${restaurantId}::uuid
      LIMIT 1
    `;

    if (!subscription) {
      const [newSub] = await sql`
        INSERT INTO billing.subscriptions (
          tenant_id, restaurant_id, plan_code, status,
          credits_balance, bonus_balance, stripe_customer_id
        ) VALUES (
          ${tenantId || restaurantId}::uuid,
          ${restaurantId}::uuid,
          ${planCode},
          'active',
          ${plan.credits_included},
          ${plan.bonus_credits},
          ${session.customer}
        )
        RETURNING *
      `;
      subscription = newSub;
    } else {
      await sql`
        UPDATE billing.subscriptions SET
          plan_code = ${planCode},
          status = 'active',
          credits_balance = credits_balance + ${plan.credits_included},
          bonus_balance = bonus_balance + ${plan.bonus_credits},
          stripe_customer_id = COALESCE(stripe_customer_id, ${session.customer}),
          updated_at = now()
        WHERE id = ${subscription.id}
      `;
    }

    await sql`
      INSERT INTO billing.credit_transactions (
        subscription_id, tenant_id, type, amount, balance_after, is_bonus,
        reference_type, reference_id, description
      ) VALUES (
        ${subscription.id},
        ${tenantId || restaurantId}::uuid,
        'purchase',
        ${plan.credits_included},
        ${(subscription.credits_balance || 0) + plan.credits_included},
        false,
        'stripe_checkout',
        ${session.id}::text::uuid,
        ${`Acquisto ${plan.name} - ${plan.credits_included} crediti`}
      )
    `;

    if (plan.bonus_credits > 0) {
      await sql`
        INSERT INTO billing.credit_transactions (
          subscription_id, tenant_id, type, amount, balance_after, is_bonus,
          reference_type, reference_id, description
        ) VALUES (
          ${subscription.id},
          ${tenantId || restaurantId}::uuid,
          'bonus',
          ${plan.bonus_credits},
          ${(subscription.bonus_balance || 0) + plan.bonus_credits},
          true,
          'stripe_checkout',
          ${session.id}::text::uuid,
          ${`Bonus ${plan.name} - ${plan.bonus_credits} crediti omaggio`}
        )
      `;
    }

    const invoiceNumber = `INV-${new Date().getFullYear()}-${Date.now()}`;
    await sql`
      INSERT INTO billing.invoices (
        subscription_id, tenant_id, invoice_number, invoice_type,
        amount_cents, status, stripe_payment_intent_id, paid_at
      ) VALUES (
        ${subscription.id},
        ${tenantId || restaurantId}::uuid,
        ${invoiceNumber},
        'package',
        ${session.amount_total},
        'paid',
        ${session.payment_intent},
        now()
      )
    `;

    console.log(`Credits granted: ${totalCredits} to restaurant ${restaurantId}`);
    return res.json({ received: true, credits_granted: totalCredits });
  }

  return res.json({ received: true });
});

// ============================================================
// PUBLIC ENDPOINTS
// ============================================================

// GET /poke/:slug/bundle
app.get('/poke/:slug/bundle', async (req, res) => {
  const sql = getDb();
  const { slug } = req.params;
  
  try {
    const r = await sql`SELECT poke.get_public_bundle_by_slug(${slug}) as bundle`;
    if (!r?.[0]?.bundle) return res.status(404).json({ success: false, error: "NOT_FOUND" });
    return res.json({ success: true, data: r[0].bundle });
  } catch (e) {
    console.error("Error:", e);
    return res.status(500).json({ success: false, error: "SERVER_ERROR" });
  }
});

// GET /public/restaurant/:slug/bundle
app.get('/public/restaurant/:slug/bundle', async (req, res) => {
  const sql = getDb();
  const { slug } = req.params;
  
  try {
    const r = await sql`SELECT poke.get_public_bundle_by_slug(${slug}) as bundle`;
    if (!r?.[0]?.bundle) return res.status(404).json({ success: false, error: "NOT_FOUND" });
    return res.json({ success: true, data: r[0].bundle });
  } catch (e) {
    console.error("Error:", e);
    return res.status(500).json({ success: false, error: "SERVER_ERROR" });
  }
});

// GET /poke/:slug/slots
app.get('/poke/:slug/slots', async (req, res) => {
  const sql = getDb();
  const { slug } = req.params;
  const date = req.query.date || todayISO();

  try {
    const rest = await sql`SELECT id FROM app.restaurants WHERE slug = ${slug} LIMIT 1`;
    if (!rest?.[0]?.id) return res.status(404).json({ success: false, error: "NOT_FOUND" });
    const rid = rest[0].id;

    const counts = await sql`
      SELECT to_char(scheduled_time, 'HH24:MI') as slot, COUNT(*)::int as cnt
      FROM app.orders WHERE restaurant_id = ${rid} AND DATE(created_at) = ${date}::date
        AND status NOT IN ('CANCELLED', 'REJECTED') GROUP BY 1
    `;
    const blocked = await sql`
      SELECT to_char(slot_time, 'HH24:MI') as slot, reason
      FROM app.blocked_slots WHERE restaurant_id = ${rid} AND slot_date = ${date}::date
    `;

    const availability = {};
    for (const slot of ALL_SLOTS) {
      const found = counts.find((c) => c.slot === slot);
      const block = blocked.find((b) => b.slot === slot);
      const count = found?.cnt ?? 0;
      const limit = PEAK_SLOTS.has(slot) ? SLOT_LIMITS.peak : SLOT_LIMITS.normal;
      availability[slot] = block
        ? { count, limit, available: false, blocked: true, reason: block.reason }
        : { count, limit, available: count < limit };
    }

    return res.json({ success: true, date, availability });
  } catch (e) {
    console.error("Error:", e);
    return res.status(500).json({ success: false, error: "SERVER_ERROR" });
  }
});

// POST /poke/:slug/order
app.post('/poke/:slug/order', async (req, res) => {
  const sql = getDb();
  const { slug } = req.params;
  const body = req.body;

  if (!body || !body.customer_name || !body.customer_phone || !Array.isArray(body.bowls)) {
    return res.status(400).json({ success: false, error: "MISSING_FIELDS" });
  }

  try {
    const rest = await sql`SELECT id, name, whatsapp_number FROM app.restaurants WHERE slug = ${slug} LIMIT 1`;
    if (!rest?.[0]?.id) return res.status(404).json({ success: false, error: "NOT_FOUND" });

    const rid = rest[0].id;
    const rname = rest[0].name;
    const phone = String(rest[0].whatsapp_number || "").replace(/\D/g, "");
    const time = body.delivery_time || "12:00";
    const slotKey = String(time).substring(0, 5);

    const existing = await sql`
      SELECT COUNT(*)::int as cnt FROM app.orders
      WHERE restaurant_id = ${rid} AND DATE(created_at) = CURRENT_DATE
        AND to_char(scheduled_time, 'HH24:MI') = ${slotKey}
        AND status NOT IN ('CANCELLED', 'REJECTED')
    `;

    const cnt = existing?.[0]?.cnt ?? 0;
    const limit = PEAK_SLOTS.has(slotKey) ? SLOT_LIMITS.peak : SLOT_LIMITS.normal;

    if (cnt >= limit) {
      return res.status(400).json({ success: false, error: "SLOT_FULL", message: `Slot ${slotKey} pieno` });
    }

    const result = await sql`
      SELECT poke.create_order(
        ${rid}::uuid, ${body.customer_name}, ${body.customer_phone},
        ${body.location_id || null}::uuid, ${body.delivery_address || ''}, ${time},
        ${body.notes || ''}, ${sql.json(body.bowls)}, ${body.discount_code || null}
      ) as result
    `;

    const order = result?.[0]?.result;
    if (!order?.success) return res.status(400).json({ success: false, error: order?.error || "CREATE_FAILED" });

    const msg = buildMessage(body, order, rname);
    const deeplink = `https://wa.me/${phone}?text=${encodeURIComponent(msg)}`;

    return res.json({
      success: true,
      order_id: order.order_id,
      order_number: order.order_number,
      subtotal: order.subtotal,
      delivery_fee: order.delivery_fee,
      discount_amount: order.discount_amount,
      total: order.total,
      whatsapp: { to: phone, text: msg, deeplink },
    });
  } catch (e) {
    console.error("Error:", e);
    return res.status(500).json({ success: false, error: "SERVER_ERROR" });
  }
});

// POST /public/orders (alias)
app.post('/public/orders', async (req, res) => {
  const sql = getDb();
  const body = req.body;

  if (!body?.customer_name || !body?.customer_phone) {
    return res.status(400).json({ success: false, error: "MISSING_FIELDS" });
  }

  const slug = body.restaurant_slug || body.slug;
  if (!slug) return res.status(400).json({ success: false, error: "MISSING_RESTAURANT_SLUG" });

  try {
    const rest = await sql`SELECT id, name, whatsapp_number FROM app.restaurants WHERE slug = ${slug} LIMIT 1`;
    if (!rest?.[0]?.id) return res.status(404).json({ success: false, error: "NOT_FOUND" });

    const rid = rest[0].id;
    const rname = rest[0].name;
    const phone = String(rest[0].whatsapp_number || "").replace(/\D/g, "");
    const time = body.delivery_time || "12:00";
    const bowls = Array.isArray(body.bowls) ? body.bowls : [];

    const result = await sql`
      SELECT poke.create_order(
        ${rid}::uuid, ${body.customer_name}, ${body.customer_phone},
        ${body.location_id || null}::uuid, ${body.delivery_address || ''}, ${time},
        ${body.notes || ''}, ${sql.json(bowls)}, ${body.discount_code || null}
      ) as result
    `;

    const order = result?.[0]?.result;
    if (!order?.success) return res.status(400).json({ success: false, error: order?.error || "CREATE_FAILED" });

    const msg = buildMessage(body, order, rname);
    const deeplink = `https://wa.me/${phone}?text=${encodeURIComponent(msg)}`;

    return res.json({
      success: true,
      order_id: order.order_id,
      order_number: order.order_number,
      subtotal: order.subtotal,
      delivery_fee: order.delivery_fee,
      discount_amount: order.discount_amount,
      total: order.total,
      whatsapp: { to: phone, text: msg, deeplink },
    });
  } catch (e) {
    console.error("Error:", e);
    return res.status(500).json({ success: false, error: "SERVER_ERROR" });
  }
});

// ============================================================
// ADMIN ENDPOINTS (AUTH REQUIRED)
// ============================================================

// GET /admin/billing/plans
app.get('/admin/billing/plans', authMiddleware, async (req, res) => {
  const sql = getDb();
  
  try {
    const plans = await sql`
      SELECT code, name, description, type, price_per_credit, package_price,
             credits_included, bonus_credits, stripe_price_id, stripe_coupon_id
      FROM billing.plans
      WHERE is_active = true
      ORDER BY sort_order
    `;
    return res.json({ success: true, plans });
  } catch (e) {
    console.error("Error:", e);
    return res.status(500).json({ success: false, error: "SERVER_ERROR" });
  }
});

// GET /admin/billing/subscription
app.get('/admin/billing/subscription', authMiddleware, async (req, res) => {
  const sql = getDb();
  const { restaurantId } = req.auth;
  
  try {
    const [subscription] = await sql`
      SELECT s.*, p.name as plan_name, p.price_per_credit,
             (s.credits_balance + s.bonus_balance) as total_credits
      FROM billing.subscriptions s
      JOIN billing.plans p ON p.code = s.plan_code
      WHERE s.restaurant_id = ${restaurantId}::uuid
      LIMIT 1
    `;

    if (!subscription) {
      return res.json({ success: true, subscription: null, message: "No active subscription" });
    }

    return res.json({ success: true, subscription });
  } catch (e) {
    console.error("Error:", e);
    return res.status(500).json({ success: false, error: "SERVER_ERROR" });
  }
});

// POST /admin/billing/checkout
app.post('/admin/billing/checkout', authMiddleware, async (req, res) => {
  const sql = getDb();
  const { restaurantId, tenantId, userId } = req.auth;
  const { plan_code: planCode } = req.body;

  if (!planCode) {
    return res.status(400).json({ success: false, error: "MISSING_PLAN_CODE" });
  }

  try {
    const [plan] = await sql`
      SELECT * FROM billing.plans 
      WHERE code = ${planCode} AND is_active = true
    `;

    if (!plan) {
      return res.status(404).json({ success: false, error: "PLAN_NOT_FOUND" });
    }

    if (!plan.stripe_price_id) {
      return res.status(500).json({ success: false, error: "STRIPE_NOT_CONFIGURED" });
    }

    const [restaurant] = await sql`
      SELECT id, name, slug FROM app.restaurants 
      WHERE id = ${restaurantId}::uuid
    `;

    let [subscription] = await sql`
      SELECT stripe_customer_id FROM billing.subscriptions
      WHERE restaurant_id = ${restaurantId}::uuid
      LIMIT 1
    `;

    let stripeCustomerId = subscription?.stripe_customer_id;

    if (!stripeCustomerId) {
      const customer = await stripeRequest("/customers", "POST", {
        name: restaurant.name,
        metadata: {
          restaurant_id: restaurantId,
          tenant_id: tenantId,
          slug: restaurant.slug
        }
      });
      stripeCustomerId = customer.id;
    }

    const checkoutParams = {
      customer: stripeCustomerId,
      mode: "payment",
      success_url: `https://ordinlampo-admin.netlify.app/?checkout=success&plan=${planCode}`,
      cancel_url: `https://ordinlampo-admin.netlify.app/?checkout=cancelled`,
      "line_items[0][price]": plan.stripe_price_id,
      "line_items[0][quantity]": "1",
      "metadata[plan_code]": planCode,
      "metadata[restaurant_id]": restaurantId,
      "metadata[tenant_id]": tenantId,
      "metadata[user_id]": userId,
    };

    if (plan.stripe_coupon_id) {
      checkoutParams["discounts[0][coupon]"] = plan.stripe_coupon_id;
    }

    const session = await stripeRequest("/checkout/sessions", "POST", checkoutParams);

    if (session.error) {
      console.error("Stripe error:", session.error);
      return res.status(500).json({ success: false, error: session.error.message });
    }

    return res.json({
      success: true,
      checkout_url: session.url,
      session_id: session.id
    });
  } catch (e) {
    console.error("Error:", e);
    return res.status(500).json({ success: false, error: "SERVER_ERROR" });
  }
});

// GET /admin/billing/history
app.get('/admin/billing/history', authMiddleware, async (req, res) => {
  const sql = getDb();
  const { restaurantId } = req.auth;

  try {
    const [subscription] = await sql`
      SELECT id FROM billing.subscriptions
      WHERE restaurant_id = ${restaurantId}::uuid
    `;

    if (!subscription) {
      return res.json({ success: true, transactions: [], invoices: [] });
    }

    const transactions = await sql`
      SELECT * FROM billing.credit_transactions
      WHERE subscription_id = ${subscription.id}
      ORDER BY created_at DESC
      LIMIT 50
    `;

    const invoices = await sql`
      SELECT * FROM billing.invoices
      WHERE subscription_id = ${subscription.id}
      ORDER BY created_at DESC
      LIMIT 20
    `;

    return res.json({ success: true, transactions, invoices });
  } catch (e) {
    console.error("Error:", e);
    return res.status(500).json({ success: false, error: "SERVER_ERROR" });
  }
});

// GET /admin/orders
app.get('/admin/orders', authMiddleware, async (req, res) => {
  const sql = getDb();
  const { restaurantId, userId, role } = req.auth;
  const date = req.query.date || todayISO();
  const requestId = getRequestId(req);
  const ip = getClientIp(req);
  const ua = getUA(req);

  try {
    await setDbRequestContext(sql, { userId, tenantId: restaurantId, role, requestId, ip, ua });
    
    const orders = await sql`
      SELECT id, order_number, customer_name, customer_phone,
             delivery_address, scheduled_time, status, notes,
             subtotal, delivery_fee, discount_amount, total,
             created_at, updated_at, location_id
      FROM app.orders
      WHERE restaurant_id = ${restaurantId}::uuid AND DATE(created_at) = ${date}::date
      ORDER BY created_at DESC
    `;
    return res.json({ success: true, date, orders });
  } catch (e) {
    console.error("Error:", e);
    return res.status(500).json({ success: false, error: "SERVER_ERROR" });
  }
});

// PUT /admin/orders/:id
app.put('/admin/orders/:id', authMiddleware, async (req, res) => {
  const sql = getDb();
  const { restaurantId, userId, role } = req.auth;
  const { id: orderId } = req.params;
  const { status } = req.body;
  const requestId = getRequestId(req);
  const ip = getClientIp(req);
  const ua = getUA(req);

  const VALID = new Set(["PENDING","CONFIRMED","PREPARING","READY","DELIVERING","DELIVERED","CANCELLED","REJECTED"]);
  if (!status || !VALID.has(status)) {
    return res.status(400).json({ success: false, error: "INVALID_STATUS" });
  }

  try {
    await setDbRequestContext(sql, { userId, tenantId: restaurantId, role, requestId, ip, ua });

    const before = await sql`
      SELECT id, status FROM app.orders
      WHERE id = ${orderId}::uuid AND restaurant_id = ${restaurantId}::uuid LIMIT 1
    `;
    if (!before?.[0]?.id) return res.status(404).json({ success: false, error: "NOT_FOUND" });

    await sql`
      UPDATE app.orders SET status = ${status}, updated_at = NOW()
      WHERE id = ${orderId}::uuid AND restaurant_id = ${restaurantId}::uuid
    `;

    return res.json({ success: true, status });
  } catch (e) {
    console.error("Error:", e);
    return res.status(500).json({ success: false, error: "SERVER_ERROR" });
  }
});

// GET /admin/settings
app.get('/admin/settings', authMiddleware, async (req, res) => {
  const sql = getDb();
  const { restaurantId, userId, role } = req.auth;
  const requestId = getRequestId(req);
  const ip = getClientIp(req);
  const ua = getUA(req);

  try {
    await setDbRequestContext(sql, { userId, tenantId: restaurantId, role, requestId, ip, ua });

    const r = await sql`
      SELECT id, name, slug, whatsapp_number FROM app.restaurants
      WHERE id = ${restaurantId}::uuid LIMIT 1
    `;
    if (!r?.[0]?.id) return res.status(404).json({ success: false, error: "NOT_FOUND" });

    const locations = await sql`
      SELECT id, name, delivery_fee, sort_order FROM app.locations
      WHERE restaurant_id = ${restaurantId}::uuid
      ORDER BY sort_order NULLS LAST, name
    `;

    return res.json({ success: true, restaurant: r[0], locations });
  } catch (e) {
    console.error("Error:", e);
    return res.status(500).json({ success: false, error: "SERVER_ERROR" });
  }
});

// 404 catch-all
app.use((req, res) => {
  res.status(404).json({ success: false, error: "NOT_FOUND", path: req.path });
});

// Error handler
app.use((err, req, res, next) => {
  console.error("Server error:", err);
  res.status(500).json({ success: false, error: "SERVER_ERROR" });
});

// ============================================================
// START SERVER
// ============================================================
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Ordini-Lampo API running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});
