import postgres from 'postgres';
interface Env { HYPERDRIVE: Hyperdrive; OUTBOX_QUEUE: Queue; }
const SLOT_LIMITS = { normal: 8, peak: 5 };
const PEAK_SLOTS = ['12:00', '12:30', '19:30', '20:00'];

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Content-Type': 'application/json'
    };
    if (method === 'OPTIONS') return new Response(null, { headers: corsHeaders });
    try {
      if (path === '/' || path === '/health') {
        return json({ status: 'ok', version: '1.2.1-slots-fix' }, corsHeaders);
      }
      const bundleMatch = path.match(/^\/poke\/([^\/]+)\/bundle$/);
      if (bundleMatch && method === 'GET') {
        return await getBundle(env, bundleMatch[1], corsHeaders);
      }
      const slotsMatch = path.match(/^\/poke\/([^\/]+)\/slots$/);
      if (slotsMatch && method === 'GET') {
        const date = url.searchParams.get('date') || todayISO();
        return await getSlots(env, slotsMatch[1], date, corsHeaders);
      }
      const orderMatch = path.match(/^\/poke\/([^\/]+)\/order$/);
      if (orderMatch && method === 'POST') {
        const body = await request.json();
        return await createOrder(env, orderMatch[1], body, corsHeaders);
      }
      return json({ error: 'Not Found', path }, corsHeaders, 404);
    } catch (e: any) {
      return json({ error: e.message }, corsHeaders, 500);
    }
  }
} satisfies ExportedHandler<Env>;

async function getBundle(env: Env, slug: string, h: any) {
  const sql = postgres(env.HYPERDRIVE.connectionString);
  try {
    const r = await sql`SELECT poke.get_public_bundle_by_slug(${slug}) as bundle`;
    if (!r[0]?.bundle) return json({ error: 'Not found' }, h, 404);
    return json({ success: true, data: r[0].bundle }, h);
  } finally { await sql.end(); }
}

async function getSlots(env: Env, slug: string, date: string, h: any) {
  const sql = postgres(env.HYPERDRIVE.connectionString);
  try {
    const rest = await sql`SELECT id FROM app.restaurants WHERE slug = ${slug} LIMIT 1`;
    if (!rest[0]?.id) return json({ error: 'Not found' }, h, 404);
    const rid = rest[0].id;
    const counts = await sql`
      SELECT scheduled_time::text as slot, COUNT(*)::int as cnt
      FROM app.orders 
      WHERE restaurant_id = ${rid} AND DATE(created_at) = ${date}::date
        AND status NOT IN ('CANCELLED', 'REJECTED')
      GROUP BY scheduled_time
    `;
    const blocked = await sql`
      SELECT slot_time::text as slot, reason
      FROM app.blocked_slots
      WHERE restaurant_id = ${rid} AND slot_date = ${date}::date
    `;
    const availability: any = {};
    const allSlots = ['11:30','12:00','12:30','13:00','13:30','14:00','18:30','19:00','19:30','20:00','20:30','21:00','21:30','22:00'];
    allSlots.forEach(slot => {
      const found = counts.find((c: any) => c.slot?.startsWith(slot));
      const block = blocked.find((b: any) => b.slot?.startsWith(slot));
      const count = found?.cnt || 0;
      const limit = PEAK_SLOTS.includes(slot) ? SLOT_LIMITS.peak : SLOT_LIMITS.normal;
      if (block) {
        availability[slot] = { count, limit, available: false, blocked: true, reason: block.reason };
      } else {
        availability[slot] = { count, limit, available: count < limit };
      }
    });
    return json({ success: true, date, availability }, h);
  } finally { await sql.end(); }
}
async function createOrder(env: Env, slug: string, body: any, h: any) {
  const sql = postgres(env.HYPERDRIVE.connectionString);
  try {
    if (!body.customer_name || !body.customer_phone || !body.bowls) {
      return json({ error: 'Missing required fields' }, h, 400);
    }
    const rest = await sql`SELECT id, name, whatsapp_number FROM app.restaurants WHERE slug = ${slug} LIMIT 1`;
    if (!rest[0]?.id) return json({ error: 'Not found' }, h, 404);
    const rid = rest[0].id;
    const rname = rest[0].name;
    const phone = rest[0].whatsapp_number?.replace(/\D/g, '') || '';
    const time = body.delivery_time || '12:00';
    const slotKey = time.substring(0, 5);
    const existing = await sql`
      SELECT COUNT(*)::int as cnt FROM app.orders 
      WHERE restaurant_id = ${rid} AND DATE(created_at) = CURRENT_DATE
        AND scheduled_time::text LIKE ${slotKey + '%'}
        AND status NOT IN ('CANCELLED', 'REJECTED')
    `;
    const cnt = existing[0]?.cnt || 0;
    const limit = PEAK_SLOTS.includes(slotKey) ? SLOT_LIMITS.peak : SLOT_LIMITS.normal;
    if (cnt >= limit) {
      return json({ error: 'Slot full', message: `Slot ${slotKey} pieno (${limit} ordini max)` }, h, 400);
    }
    const result = await sql`
      SELECT poke.create_order(
        ${rid}::uuid, ${body.customer_name}, ${body.customer_phone},
        ${body.location_id || null}::uuid, ${body.delivery_address || ''},
        ${time}, ${body.notes || ''}, ${body.bowls}::jsonb,
        ${body.discount_code || null}
      ) as result
    `;
    const order = result[0]?.result;
    if (!order?.success) return json({ error: order?.error || 'Failed' }, h, 400);
    const msg = buildMessage(body, order, rname);
    const deeplink = `https://wa.me/${phone}?text=${encodeURIComponent(msg)}`;
    return json({
      success: true, order_id: order.order_id, order_number: order.order_number,
      subtotal: order.subtotal, delivery_fee: order.delivery_fee,
      discount_amount: order.discount_amount, total: order.total,
      whatsapp: { to: phone, text: msg, deeplink }
    }, h);
  } finally { await sql.end(); }
}

function buildMessage(body: any, order: any, rname: string): string {
  const now = new Date();
  const d = now.toLocaleDateString('it-IT');
  const t = now.toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit' });
  let msg = `==================\nSEZIONE 1: DATI ORDINE\n==================\n`;
  msg += `N. Ordine: #${order.order_number}\nData Ordine: ${d} ore ${t}\n`;
  msg += `Ora Consegna: ${body.delivery_time || '12:00'}\n`;
  msg += `==================\nSEZIONE 2: INGREDIENTI\n==================\n`;
  if (body.bowls?.length) {
    body.bowls.forEach((b: any, i: number) => {
      msg += `BOWL #${i+1} (${b.bowl_type_name || 'Regular'})\n------------------\n`;
      ['base','proteine','verdure','salse','toppings'].forEach(cat => {
        if (b[cat]?.length) {
          msg += `${cat.charAt(0).toUpperCase() + cat.slice(1)} [${b[cat].length}]:\n`;
          b[cat].forEach((x: any) => { msg += ` - ${x.name}${x.qty > 1 ? ' x' + x.qty : ''}\n`; });
        }
      });
    });
  }
  if (body.allergie) msg += `ALLERGIE: ${body.allergie}\n`;
  if (body.posate_richieste) msg += `Posate Richieste: Si\n`;
  msg += `==================\nSEZIONE 3: CLIENTE\n==================\n`;
  msg += `Nome: ${body.customer_name}\nTelefono: ${body.customer_phone}\n`;
  msg += `Indirizzo: ${body.delivery_address || 'Ritiro'}\n`;
  if (body.citofono) msg += `Citofono: ${body.citofono}\n`;
  msg += `Pagamento: ${body.payment_method || 'Contanti'}\n`;
  msg += `==================\nSEZIONE 4: RIEPILOGO\n==================\n`;
  msg += `Subtotale: EUR ${order.subtotal.toFixed(2)}\n`;
  if (order.delivery_fee > 0) msg += `Consegna: EUR ${order.delivery_fee.toFixed(2)}\n`;
  if (order.discount_amount > 0) msg += `Sconto: -EUR ${order.discount_amount.toFixed(2)}\n`;
  msg += `TOTALE: EUR ${order.total.toFixed(2)}\n`;
  msg += `Grazie per aver scelto ${rname}!\nPowered by Ordini-Lampo.it`;
  return msg;
}

function json(data: any, h: any, status = 200) {
  return new Response(JSON.stringify(data, null, 2), { status, headers: h });
}

function todayISO() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
}
