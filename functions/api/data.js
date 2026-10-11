const DEFAULT_HOST = 'control.reviewspot.de';
const DEFAULT_TEAM_DOMAIN = 'https://delicate-union-f31f.cloudflareaccess.com';
let jwksCache = {at: 0, keys: []};
let schemaReady = false;
const json = (body, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff'
  }
});

function validName(v, max = 64) {
  return typeof v === 'string' && v.length > 0 && v.length <= max && /^[a-zA-Z0-9_-]+$/.test(v);
}

function b64urlBytes(s) {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=');
  const bin = atob(b64), out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64urlJson(s) {
  return JSON.parse(new TextDecoder().decode(b64urlBytes(s)));
}
async function getJwks(teamDomain) {
  if (Date.now() - jwksCache.at < 10 * 60 * 1000 && jwksCache.keys.length) return jwksCache.keys;
  const r = await fetch(teamDomain.replace(/\/$/, '') + '/cdn-cgi/access/certs', {cf:{cacheTtl:600,cacheEverything:true}});
  if (!r.ok) throw new Error('Could not load Access signing keys');
  const j = await r.json(); jwksCache = {at: Date.now(), keys: Array.isArray(j.keys) ? j.keys : []};
  return jwksCache.keys;
}
async function verifyAccess(request, env) {
  const token = request.headers.get('Cf-Access-Jwt-Assertion');
  if (!token) throw new Error('Missing Cloudflare Access JWT');
  if (!env.POLICY_AUD) throw new Error('Missing POLICY_AUD environment variable');
  const parts = token.split('.'); if (parts.length !== 3) throw new Error('Malformed Access JWT');
  const header = b64urlJson(parts[0]), payload = b64urlJson(parts[1]);
  if (header.alg !== 'RS256' || !header.kid) throw new Error('Unsupported Access JWT');
  const teamDomain = (env.TEAM_DOMAIN || DEFAULT_TEAM_DOMAIN).replace(/\/$/, '');
  if (payload.iss !== teamDomain) throw new Error('Wrong Access issuer');
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud.includes(env.POLICY_AUD)) throw new Error('Wrong Access audience');
  const now = Math.floor(Date.now()/1000);
  if (!payload.exp || payload.exp <= now) throw new Error('Expired Access JWT');
  if (payload.nbf && payload.nbf > now + 30) throw new Error('Access JWT not active yet');
  const keys = await getJwks(teamDomain), jwk = keys.find(k => k.kid === header.kid);
  if (!jwk) { jwksCache = {at:0,keys:[]}; throw new Error('Access signing key not found'); }
  const key = await crypto.subtle.importKey('jwk', jwk, {name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'}, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64urlBytes(parts[2]), new TextEncoder().encode(parts[0]+'.'+parts[1]));
  if (!ok) throw new Error('Invalid Access JWT signature');
  return payload;
}

async function ensureSchema(DB) {
  if (schemaReady) return;
  await DB.prepare(`CREATE TABLE IF NOT EXISTS reviewspot_state (
    scope TEXT NOT NULL,
    key TEXT NOT NULL,
    data TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by TEXT,
    PRIMARY KEY (scope, key)
  )`).run();
  await DB.prepare(`CREATE TABLE IF NOT EXISTS reviewspot_docs (
    scope TEXT NOT NULL,
    collection TEXT NOT NULL,
    id TEXT NOT NULL,
    data TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by TEXT,
    PRIMARY KEY (scope, collection, id)
  )`).run();
  await DB.prepare(`CREATE INDEX IF NOT EXISTS idx_reviewspot_docs_lookup
    ON reviewspot_docs(scope, collection, updated_at)`).run();
  schemaReady = true;
}

function guard(context) {
  const url = new URL(context.request.url);
  const allowedHost = context.env.APP_HOST || DEFAULT_HOST;
  if (url.hostname !== allowedHost) {
    return json({ok:false, error:'API is only available on the protected ReviewSpot hostname.'}, 403);
  }
  if (!context.env.DB) return json({ok:false, error:'D1 binding DB is missing.'}, 500);
  return null;
}

export async function onRequestGet(context) {
  const blocked = guard(context); if (blocked) return blocked;
  const {request, env} = context;
  try { await verifyAccess(request, env); } catch (e) { return json({ok:false,error:e.message || 'Invalid Cloudflare Access session.'},403); }
  try { await ensureSchema(env.DB); } catch (e) {
    console.error('ReviewSpot D1 schema init failed', e);
    return json({ok:false,error:'Database initialization failed: ' + (e && e.message ? e.message : String(e))},500);
  }
  const u = new URL(request.url);
  const kind = u.searchParams.get('kind');
  const scope = u.searchParams.get('scope');
  if (!validName(scope)) return json({ok:false,error:'Invalid scope.'},400);

  if (kind === 'state') {
    const r = await env.DB.prepare('SELECT key, data FROM reviewspot_state WHERE scope = ? ORDER BY key').bind(scope).all();
    const state = {};
    for (const row of r.results || []) {
      try { state[row.key] = JSON.parse(row.data); } catch { state[row.key] = null; }
    }
    return json({ok:true,state});
  }

  if (kind === 'docs') {
    const collection = u.searchParams.get('collection');
    if (!validName(collection)) return json({ok:false,error:'Invalid collection.'},400);
    const r = await env.DB.prepare('SELECT id, data FROM reviewspot_docs WHERE scope = ? AND collection = ? ORDER BY id').bind(scope, collection).all();
    const docs = {};
    for (const row of r.results || []) {
      try { docs[row.id] = JSON.parse(row.data); } catch { docs[row.id] = null; }
    }
    return json({ok:true,docs});
  }

  return json({ok:false,error:'Unknown kind.'},400);
}

export async function onRequestPost(context) {
  const blocked = guard(context); if (blocked) return blocked;
  const {request, env} = context;
  let identity; try { identity = await verifyAccess(request, env); } catch (e) { return json({ok:false,error:e.message || 'Invalid Cloudflare Access session.'},403); }
  try { await ensureSchema(env.DB); } catch (e) {
    console.error('ReviewSpot D1 schema init failed', e);
    return json({ok:false,error:'Database initialization failed: ' + (e && e.message ? e.message : String(e))},500);
  }
  let body;
  try { body = await request.json(); } catch { return json({ok:false,error:'Invalid JSON.'},400); }
  const scope = body && body.scope;
  const kind = body && body.kind;
  const who = typeof identity.email === 'string' ? identity.email : null;
  if (!validName(scope)) return json({ok:false,error:'Invalid scope.'},400);

  if (kind === 'state') {
    const items = body.items;
    if (!items || typeof items !== 'object' || Array.isArray(items)) return json({ok:false,error:'items must be an object.'},400);
    const entries = Object.entries(items);
    if (entries.length > 50) return json({ok:false,error:'Too many state keys.'},413);
    const statements = [];
    for (const [key, value] of entries) {
      if (!validName(key)) return json({ok:false,error:'Invalid state key.'},400);
      const data = JSON.stringify(value);
      if (data.length > 1_500_000) return json({ok:false,error:'State value too large.'},413);
      statements.push(env.DB.prepare(`
        INSERT INTO reviewspot_state(scope,key,data,updated_at,updated_by)
        VALUES(?,?,?,CURRENT_TIMESTAMP,?)
        ON CONFLICT(scope,key) DO UPDATE SET
          data=excluded.data, updated_at=CURRENT_TIMESTAMP, updated_by=excluded.updated_by
      `).bind(scope,key,data,who));
    }
    if (statements.length) await env.DB.batch(statements);
    return json({ok:true,updated:statements.length});
  }

  if (kind === 'docs') {
    const collection = body.collection;
    if (!validName(collection)) return json({ok:false,error:'Invalid collection.'},400);
    const upsert = body.upsert && typeof body.upsert === 'object' && !Array.isArray(body.upsert) ? body.upsert : {};
    const del = Array.isArray(body.delete) ? body.delete : [];
    if (Object.keys(upsert).length + del.length > 500) return json({ok:false,error:'Too many document changes.'},413);
    const statements = [];
    for (const [id, value] of Object.entries(upsert)) {
      if (!validName(id,128)) return json({ok:false,error:'Invalid document id.'},400);
      const data = JSON.stringify(value);
      if (data.length > 500_000) return json({ok:false,error:'Document too large.'},413);
      statements.push(env.DB.prepare(`
        INSERT INTO reviewspot_docs(scope,collection,id,data,updated_at,updated_by)
        VALUES(?,?,?,?,CURRENT_TIMESTAMP,?)
        ON CONFLICT(scope,collection,id) DO UPDATE SET
          data=excluded.data, updated_at=CURRENT_TIMESTAMP, updated_by=excluded.updated_by
      `).bind(scope,collection,id,data,who));
    }
    for (const id of del) {
      if (!validName(id,128)) return json({ok:false,error:'Invalid document id.'},400);
      statements.push(env.DB.prepare('DELETE FROM reviewspot_docs WHERE scope = ? AND collection = ? AND id = ?').bind(scope,collection,id));
    }
    if (statements.length) await env.DB.batch(statements);
    return json({ok:true,updated:Object.keys(upsert).length,deleted:del.length});
  }

  return json({ok:false,error:'Unknown kind.'},400);
}

export function onRequestOptions() {
  return new Response(null,{status:204,headers:{'allow':'GET, POST, OPTIONS'}});
}
