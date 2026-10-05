const worker = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const bootstrap = await handleV85(request, env, async (key, device_id) => {
      const verifyURL = new URL('/v1/license/verify', request.url);
      const response = await worker.fetch(new Request(verifyURL, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({key, device_id})
      }), env);
      return response.ok ? response.json() : null;
    });
    if (bootstrap) return bootstrap;

    if (
      request.method === "GET" &&
      !url.pathname.startsWith("/v1/") &&
      url.pathname !== "/health"
    ) {
      return env.ASSETS.fetch(request);
    }

    if (url.pathname === "/health" && request.method === "GET") {
      const maintenance = await getMaintenance(env);
      return json({
        ok: true,
        service: "vip-reaper",
        admin_token_configured: Boolean(env.ADMIN_TOKEN),
        maintenance: maintenance.enabled
      });
    }

    async function admin(req) {
      const auth = req.headers.get("Authorization") || "";
      const token = auth.replace(/^Bearer\s+/i, "");
      return Boolean(
        env.ADMIN_TOKEN &&
        token.trim() === env.ADMIN_TOKEN.trim()
      );
    }

    // ==========================================
    // Maintenance - قراءة حالة السيرفر
    // ==========================================
    if (
      url.pathname === "/v1/admin/maintenance" &&
      request.method === "GET"
    ) {
      if (!(await admin(request))) {
        return json({ ok: false, error: "unauthorized" }, 401);
      }

      const maintenance = await getMaintenance(env);

      return json({
        ok: true,
        ...maintenance
      });
    }

    // ==========================================
    // Maintenance - تشغيل / إيقاف
    // ==========================================
    if (
      url.pathname === "/v1/admin/maintenance" &&
      request.method === "POST"
    ) {
      if (!(await admin(request))) {
        return json({ ok: false, error: "unauthorized" }, 401);
      }

      try {
        const body = await request.json();

        if (typeof body?.enabled !== "boolean") {
          return json(
            {
              ok: false,
              error: "invalid_maintenance_state"
            },
            400
          );
        }

        const message =
          typeof body?.message === "string" &&
          body.message.trim()
            ? body.message.trim().slice(0, 500)
            : MAINTENANCE_MESSAGE;

        await ensureSettings(env);

        await env.DB.prepare(
          `INSERT INTO server_settings
           (name,value,updated_at)
           VALUES
           ('maintenance_enabled',?,datetime('now'))
           ON CONFLICT(name)
           DO UPDATE SET
           value=excluded.value,
           updated_at=datetime('now')`
        )
          .bind(body.enabled ? "1" : "0")
          .run();

        await env.DB.prepare(
          `INSERT INTO server_settings
           (name,value,updated_at)
           VALUES
           ('maintenance_message',?,datetime('now'))
           ON CONFLICT(name)
           DO UPDATE SET
           value=excluded.value,
           updated_at=datetime('now')`
        )
          .bind(message)
          .run();

        return json({
          ok: true,
          enabled: body.enabled,
          message
        });
      } catch (e) {
        return json(
          {
            ok: false,
            error: "server_error"
          },
          500
        );
      }
    }

    // ==========================================
    // التحقق من المفتاح
    // ==========================================
    if (
      url.pathname === "/v1/license/verify" &&
      request.method === "POST"
    ) {
      try {
        // أولاً نفحص حالة الصيانة
        const maintenance = await getMaintenance(env);

        if (maintenance.enabled) {
          return json(
            {
              ok: false,
              maintenance: true,
              error: "maintenance",
              message: maintenance.message
            },
            503
          );
        }

        await cleanupExpired(env);

        const body = await request.json();

        const key = body?.key;

        const deviceId =
          typeof body?.device_id === "string"
            ? body.device_id.trim()
            : "";

        if (!isValidKey(key)) {
          return json(
            {
              ok: false,
              error: "invalid_key"
            },
            400
          );
        }

        const row = await env.DB.prepare(
          `SELECT
             key,
             status,
             expires_at,
             device_mode,
             device_hash,
             created_at,
             last_seen_at
           FROM licenses
           WHERE key=?`
        )
          .bind(key)
          .first();

        if (!row) {
          return json(
            {
              ok: false,
              error: "invalid_license"
            },
            404
          );
        }

        if (row.status !== "active") {
          return json(
            {
              ok: false,
              error: "license_" + row.status
            },
            403
          );
        }

        if (
          row.expires_at &&
          new Date(row.expires_at) <= new Date()
        ) {
          await env.DB.prepare(
            "DELETE FROM licenses WHERE key=?"
          )
            .bind(key)
            .run();

          return json(
            {
              ok: false,
              error: "license_expired"
            },
            403
          );
        }

        let boundNow = false;

        if (row.device_mode === "single_device") {
          if (!deviceId) {
            return json(
              {
                ok: false,
                error: "device_id_required"
              },
              400
            );
          }

          const hash = await sha256(deviceId);

          if (!row.device_hash) {
            await env.DB.prepare(
              `UPDATE licenses
               SET device_hash=?,
                   last_seen_at=datetime('now')
               WHERE key=? AND device_hash IS NULL`
            )
              .bind(hash, key)
              .run();

            const binding = await env.DB.prepare(
              "SELECT device_hash FROM licenses WHERE key=?"
            ).bind(key).first();
            if (!binding || binding.device_hash !== hash) {
              return json({ok: false, error: "device_mismatch"}, 403);
            }
            row.device_hash = binding.device_hash;
            boundNow = true;
          } else if (row.device_hash !== hash) {
            return json(
              {
                ok: false,
                error: "device_mismatch"
              },
              403
            );
          }
        }

        await env.DB.prepare(
          `UPDATE licenses
           SET last_seen_at=datetime('now')
           WHERE key=?`
        )
          .bind(key)
          .run();

        return json({
          ok: true,
          key: row.key,
          expires_at: row.expires_at,
          device_mode: row.device_mode,
          device_bound: Boolean(row.device_hash),
          bound_now: boundNow
        });
      } catch (e) {
        return json(
          {
            ok: false,
            error: "server_error"
          },
          500
        );
      }
    }

    // حذف المفاتيح المنتهية
    await cleanupExpired(env);

    // ==========================================
    // عرض المفاتيح + البحث
    // مثال:
    // /v1/admin/licenses?q=ABC
    // ==========================================
    if (
      url.pathname === "/v1/admin/licenses" &&
      request.method === "GET"
    ) {
      if (!(await admin(request))) {
        return json(
          {
            ok: false,
            error: "unauthorized"
          },
          401
        );
      }

      const q = (
        url.searchParams.get("q") || ""
      )
        .trim()
        .toUpperCase();

      let stmt;

      if (q) {
        stmt = env.DB.prepare(
          `SELECT
             id,
             key,
             status,
             expires_at,
             created_at,
             last_seen_at,
             device_mode,
             CASE
               WHEN device_hash IS NULL THEN 0
               ELSE 1
             END AS device_bound,
             duration_value,
             duration_unit
           FROM licenses
           WHERE UPPER(key) LIKE ?
           ORDER BY id DESC`
        ).bind("%" + q + "%");
      } else {
        stmt = env.DB.prepare(
          `SELECT
             id,
             key,
             status,
             expires_at,
             created_at,
             last_seen_at,
             device_mode,
             CASE
               WHEN device_hash IS NULL THEN 0
               ELSE 1
             END AS device_bound,
             duration_value,
             duration_unit
           FROM licenses
           ORDER BY id DESC`
        );
      }

      const result = await stmt.all();

      return json({
        ok: true,
        licenses: result.results || []
      });
    }

    // ==========================================
    // إنشاء مفتاح
    // ==========================================
    if (
      url.pathname === "/v1/admin/licenses" &&
      request.method === "POST"
    ) {
      if (!(await admin(request))) {
        return json(
          {
            ok: false,
            error: "unauthorized"
          },
          401
        );
      }

      try {
        const body = await request.json();

        const value = Number(body?.duration_value);

        const unit =
          body?.duration_unit === "days"
            ? "days"
            : "hours";

        const mode =
          body?.device_mode === "unlimited_devices"
            ? "unlimited_devices"
            : "single_device";

        if (
          !Number.isInteger(value) ||
          value < 1 ||
          value >
            (unit === "days" ? 3650 : 87600)
        ) {
          return json(
            {
              ok: false,
              error: "invalid_duration"
            },
            400
          );
        }

        const key = makeKey();

        const ms =
          value *
          (unit === "days"
            ? 86400000
            : 3600000);

        const expires =
          new Date(
            Date.now() + ms
          ).toISOString();

        await env.DB.prepare(
          `INSERT INTO licenses
           (
             key,
             status,
             expires_at,
             device_mode,
             device_hash,
             duration_value,
             duration_unit
           )
           VALUES
           (?,'active',?,?,NULL,?,?)`
        )
          .bind(
            key,
            expires,
            mode,
            value,
            unit
          )
          .run();

        return json({
          ok: true,
          key,
          expires_at: expires,
          device_mode: mode,
          duration_value: value,
          duration_unit: unit
        });
      } catch (e) {
        return json(
          {
            ok: false,
            error: "server_error"
          },
          500
        );
      }
    }

    // ==========================================
    // إدارة مفتاح محدد
    // ==========================================
    const m = url.pathname.match(
      /^\/v1\/admin\/licenses\/([^/]+)\/(revoke|activate|reset-device|reset-license|delete)$/
    );

    if (m && request.method === "POST") {
      if (!(await admin(request))) {
        return json(
          {
            ok: false,
            error: "unauthorized"
          },
          401
        );
      }

      const key =
        decodeURIComponent(m[1]);

      const action = m[2];

      // إيقاف مفتاح
      if (action === "revoke") {
        const r =
          await env.DB.prepare(
            `UPDATE licenses
             SET status='revoked'
             WHERE key=?`
          )
            .bind(key)
            .run();

        return json({
          ok: r.meta?.changes === 1
        });
      }

      // تفعيل مفتاح
      if (action === "activate") {
        const r =
          await env.DB.prepare(
            `UPDATE licenses
             SET status='active'
             WHERE key=?`
          )
            .bind(key)
            .run();

        return json({
          ok: r.meta?.changes === 1
        });
      }

      // Reset Device
      if (action === "reset-device") {
        const r =
          await env.DB.prepare(
            `UPDATE licenses
             SET device_hash=NULL,
                 last_seen_at=NULL
             WHERE key=?`
          )
            .bind(key)
            .run();

        return json({
          ok: r.meta?.changes === 1
        });
      }

      // Reset License
      if (action === "reset-license") {
        const row =
          await env.DB.prepare(
            `SELECT
               duration_value,
               duration_unit
             FROM licenses
             WHERE key=?`
          )
            .bind(key)
            .first();

        if (!row) {
          return json(
            {
              ok: false,
              error: "invalid_license"
            },
            404
          );
        }

        const ms =
          Number(row.duration_value) *
          (
            row.duration_unit === "days"
              ? 86400000
              : 3600000
          );

        const expires =
          new Date(
            Date.now() + ms
          ).toISOString();

        const r =
          await env.DB.prepare(
            `UPDATE licenses
             SET
               status='active',
               expires_at=?,
               device_hash=NULL,
               last_seen_at=NULL
             WHERE key=?`
          )
            .bind(
              expires,
              key
            )
            .run();

        return json({
          ok: r.meta?.changes === 1,
          expires_at: expires
        });
      }

      // حذف
      if (action === "delete") {
        const r =
          await env.DB.prepare(
            "DELETE FROM licenses WHERE key=?"
          )
            .bind(key)
            .run();

        return json({
          ok: r.meta?.changes === 1
        });
      }
    }

    return json(
      {
        ok: false,
        error: "not_found"
      },
      404
    );
  },

  // Cron cleanup
  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      cleanupExpired(env)
    );
  }
};


// ==========================================
// رسالة الصيانة
// ==========================================

const MAINTENANCE_MESSAGE =
  "السيرفر قيد الصيانة، الرجاء التحلي بالصبر حتى يتم إضافة الإصلاحات";


// ==========================================
// إنشاء جدول إعدادات السيرفر تلقائياً
// ==========================================

async function ensureSettings(env) {
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS server_settings (
       name TEXT PRIMARY KEY,
       value TEXT NOT NULL,
       updated_at TEXT DEFAULT (datetime('now'))
     )`
  ).run();
}


// ==========================================
// قراءة حالة الصيانة
// ==========================================

async function getMaintenance(env) {
  await ensureSettings(env);

  const result =
    await env.DB.prepare(
      `SELECT name,value
       FROM server_settings
       WHERE name IN (
         'maintenance_enabled',
         'maintenance_message'
       )`
    ).all();

  let enabled = false;

  let message =
    MAINTENANCE_MESSAGE;

  for (
    const row of result.results || []
  ) {
    if (
      row.name ===
      "maintenance_enabled"
    ) {
      enabled =
        row.value === "1";
    }

    if (
      row.name ===
        "maintenance_message" &&
      row.value
    ) {
      message = row.value;
    }
  }

  return {
    enabled,
    message
  };
}


// ==========================================
// حذف المفاتيح المنتهية
// ==========================================

async function cleanupExpired(env) {
  await env.DB.prepare(
    `DELETE FROM licenses
     WHERE expires_at IS NOT NULL
     AND datetime(expires_at)
         <= datetime('now')`
  ).run();
}


// ==========================================
// SHA256
// ==========================================

async function sha256(value) {
  const data =
    new TextEncoder()
      .encode(value);

  const digest =
    await crypto.subtle.digest(
      "SHA-256",
      data
    );

  return [
    ...new Uint8Array(digest)
  ]
    .map(
      x =>
        x
          .toString(16)
          .padStart(2, "0")
    )
    .join("");
}


// ==========================================
// JSON Response
// ==========================================

function json(
  data,
  status = 200
) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        "Content-Type":
          "application/json; charset=utf-8"
      }
    }
  );
}


// ==========================================
// إنشاء مفتاح
// ==========================================

function makeKey() {
  const bytes =
    new Uint8Array(12);

  crypto.getRandomValues(bytes);

  const hex = [
    ...bytes
  ]
    .map(
      x =>
        x
          .toString(16)
          .padStart(2, "0")
    )
    .join("")
    .toUpperCase();

  return hex
    .match(/.{1,6}/g)
    .join("-");
}


// ==========================================
// التحقق من صيغة المفتاح
// ==========================================

function isValidKey(key) {
  return (
    typeof key === "string" &&
    /^[A-Z0-9-]{8,80}$/.test(key)
  );
}

export default worker;


// Remote SDK bootstrap, wire-compatible with the existing v85 ARM64 loader.
const BUILD = '5144c274ddb8d824c6cdb506e9bedf04';
const encoder = new TextEncoder();
const headers = {'Content-Type':'application/octet-stream','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'};
const reply = (status, body=null) => new Response(body,{status,headers});
const hex = b => Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
function unhex(s,n){if(typeof s!=='string'||!new RegExp(`^[0-9a-f]{${n*2}}$`).test(s))throw Error('hex');return Uint8Array.from(s.match(/../g),x=>parseInt(x,16));}
async function digest(s){return new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(s)));}
function uint(n,max=Number.MAX_SAFE_INTEGER){if(!Number.isSafeInteger(n)||n<=0||n>max)throw Error('integer');return n;}
function validateCatalog(c){
  if(c.build_id!==BUILD||!Array.isArray(c.chunks)||c.chunks.length!==4)throw Error('catalog');
  uint(c.payload_size,128*1024*1024);unhex(c.payload_sha256,32);unhex(c.public_key_x963,65);
  for(const a of [c.seed_vm,c.ready_vm])if(uint(a,0xfffffff)%4)throw Error('address');
  let sum=0;
  c.chunks.forEach((e,i)=>{if(e.index!==i)throw Error('index');uint(e.plain_size,32*1024*1024);if(e.blob_size!==72+(Math.floor(e.plain_size/16)+1)*16)throw Error('size');unhex(e.sha256,32);unhex(e.keys,64);sum+=e.plain_size;});
  if(sum!==c.payload_size)throw Error('payload');return c;
}
async function settings(env){
  if(!env.REAPER_PAYLOADS||!env.DB||!env.REAPER_SIGNING_KEY_PKCS8||!env.REAPER_CATALOG_JSON)throw Error('configuration');
  const c=validateCatalog(JSON.parse(env.REAPER_CATALOG_JSON));
  const pem=env.REAPER_SIGNING_KEY_PKCS8;
  if(!/^-----BEGIN PRIVATE KEY-----\s+[A-Za-z0-9+/=\s]+-----END PRIVATE KEY-----\s*$/.test(pem))throw Error('key');
  const der=Uint8Array.from(atob(pem.replace(/-----[^-]+-----/g,'').replace(/\s/g,'')),x=>x.charCodeAt(0));
  const key=await crypto.subtle.importKey('pkcs8',der,{name:'ECDSA',namedCurve:'P-256'},false,['sign']);
  const pub=await crypto.subtle.importKey('raw',unhex(c.public_key_x963,65),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  // Reject a misconfigured signing key before delivering keys to the client.
  const probe=encoder.encode('Reaper v85 signing identity');
  const sig=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,probe);
  if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},pub,sig,probe))throw Error('identity');
  return {c,key};
}
function signatureDER(raw){
  const b=new Uint8Array(raw);if(b.length!==64)throw Error('signature');
  const integer=p=>{let i=0;while(i<31&&p[i]===0)i++;p=p.slice(i);return [...(p[0]&128?[0]:[]),...p];};
  const r=integer(b.slice(0,32)),s=integer(b.slice(32));
  return new Uint8Array([0x30,4+r.length+s.length,2,r.length,...r,2,s.length,...s]);
}
async function makeCapsule(c,key,body,issued,expiry,token){
  const b=new Uint8Array(688),v=new DataView(b.buffer);
  const put=(o,x)=>b.set(x,o),u32=(o,x)=>v.setUint32(o,x,true),u64=(o,x)=>v.setBigUint64(o,BigInt(x),true);
  put(0,encoder.encode('R85BOOT1'));u32(8,1);u32(12,4);put(16,unhex(c.build_id,16));put(32,unhex(body.nonce,32));
  put(64,await digest(body.device_id));put(96,await digest(body.key));u64(128,issued);u64(136,Math.min(issued+120,expiry));
  u64(144,c.payload_size);put(152,unhex(c.payload_sha256,32));put(184,token);u64(216,c.seed_vm);u64(224,c.ready_vm);u64(232,expiry);
  c.chunks.forEach((e,i)=>{const o=240+i*112;u32(o,i);u32(o+4,e.plain_size);u32(o+8,e.blob_size);put(o+16,unhex(e.sha256,32));put(o+48,unhex(e.keys,64));});
  const sig=signatureDER(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,b));
  const result=new Uint8Array(692+sig.length);result.set(b);new DataView(result.buffer).setUint32(688,sig.length,true);result.set(sig,692);return result;
}
async function boundedJSON(request){
  const declared=request.headers.get('Content-Length');
  if(declared!==null&&(!/^\d+$/.test(declared)||Number(declared)>1024))throw Error('length');
  if(!request.body)throw Error('body');const reader=request.body.getReader();let size=0,chunks=[];
  try{while(true){const {value,done}=await reader.read();if(done)break;size+=value.length;if(size>1024){await reader.cancel();throw Error('length');}chunks.push(value);}}
  finally{reader.releaseLock();}
  const bytes=new Uint8Array(size);let p=0;for(const chunk of chunks){bytes.set(chunk,p);p+=chunk.length;}
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
}
function validRequest(b){
  if(!b||Array.isArray(b)||typeof b!=='object'||Object.keys(b).sort().join(',')!=='build_id,device_id,key,nonce')return false;
  return typeof b.key==='string'&&/^[A-Z0-9-]{8,80}$/.test(b.key)&&typeof b.device_id==='string'&&/^[A-Za-z0-9-]{1,180}$/.test(b.device_id)&&typeof b.nonce==='string'&&/^[0-9a-f]{64}$/.test(b.nonce)&&b.build_id===BUILD;
}
async function handleV85(request,env,verify){
  const url=new URL(request.url);if(!url.pathname.startsWith('/v85/'))return null;
  if(url.search)return reply(400);
  if(url.pathname==='/v85/bootstrap'){
    if(request.method!=='POST')return reply(405);
    let body;try{body=await boundedJSON(request);if(!validRequest(body))return reply(403);}catch{return reply(403);}
    try{
      const {c,key}=await settings(env);
      const auth=await verify(body.key,body.device_id);
      if(!auth||auth.ok!==true||typeof auth.expires_at!=='string'||!/(Z|[+-]\d{2}:\d{2})$/.test(auth.expires_at))return reply(403);
      const now=Math.floor(Date.now()/1000),expiry=Math.floor(Date.parse(auth.expires_at)/1000);
      if(!Number.isSafeInteger(expiry)||expiry<=now)return reply(403);
      // D1 supplies atomic nonce uniqueness across Worker isolates.
      const id=hex(await digest(body.device_id+'\0'+body.key+'\0'+body.nonce));
      await env.DB.prepare('DELETE FROM reaper_v85_nonces WHERE expires <= ?').bind(now).run();
      await env.DB.prepare('DELETE FROM reaper_v85_sessions WHERE expires <= ?').bind(now).run();
      const used=await env.DB.prepare('INSERT OR IGNORE INTO reaper_v85_nonces (identity, expires) SELECT ?, ? WHERE (SELECT COUNT(*) FROM reaper_v85_nonces) < 4096').bind(id,now+120).run();
      if(used.meta?.changes!==1)return reply(403);
      for(let i=0;i<4;i++){const object=await env.REAPER_PAYLOADS.head(`${BUILD}/payload-${i}.bin`);if(!object||object.size!==c.chunks[i].blob_size)return reply(503);}
      const token=crypto.getRandomValues(new Uint8Array(32)),tokenHash=hex(await digest(hex(token)));
      const capsule=await makeCapsule(c,key,body,now,expiry,token);
      await env.DB.prepare('INSERT INTO reaper_v85_sessions (token_hash, expires, build_id) VALUES (?, ?, ?)').bind(tokenHash,Math.min(now+120,expiry),BUILD).run();
      return reply(200,capsule);
    }catch{return reply(503);}
  }
  const match=/^\/v85\/payload\/([0-3])\.bin$/.exec(url.pathname);
  if(!match)return reply(404);if(request.method!=='GET')return reply(405);
  const auth=request.headers.get('Authorization')||'';if(!/^Bearer [0-9a-f]{64}$/.test(auth))return reply(403);
  try{
    if(!env.DB||!env.REAPER_PAYLOADS)return reply(503);
    const session=await env.DB.prepare('SELECT expires, build_id FROM reaper_v85_sessions WHERE token_hash=?').bind(hex(await digest(auth.slice(7)))).first();
    if(!session||session.expires<=Math.floor(Date.now()/1000)||session.build_id!==BUILD)return reply(403);
    const c=validateCatalog(JSON.parse(env.REAPER_CATALOG_JSON));
    const object=await env.REAPER_PAYLOADS.get(`${BUILD}/payload-${match[1]}.bin`);
    if(!object||!object.body||object.size!==c.chunks[Number(match[1])].blob_size)return reply(503);
    return new Response(object.body,{status:200,headers:{...headers,'Content-Length':String(object.size)}});
  }catch{return reply(503);}
}
