export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "GET" && !url.pathname.startsWith("/v1/") && url.pathname !== "/health") {
      return env.ASSETS.fetch(request);
    }

    if (url.pathname === "/health" && request.method === "GET") {
      return json({ ok: true, service: "vip-reaper", admin_token_configured: Boolean(env.ADMIN_TOKEN) });
    }

    async function admin(req) {
      const auth = req.headers.get("Authorization") || "";
      const token = auth.replace(/^Bearer\s+/i, "");
      return Boolean(env.ADMIN_TOKEN && token.trim() === env.ADMIN_TOKEN.trim());
    }

    // Delete expired licenses opportunistically on API activity.
    await cleanupExpired(env);

    // App verification. device_id is required for single_device keys.
    if (url.pathname === "/v1/license/verify" && request.method === "POST") {
      try {
        const body = await request.json();
        const key = body?.key;
        const deviceId = typeof body?.device_id === "string" ? body.device_id.trim() : "";

        if (!isValidKey(key)) return json({ ok:false, error:"invalid_key" }, 400);

        const row = await env.DB.prepare(
          `SELECT key,status,expires_at,device_mode,device_hash,created_at,last_seen_at
           FROM licenses WHERE key=?`
        ).bind(key).first();

        if (!row) return json({ ok:false, error:"invalid_license" }, 404);
        if (row.status !== "active") return json({ ok:false, error:"license_"+row.status }, 403);

        if (row.expires_at && new Date(row.expires_at) <= new Date()) {
          await env.DB.prepare("DELETE FROM licenses WHERE key=?").bind(key).run();
          return json({ ok:false, error:"license_expired" }, 403);
        }

        let boundNow = false;
        if (row.device_mode === "single_device") {
          if (!deviceId) return json({ ok:false, error:"device_id_required" }, 400);
          const hash = await sha256(deviceId);
          if (!row.device_hash) {
            await env.DB.prepare(
              "UPDATE licenses SET device_hash=?, last_seen_at=datetime('now') WHERE key=?"
            ).bind(hash, key).run();
            row.device_hash = hash;
            boundNow = true;
          } else if (row.device_hash !== hash) {
            return json({ ok:false, error:"device_mismatch" }, 403);
          }
        }

        await env.DB.prepare(
          "UPDATE licenses SET last_seen_at=datetime('now') WHERE key=?"
        ).bind(key).run();

        return json({
          ok:true,
          key:row.key,
          expires_at:row.expires_at,
          device_mode:row.device_mode,
          device_bound:Boolean(row.device_hash),
          bound_now:boundNow
        });
      } catch (e) {
        return json({ ok:false, error:"server_error" }, 500);
      }
    }

    if (url.pathname === "/v1/admin/licenses" && request.method === "GET") {
      if (!(await admin(request))) return json({ok:false,error:"unauthorized"},401);
      const result = await env.DB.prepare(
        `SELECT id,key,status,expires_at,created_at,last_seen_at,device_mode,
                CASE WHEN device_hash IS NULL THEN 0 ELSE 1 END AS device_bound,
                duration_value,duration_unit
         FROM licenses ORDER BY id DESC`
      ).all();
      return json({ok:true,licenses:result.results||[]});
    }

    if (url.pathname === "/v1/admin/licenses" && request.method === "POST") {
      if (!(await admin(request))) return json({ok:false,error:"unauthorized"},401);
      try {
        const body = await request.json();
        const value = Number(body?.duration_value);
        const unit = body?.duration_unit === "days" ? "days" : "hours";
        const mode = body?.device_mode === "unlimited_devices" ? "unlimited_devices" : "single_device";
        if (!Number.isInteger(value) || value < 1 || value > (unit==="days"?3650:87600)) {
          return json({ok:false,error:"invalid_duration"},400);
        }

        const key = makeKey();
        const ms = value * (unit === "days" ? 86400000 : 3600000);
        const expires = new Date(Date.now()+ms).toISOString();

        await env.DB.prepare(
          `INSERT INTO licenses
           (key,status,expires_at,device_mode,device_hash,duration_value,duration_unit)
           VALUES (?,'active',?,?,NULL,?,?)`
        ).bind(key,expires,mode,value,unit).run();

        return json({ok:true,key,expires_at:expires,device_mode:mode,duration_value:value,duration_unit:unit});
      } catch {
        return json({ok:false,error:"server_error"},500);
      }
    }

    const m = url.pathname.match(/^\/v1\/admin\/licenses\/([^/]+)\/(revoke|activate|reset-device|reset-license|delete)$/);
    if (m && request.method === "POST") {
      if (!(await admin(request))) return json({ok:false,error:"unauthorized"},401);
      const key = decodeURIComponent(m[1]);
      const action = m[2];

      if (action === "revoke") {
        const r=await env.DB.prepare("UPDATE licenses SET status='revoked' WHERE key=?").bind(key).run();
        return json({ok:r.meta?.changes===1});
      }
      if (action === "activate") {
        const r=await env.DB.prepare("UPDATE licenses SET status='active' WHERE key=?").bind(key).run();
        return json({ok:r.meta?.changes===1});
      }
      if (action === "reset-device") {
        const r=await env.DB.prepare("UPDATE licenses SET device_hash=NULL,last_seen_at=NULL WHERE key=?").bind(key).run();
        return json({ok:r.meta?.changes===1});
      }
      if (action === "reset-license") {
        const row=await env.DB.prepare("SELECT duration_value,duration_unit FROM licenses WHERE key=?").bind(key).first();
        if (!row) return json({ok:false,error:"invalid_license"},404);
        const ms=Number(row.duration_value)*(row.duration_unit==="days"?86400000:3600000);
        const expires=new Date(Date.now()+ms).toISOString();
        const r=await env.DB.prepare(
          "UPDATE licenses SET status='active',expires_at=?,device_hash=NULL,last_seen_at=NULL WHERE key=?"
        ).bind(expires,key).run();
        return json({ok:r.meta?.changes===1,expires_at:expires});
      }
      if (action === "delete") {
        const r=await env.DB.prepare("DELETE FROM licenses WHERE key=?").bind(key).run();
        return json({ok:r.meta?.changes===1});
      }
    }

    return json({ok:false,error:"not_found"},404);
  },

  // Add a Cloudflare Cron Trigger to run cleanup even when nobody uses the API.
  async scheduled(event, env, ctx) {
    ctx.waitUntil(cleanupExpired(env));
  }
};

async function cleanupExpired(env) {
  await env.DB.prepare(
    "DELETE FROM licenses WHERE expires_at IS NOT NULL AND datetime(expires_at) <= datetime('now')"
  ).run();
}

async function sha256(value) {
  const data = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].map(x=>x.toString(16).padStart(2,"0")).join("");
}

function json(data,status=200) {
  return new Response(JSON.stringify(data),{status,headers:{"Content-Type":"application/json; charset=utf-8"}});
}

function makeKey() {
  const bytes=new Uint8Array(12); crypto.getRandomValues(bytes);
  const hex=[...bytes].map(x=>x.toString(16).padStart(2,"0")).join("").toUpperCase();
  return hex.match(/.{1,6}/g).join("-");
}
function isValidKey(key) {
  return typeof key==="string" && /^[A-Z0-9-]{8,80}$/.test(key);
}
