export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Serve the dashboard/static files
    if (
      request.method === "GET" &&
      !url.pathname.startsWith("/v1/") &&
      url.pathname !== "/health"
    ) {
      return env.ASSETS.fetch(request);
    }

    // Health check
    if (url.pathname === "/health" && request.method === "GET") {
      return json({
        ok: true,
        service: "license-server",
        admin_token_configured: Boolean(env.ADMIN_TOKEN)
      });
    }

    // Admin authentication
    async function admin(request) {
      const auth = request.headers.get("Authorization") || "";
      const token = auth.replace(/^Bearer\s+/i, "");

      return Boolean(
        env.ADMIN_TOKEN &&
        token.trim() === env.ADMIN_TOKEN.trim()
      );
    }

    // Verify license
    if (
      url.pathname === "/v1/license/verify" &&
      request.method === "POST"
    ) {
      try {
        const body = await request.json();
        const key = body?.key;

        if (!isValidKey(key)) {
          return json(
            { ok: false, error: "invalid_key" },
            400
          );
        }

        const row = await env.DB
          .prepare(
            "SELECT key, status, expires_at FROM licenses WHERE key = ?"
          )
          .bind(key)
          .first();

        if (!row) {
          return json(
            { ok: false, error: "invalid_license" },
            404
          );
        }

        if (row.status !== "active") {
          return json(
            { ok: false, error: "license_" + row.status },
            403
          );
        }

        if (
          row.expires_at &&
          new Date(row.expires_at) <= new Date()
        ) {
          await env.DB
            .prepare(
              "UPDATE licenses SET status = 'expired' WHERE key = ?"
            )
            .bind(key)
            .run();

          return json(
            { ok: false, error: "license_expired" },
            403
          );
        }

        await env.DB
          .prepare(
            "UPDATE licenses SET last_seen_at = datetime('now') WHERE key = ?"
          )
          .bind(key)
          .run();

        return json({
          ok: true,
          key: row.key,
          expires_at: row.expires_at
        });
      } catch {
        return json(
          { ok: false, error: "server_error" },
          500
        );
      }
    }

    // List licenses
    if (
      url.pathname === "/v1/admin/licenses" &&
      request.method === "GET"
    ) {
      if (!(await admin(request))) {
        return json(
          { ok: false, error: "unauthorized" },
          401
        );
      }

      const result = await env.DB
        .prepare(
          `SELECT id, key, status, expires_at, created_at, last_seen_at
           FROM licenses
           ORDER BY id DESC`
        )
        .all();

      return json({
        ok: true,
        licenses: result.results || []
      });
    }

    // Create license
    if (
      url.pathname === "/v1/admin/licenses" &&
      request.method === "POST"
    ) {
      if (!(await admin(request))) {
        return json(
          { ok: false, error: "unauthorized" },
          401
        );
      }

      try {
        const body = await request.json();
        const days = Number(body?.days);

        if (
          !Number.isInteger(days) ||
          days < 1 ||
          days > 3650
        ) {
          return json(
            { ok: false, error: "invalid_days" },
            400
          );
        }

        const key = makeKey();

        const expires = new Date(
          Date.now() + days * 86400000
        ).toISOString();

        await env.DB
          .prepare(
            `INSERT INTO licenses
             (key, status, expires_at)
             VALUES (?, 'active', ?)`
          )
          .bind(key, expires)
          .run();

        return json({
          ok: true,
          key,
          expires_at: expires
        });
      } catch {
        return json(
          { ok: false, error: "server_error" },
          500
        );
      }
    }

    // Revoke license
    if (
      url.pathname.startsWith("/v1/admin/licenses/") &&
      url.pathname.endsWith("/revoke") &&
      request.method === "POST"
    ) {
      if (!(await admin(request))) {
        return json(
          { ok: false, error: "unauthorized" },
          401
        );
      }

      const parts = url.pathname.split("/");
      const key = decodeURIComponent(parts[4] || "");

      const result = await env.DB
        .prepare(
          "UPDATE licenses SET status = 'revoked' WHERE key = ?"
        )
        .bind(key)
        .run();

      return json({
        ok: result.meta?.changes === 1
      });
    }

    // Activate license
    if (
      url.pathname.startsWith("/v1/admin/licenses/") &&
      url.pathname.endsWith("/activate") &&
      request.method === "POST"
    ) {
      if (!(await admin(request))) {
        return json(
          { ok: false, error: "unauthorized" },
          401
        );
      }

      const parts = url.pathname.split("/");
      const key = decodeURIComponent(parts[4] || "");

      const result = await env.DB
        .prepare(
          "UPDATE licenses SET status = 'active' WHERE key = ?"
        )
        .bind(key)
        .run();

      return json({
        ok: result.meta?.changes === 1
      });
    }

    return json(
      { ok: false, error: "not_found" },
      404
    );
  }
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8"
    }
  });
}

function makeKey() {
  const bytes = new Uint8Array(12);
  crypto.getRandomValues(bytes);

  const hex = [...bytes]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();

  return hex.match(/.{1,6}/g).join("-");
}

function isValidKey(key) {
  return (
    typeof key === "string" &&
    /^[A-Z0-9-]{8,80}$/.test(key)
  );
}
