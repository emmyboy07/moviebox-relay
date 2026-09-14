/**
 * MovieBox mobile-bff relay
 * =============================================================================
 * Our production server's IP got blocked by MovieBox's gateway specifically
 * for mobile-bff CONTENT routes (search/get/resource/season-info - the
 * "bottom-tab" auth endpoint still works fine, only content retrieval 406s).
 * This Worker just forwards those specific requests through Cloudflare's own
 * IP range instead, which isn't blocked.
 *
 * Deploy (no CLI needed):
 *   1. https://dash.cloudflare.com -> Workers & Pages -> Create -> "Create Worker"
 *   2. Give it any name (e.g. "moviebox-relay") -> Deploy (deploys the default
 *      hello-world template first, that's fine)
 *   3. Click "Edit code" -> select all -> paste this whole file -> Deploy
 *   4. Set the secret: Settings -> Variables and Secrets -> Add -> name
 *      RELAY_SECRET, type "Secret", any long random value you make up -> Save
 *      (must redeploy once after adding it - click Deploy again)
 *   5. Copy the worker's URL (shown at the top of the editor, looks like
 *      https://moviebox-relay.<your-subdomain>.workers.dev) and send it back,
 *      along with the RELAY_SECRET value you picked, so the app can be wired
 *      up to use it.
 *
 * Usage once deployed: GET/POST <worker-url>/?url=<url-encoded target>
 * with header X-Relay-Secret: <RELAY_SECRET>. Only forwards to *.aoneroom.com
 * hosts - anything else is rejected.
 * =============================================================================
 */

const ALLOWED_HOST_PATTERN = /(^|\.)aoneroom\.com$/;

// Headers that are either hop-by-hop or automatically set by fetch() itself -
// forwarding them from the incoming request would conflict with what the
// Worker's own outbound fetch needs to set.
const STRIP_REQUEST_HEADERS = new Set([
    "host", "connection", "content-length", "cf-connecting-ip", "cf-ray",
    "cf-visitor", "cf-ipcountry", "x-forwarded-for", "x-forwarded-proto",
    "x-real-ip", "x-relay-secret",
]);

export default {
    async fetch(request, env) {
        const url = new URL(request.url);

        if (!env.RELAY_SECRET || request.headers.get("x-relay-secret") !== env.RELAY_SECRET) {
            return new Response("Forbidden", { status: 403 });
        }

        const target = url.searchParams.get("url");
        if (!target) {
            return new Response("Missing url parameter", { status: 400 });
        }

        let targetUrl;
        try {
            targetUrl = new URL(target);
        } catch {
            return new Response("Invalid url parameter", { status: 400 });
        }
        if (!ALLOWED_HOST_PATTERN.test(targetUrl.hostname)) {
            return new Response("Host not allowed", { status: 403 });
        }

        const outboundHeaders = new Headers();
        for (const [key, value] of request.headers) {
            if (!STRIP_REQUEST_HEADERS.has(key.toLowerCase())) {
                outboundHeaders.set(key, value);
            }
        }

        const upstream = await fetch(targetUrl.toString(), {
            method: request.method,
            headers: outboundHeaders,
            body: request.method === "GET" || request.method === "HEAD" ? undefined : await request.arrayBuffer(),
        });

        const responseHeaders = new Headers(upstream.headers);
        responseHeaders.set("Access-Control-Allow-Origin", "*");
        return new Response(upstream.body, { status: upstream.status, headers: responseHeaders });
    },
};
