import dns from "node:dns";
import https from "node:https";

const GRAPH = "https://graph.facebook.com/v21.0";
const DIALOG = "https://www.facebook.com/v21.0/dialog/oauth";

// Force IPv4 for all Facebook API calls. On Windows, Node.js often tries IPv6
// first for graph.facebook.com, which hangs for 10s then times out.
if (typeof dns.setDefaultResultOrder === "function") {
  dns.setDefaultResultOrder("ipv4first");
}

export const FACEBOOK_SCOPES = [
  "public_profile",
  "pages_show_list",
  "pages_read_engagement",
  "pages_manage_posts",
  "pages_manage_metadata",
].join(",");

export function metaConfigured(): boolean {
  return Boolean(process.env.META_APP_ID && process.env.META_APP_SECRET);
}

export function buildAuthUrl(opts: {
  redirectUri: string;
  state: string;
  configId?: string;
}): string {
  const appId = process.env.META_APP_ID ?? "";
  const params = new URLSearchParams({
    client_id: appId,
    redirect_uri: opts.redirectUri,
    state: opts.state,
    response_type: "code",
  });
  if (opts.configId) params.set("config_id", opts.configId);
  else params.set("scope", FACEBOOK_SCOPES);
  return `${DIALOG}?${params.toString()}`;
}

export type GraphPage = {
  page_id: string;
  page_name: string;
  page_access_token: string;
};

export class FacebookApiError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FacebookApiError";
  }
}

/** Robust HTTPS request to Facebook Graph API forcing IPv4 */
function fbRequest<T>(options: {
  method: "GET" | "POST";
  path: string;
  query?: Record<string, string>;
  body?: Record<string, string>;
}): Promise<T> {
  return new Promise((resolve, reject) => {
    let fullPath = `/v21.0${options.path}`;
    if (options.query && Object.keys(options.query).length > 0) {
      fullPath += `?${new URLSearchParams(options.query).toString()}`;
    }

    const postData = options.body ? new URLSearchParams(options.body).toString() : "";
    const headers: Record<string, string> = {};
    if (options.method === "POST") {
      headers["Content-Type"] = "application/x-www-form-urlencoded";
      headers["Content-Length"] = Buffer.byteLength(postData).toString();
    }

    const req = https.request(
      {
        hostname: "graph.facebook.com",
        port: 443,
        path: fullPath,
        method: options.method,
        headers,
        family: 4, // Explicitly force IPv4 to avoid Windows DNS timeout
        timeout: 15000,
      },
      (res) => {
        let rawData = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          rawData += chunk;
        });
        res.on("end", () => {
          try {
            const json = JSON.parse(rawData);
            if (res.statusCode && res.statusCode >= 400) {
              const errMsg = json.error?.message || `Facebook Graph API error (status ${res.statusCode})`;
              return reject(new FacebookApiError(errMsg));
            }
            if (json.error) {
              return reject(new FacebookApiError(json.error.message || "Facebook Graph API returned an error"));
            }
            resolve(json as T);
          } catch {
            if (res.statusCode && res.statusCode >= 400) {
              return reject(new FacebookApiError(`Facebook Graph API HTTP error ${res.statusCode}`));
            }
            reject(new FacebookApiError("Invalid response from Facebook Graph API"));
          }
        });
      },
    );

    req.on("timeout", () => {
      req.destroy();
      reject(new FacebookApiError("Connection to Facebook Graph API timed out"));
    });

    req.on("error", (err) => {
      reject(new FacebookApiError(`Facebook connection error: ${err.message}`));
    });

    if (options.method === "POST" && postData) {
      req.write(postData);
    }
    req.end();
  });
}

async function graphGet<T>(path: string, query: Record<string, string>): Promise<T> {
  return fbRequest<T>({ method: "GET", path, query });
}

async function graphPost<T>(
  path: string,
  body: Record<string, string>,
): Promise<T> {
  return fbRequest<T>({ method: "POST", path, body });
}

export async function exchangeCodeForToken(code: string, redirectUri: string) {
  return graphGet<{ access_token: string; expires_in?: number }>(
    "/oauth/access_token",
    {
      client_id: process.env.META_APP_ID ?? "",
      client_secret: process.env.META_APP_SECRET ?? "",
      redirect_uri: redirectUri,
      code,
    },
  );
}

export async function exchangeForLongLived(shortToken: string) {
  return graphGet<{ access_token: string; expires_in?: number }>(
    "/oauth/access_token",
    {
      grant_type: "fb_exchange_token",
      client_id: process.env.META_APP_ID ?? "",
      client_secret: process.env.META_APP_SECRET ?? "",
      fb_exchange_token: shortToken,
    },
  );
}

export async function fetchUserPages(userToken: string): Promise<GraphPage[]> {
  const json = await graphGet<{
    data?: Array<{ id: string; name: string; access_token: string }>;
  }>("/me/accounts", { access_token: userToken, fields: "id,name,access_token" });
  return (json.data ?? []).map((p) => ({
    page_id: p.id,
    page_name: p.name,
    page_access_token: p.access_token,
  }));
}

export async function fetchUserinfo(userToken: string) {
  return graphGet<{ id: string; name?: string }>("/me", {
    access_token: userToken,
    fields: "id,name",
  });
}

export async function publishFacebookText(
  pageId: string,
  pageToken: string,
  message: string,
) {
  return graphPost<{ id: string }>(`/${pageId}/feed`, {
    message,
    access_token: pageToken,
  });
}

export async function publishFacebookPhoto(
  pageId: string,
  pageToken: string,
  caption: string,
  imageUrl: string,
) {
  return graphPost<{ id: string; post_id?: string }>(`/${pageId}/photos`, {
    url: imageUrl,
    caption,
    access_token: pageToken,
  });
}

export async function inspectPageToken(pageToken: string) {
  return graphGet<{ id: string; name?: string }>("/me", {
    access_token: pageToken,
    fields: "id,name",
  });
}
