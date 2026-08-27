import dns from "node:dns";
if (typeof dns.setDefaultResultOrder === "function") {
  dns.setDefaultResultOrder("ipv4first");
}

const GRAPH = "https://graph.facebook.com/v21.0";
const DIALOG = "https://www.facebook.com/v21.0/dialog/oauth";

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

async function graphGet<T>(path: string, query: Record<string, string>): Promise<T> {
  const url = `${GRAPH}${path}?${new URLSearchParams(query).toString()}`;
  const res = await fetch(url);
  const json = (await res.json()) as T & { error?: { message?: string } };
  if (!res.ok || json.error) {
    throw new FacebookApiError(json.error?.message || `Graph error ${res.status}`);
  }
  return json;
}

async function graphPost<T>(
  path: string,
  body: Record<string, string>,
): Promise<T> {
  const res = await fetch(`${GRAPH}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(body),
  });
  const json = (await res.json()) as T & { error?: { message?: string } };
  if (!res.ok || json.error) {
    throw new FacebookApiError(json.error?.message || `Graph error ${res.status}`);
  }
  return json;
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
