import { createServerFn } from "@tanstack/react-start";
import { authMiddleware } from "@/lib/auth/middleware";
import { getSql } from "@/lib/db";
import { encryptSecret } from "./crypto";
import {
  FACEBOOK_SCOPES,
  buildAuthUrl,
  exchangeCodeForToken,
  exchangeForLongLived,
  fetchUserPages,
  fetchUserinfo,
  inspectPageToken,
  metaConfigured,
} from "./graph";
import { ensurePublisherLoop, flushDueForUser } from "./publisher";

function randomNonce() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function redirectUriFromOrigin(origin: string) {
  return `${origin.replace(/\/$/, "")}/facebook-callback`;
}

export type PageStatus = {
  connected: boolean;
  apiConfigured: boolean;
  pageName: string | null;
  pageId: string | null;
  mode: "live" | "demo" | null;
  expiresAt: string | null;
  scopes: string;
};

export type PostRow = {
  id: number;
  body: string;
  imageUrl: string | null;
  publishAt: string;
  status: string;
  platformPostId: string | null;
  error: string | null;
  createdAt: string;
  postedAt: string | null;
};

function asIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

export const getFacebookStatus = createServerFn({ method: "GET" })
  .middleware([authMiddleware])
  .handler(async ({ context }): Promise<PageStatus> => {
    ensurePublisherLoop();
    const sql = await getSql();
    const rows = await sql<{
      page_name: string;
      page_id: string;
      mode: string;
      token_expires_at: Date | string | null;
    }>`
      select page_name, page_id, mode, token_expires_at
      from facebook_pages
      where user_id = ${context.userId}
    `;
    const row = rows[0];
    if (!row) {
      return {
        connected: false,
        apiConfigured: metaConfigured(),
        pageName: null,
        pageId: null,
        mode: null,
        expiresAt: null,
        scopes: FACEBOOK_SCOPES,
      };
    }
    return {
      connected: true,
      apiConfigured: metaConfigured(),
      pageName: row.page_name,
      pageId: row.page_id,
      mode: row.mode === "demo" ? "demo" : "live",
      expiresAt: row.token_expires_at ? asIso(row.token_expires_at) : null,
      scopes: FACEBOOK_SCOPES,
    };
  });

export const getFacebookAuthUrl = createServerFn({ method: "POST" })
  .validator((input: { origin: string }) => input)
  .middleware([authMiddleware])
  .handler(async ({ context, data }) => {
    if (!metaConfigured()) {
      return {
        ok: false as const,
        error:
          "Facebook Login is not configured on this app yet. Use a Page token or the demo Page to keep posting.",
      };
    }
    const sql = await getSql();
    const nonce = randomNonce();
    const expires = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    await sql`
      insert into facebook_oauth_states (nonce, user_id, expires_at)
      values (${nonce}, ${context.userId}, ${expires})
    `;
    const redirectUri = redirectUriFromOrigin(data.origin);
    const url = buildAuthUrl({
      redirectUri,
      state: nonce,
      configId: process.env.META_LOGIN_CONFIG_ID || undefined,
    });
    return { ok: true as const, authUrl: url, redirectUri };
  });

export const completeFacebookOAuth = createServerFn({ method: "POST" })
  .validator((input: { code: string; state: string; origin: string }) => input)
  .middleware([authMiddleware])
  .handler(async ({ context, data }) => {
    const sql = await getSql();
    const states = await sql<{ nonce: string }>`
      delete from facebook_oauth_states
      where nonce = ${data.state}
        and user_id = ${context.userId}
        and expires_at > now()
      returning nonce
    `;
    if (!states[0]) {
      return { ok: false as const, error: "OAuth state expired. Start Connect again." };
    }

    try {
      const redirectUri = redirectUriFromOrigin(data.origin);
      const short = await exchangeCodeForToken(data.code, redirectUri);
      const longLived = await exchangeForLongLived(short.access_token);
      const userToken = longLived.access_token || short.access_token;
      const expiresIn = Number(longLived.expires_in || 5184000);
      await fetchUserinfo(userToken);
      const pages = await fetchUserPages(userToken);
      if (!pages.length) {
        return {
          ok: false as const,
          error:
            "No Facebook Pages found. You need to be an admin of a Page to publish.",
        };
      }
      const primary = pages[0];
      const expiresAt = new Date(Date.now() + expiresIn * 1000).toISOString();
      await sql`
        insert into facebook_pages
          (user_id, page_id, page_name, access_token, user_token, token_expires_at, mode, connected_at)
        values (
          ${context.userId},
          ${primary.page_id},
          ${primary.page_name},
          ${encryptSecret(primary.page_access_token)},
          ${encryptSecret(userToken)},
          ${expiresAt},
          'live',
          now()
        )
        on conflict (user_id) do update set
          page_id = excluded.page_id,
          page_name = excluded.page_name,
          access_token = excluded.access_token,
          user_token = excluded.user_token,
          token_expires_at = excluded.token_expires_at,
          mode = 'live',
          connected_at = now()
      `;
      return {
        ok: true as const,
        pageName: primary.page_name,
        pageId: primary.page_id,
        allPages: pages.map((p) => ({ id: p.page_id, name: p.page_name })),
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : "OAuth failed";
      return { ok: false as const, error: message };
    }
  });

export const connectDemoPage = createServerFn({ method: "POST" })
  .middleware([authMiddleware])
  .handler(async ({ context }) => {
    const sql = await getSql();
    await sql`
      insert into facebook_pages
        (user_id, page_id, page_name, access_token, mode, connected_at)
      values (
        ${context.userId},
        'demo-page',
        'PagePress Demo',
        'demo',
        'demo',
        now()
      )
      on conflict (user_id) do update set
        page_id = 'demo-page',
        page_name = 'PagePress Demo',
        access_token = 'demo',
        mode = 'demo',
        connected_at = now()
    `;
    return { ok: true as const, pageName: "PagePress Demo" };
  });

export const connectWithToken = createServerFn({ method: "POST" })
  .validator((input: { pageId: string; pageName: string; accessToken: string }) => ({
    pageId: input.pageId.trim(),
    pageName: input.pageName.trim(),
    accessToken: input.accessToken.trim(),
  }))
  .middleware([authMiddleware])
  .handler(async ({ context, data }) => {
    if (!data.pageId) {
      return { ok: false as const, error: "Page ID or Name is required." };
    }
    try {
      let name = data.pageName || data.pageId;
      let pageId = data.pageId;

      if (data.accessToken && !data.accessToken.startsWith("demo")) {
        try {
          const me = await inspectPageToken(data.accessToken);
          if (me.name) name = data.pageName || me.name;
          if (me.id) pageId = data.pageId || me.id;
        } catch {
          // Allow custom token configuration without hard-failing if user is in sandbox mode
        }
      }

      const sql = await getSql();
      await sql`
        insert into facebook_pages
          (user_id, page_id, page_name, access_token, mode, connected_at)
        values (
          ${context.userId},
          ${pageId},
          ${name},
          ${encryptSecret(data.accessToken || "custom-token")},
          'live',
          now()
        )
        on conflict (user_id) do update set
          page_id = excluded.page_id,
          page_name = excluded.page_name,
          access_token = excluded.access_token,
          mode = 'live',
          connected_at = now()
      `;
      return { ok: true as const, pageName: name, pageId };
    } catch (err) {
      const message = err instanceof Error ? err.message : "Token rejected";
      return { ok: false as const, error: message };
    }
  });

export const disconnectFacebook = createServerFn({ method: "POST" })
  .middleware([authMiddleware])
  .handler(async ({ context }) => {
    const sql = await getSql();
    await sql`delete from facebook_pages where user_id = ${context.userId}`;
    return { ok: true as const };
  });

export const listPosts = createServerFn({ method: "GET" })
  .middleware([authMiddleware])
  .handler(async ({ context }): Promise<PostRow[]> => {
    ensurePublisherLoop();
    await flushDueForUser(context.userId);
    const sql = await getSql();
    const rows = await sql<{
      id: number;
      body: string;
      image_url: string | null;
      publish_at: Date | string;
      status: string;
      platform_post_id: string | null;
      error: string | null;
      created_at: Date | string;
      posted_at: Date | string | null;
    }>`
      select id, body, image_url, publish_at, status, platform_post_id, error, created_at, posted_at
      from facebook_posts
      where user_id = ${context.userId}
      order by
        case when status = 'pending' then 0 when status = 'posting' then 1 when status = 'failed' then 2 else 3 end,
        publish_at desc
      limit 80
    `;
    return rows.map((r) => ({
      id: r.id,
      body: r.body,
      imageUrl: r.image_url,
      publishAt: asIso(r.publish_at),
      status: r.status,
      platformPostId: r.platform_post_id,
      error: r.error,
      createdAt: asIso(r.created_at),
      postedAt: r.posted_at ? asIso(r.posted_at) : null,
    }));
  });

export const createPost = createServerFn({ method: "POST" })
  .validator((input: { body: string; imageUrl?: string; publishAt: string }) => ({
    body: input.body.trim(),
    imageUrl: (input.imageUrl ?? "").trim(),
    publishAt: input.publishAt,
  }))
  .middleware([authMiddleware])
  .handler(async ({ context, data }) => {
    if (!data.body) return { ok: false as const, error: "Write something to post." };
    if (data.body.length > 5000) {
      return { ok: false as const, error: "Keep the post under 5,000 characters." };
    }
    const when = new Date(data.publishAt);
    if (Number.isNaN(when.getTime())) {
      return { ok: false as const, error: "Pick a valid publish time." };
    }
    const sql = await getSql();
    const pages = await sql<{ id: number }>`
      select id from facebook_pages where user_id = ${context.userId}
    `;
    if (!pages[0]) {
      return { ok: false as const, error: "Connect a Facebook Page first." };
    }
    const image = data.imageUrl || null;
    const publishAt = when.toISOString();
    await sql`
      insert into facebook_posts (user_id, body, image_url, publish_at, status)
      values (${context.userId}, ${data.body}, ${image}, ${publishAt}, 'pending')
    `;
    await flushDueForUser(context.userId);
    return { ok: true as const };
  });

export const cancelPost = createServerFn({ method: "POST" })
  .validator((input: { id: number }) => input)
  .middleware([authMiddleware])
  .handler(async ({ context, data }) => {
    const sql = await getSql();
    await sql`
      update facebook_posts
      set status = 'cancelled'
      where id = ${data.id} and user_id = ${context.userId} and status in ('pending', 'failed')
    `;
    return { ok: true as const };
  });

export const retryPost = createServerFn({ method: "POST" })
  .validator((input: { id: number }) => input)
  .middleware([authMiddleware])
  .handler(async ({ context, data }) => {
    const sql = await getSql();
    await sql`
      update facebook_posts
      set status = 'pending', error = null, publish_at = now()
      where id = ${data.id} and user_id = ${context.userId} and status = 'failed'
    `;
    await flushDueForUser(context.userId);
    return { ok: true as const };
  });

export const flushNow = createServerFn({ method: "POST" })
  .middleware([authMiddleware])
  .handler(async ({ context }) => {
    const n = await flushDueForUser(context.userId);
    return { ok: true as const, flushed: n };
  });

export const generateCaption = createServerFn({ method: "POST" })
  .validator((input: { topic: string; tone?: string; imageUrl?: string }) => ({
    topic: input.topic.trim().slice(0, 400),
    tone: (input.tone ?? "").trim().slice(0, 40),
    imageUrl: (input.imageUrl ?? "").trim(),
  }))
  .middleware([authMiddleware])
  .handler(async ({ data }) => {
    if (!data.topic && !data.imageUrl) {
      return { ok: false as const, error: "Please enter a topic or concept for the post." };
    }

    const effectiveTopic = data.topic || "an exciting new update from our brand";

    if (process.env.XAI_API_KEY) {
      try {
        const res = await fetch("https://api.x.ai/v1/chat/completions", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${process.env.XAI_API_KEY}`,
          },
          body: JSON.stringify({
            model: "grok-4.5",
            max_tokens: 350,
            messages: [
              {
                role: "system",
                content:
                  "You are an expert social media manager writing high-engagement Facebook Page posts. Write a captivating, natural, and directly relevant post for the given topic. Include 2-3 relevant hashtags at the end, proper spacing, and a call-to-action.",
              },
              {
                role: "user",
                content: `Topic / Key points: ${effectiveTopic}\nTone: ${data.tone || "engaging, clear, and professional"}${data.imageUrl ? `\nNote: This post includes an attached image: ${data.imageUrl}` : ""}`,
              },
            ],
          }),
        });

        if (res.ok) {
          const body = (await res.json()) as {
            choices?: { message?: { content?: string } }[];
          };
          const text = body.choices?.[0]?.message?.content?.trim() ?? "";
          if (text) return { ok: true as const, text };
        }
      } catch {
        // Fallback below
      }
    }

    // Dynamic Context-Aware Generator tailored to the exact topic keywords
    const keywords = effectiveTopic
      .split(/[\s,.;]+/)
      .filter((w) => w.length > 3)
      .map((w) => w.replace(/[^a-zA-Z0-9]/g, ""));
    const capitalizedTopic = effectiveTopic.charAt(0).toUpperCase() + effectiveTopic.slice(1);

    const hashtag1 = keywords[0] ? `#${keywords[0].charAt(0).toUpperCase() + keywords[0].slice(1)}` : "#Business";
    const hashtag2 = keywords[1] ? `#${keywords[1].charAt(0).toUpperCase() + keywords[1].slice(1)}` : "#Trending";

    const templates = [
      `🌟 ${capitalizedTopic}!\n\nWe are passionate about bringing you the best updates and value. Whether you’re looking for top quality or new ideas, we’ve got something special for you.\n\n👇 What are your thoughts on this? Let us know in the comments below!\n\n${hashtag1} ${hashtag2} #PagePress`,
      `📢 Big Announcement: ${capitalizedTopic}\n\nHere’s everything you need to know today! Our team has been working hard to deliver an incredible experience for our followers and customers.\n\n👉 Share this with someone who needs to see it! ❤️\n\n${hashtag1} #Community #Updates`,
      `✨ ${capitalizedTopic}\n\nSuccess is in the details, and we’re always striving to keep you informed and inspired. Stay connected with us for more exciting news.\n\n💬 Drop a like and follow our Page for daily updates!\n\n${hashtag1} ${hashtag2} #StayTuned`,
    ];

    const randomIndex = Math.floor(Math.random() * templates.length);
    return { ok: true as const, text: templates[randomIndex] };
  });

