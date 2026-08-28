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
import { ensurePublisherLoop, flushDueForUser, publishOnePost } from "./publisher";

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
    // Mark as 'posting' and attempt to publish directly — never goes back to
    // the queue so the user doesn't see it bounce between columns.
    const rows = await sql<{
      id: number;
      user_id: string;
      body: string;
      image_url: string | null;
    }>`
      update facebook_posts
      set status = 'posting', error = null
      where id = ${data.id} and user_id = ${context.userId} and status = 'failed'
      returning id, user_id, body, image_url
    `;
    const post = rows[0];
    if (post) {
      await publishOnePost(post);
    }
    return { ok: true as const };
  });

export const flushNow = createServerFn({ method: "POST" })
  .middleware([authMiddleware])
  .handler(async ({ context }) => {
    const n = await flushDueForUser(context.userId);
    return { ok: true as const, flushed: n };
  });

async function callAiProviders(prompt: string, systemPrompt: string): Promise<string | null> {
  // 1. Try xAI (Grok 2)
  if (process.env.XAI_API_KEY) {
    try {
      const res = await fetch("https://api.x.ai/v1/chat/completions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${process.env.XAI_API_KEY}`,
        },
        body: JSON.stringify({
          model: "grok-2-latest",
          max_tokens: 600,
          messages: [
            { role: "system", content: systemPrompt },
            { role: "user", content: prompt },
          ],
        }),
      });
      if (res.ok) {
        const body = (await res.json()) as { choices?: { message?: { content?: string } }[] };
        const text = body.choices?.[0]?.message?.content?.trim();
        if (text) return text;
      } else {
        const errText = await res.text();
        console.warn("[xAI API error]:", res.status, errText);
      }
    } catch (err) {
      console.error("[xAI call failed]:", err);
    }
  }

  // 2. Try OpenAI (gpt-4o-mini)
  if (process.env.OPENAI_API_KEY) {
    try {
      const res = await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
        },
        body: JSON.stringify({
          model: "gpt-4o-mini",
          max_tokens: 600,
          messages: [
            { role: "system", content: systemPrompt },
            { role: "user", content: prompt },
          ],
        }),
      });
      if (res.ok) {
        const body = (await res.json()) as { choices?: { message?: { content?: string } }[] };
        const text = body.choices?.[0]?.message?.content?.trim();
        if (text) return text;
      }
    } catch (err) {
      console.error("[OpenAI call failed]:", err);
    }
  }

  // 3. Try Groq (Llama 3.3)
  if (process.env.GROQ_API_KEY) {
    try {
      const res = await fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${process.env.GROQ_API_KEY}`,
        },
        body: JSON.stringify({
          model: "llama-3.3-70b-versatile",
          max_tokens: 600,
          messages: [
            { role: "system", content: systemPrompt },
            { role: "user", content: prompt },
          ],
        }),
      });
      if (res.ok) {
        const body = (await res.json()) as { choices?: { message?: { content?: string } }[] };
        const text = body.choices?.[0]?.message?.content?.trim();
        if (text) return text;
      }
    } catch (err) {
      console.error("[Groq call failed]:", err);
    }
  }

  // 4. Try Google Gemini
  if (process.env.GEMINI_API_KEY) {
    try {
      const res = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${process.env.GEMINI_API_KEY}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            systemInstruction: { parts: [{ text: systemPrompt }] },
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: { maxOutputTokens: 600 },
          }),
        },
      );
      if (res.ok) {
        const body = (await res.json()) as {
          candidates?: { content?: { parts?: { text?: string }[] } }[];
        };
        const text = body.candidates?.[0]?.content?.parts?.[0]?.text?.trim();
        if (text) return text;
      }
    } catch (err) {
      console.error("[Gemini call failed]:", err);
    }
  }

  return null;
}

function generateSmartFallback(topic: string, tone?: string, hasVideo?: boolean): string {
  const cleanTopic = topic.trim();
  const lower = cleanTopic.toLowerCase();

  // Extract meaningful words for hashtags
  const words = cleanTopic
    .replace(/[^\w\s]/gi, "")
    .split(/\s+/)
    .filter((w) => w.length > 3);
  const tagWords = Array.from(new Set(words)).slice(0, 3);
  const hashtags = tagWords
    .map((w) => `#${w.charAt(0).toUpperCase() + w.slice(1)}`)
    .join(" ");

  const headline = cleanTopic.length > 60 ? cleanTopic.slice(0, 57) + "…" : cleanTopic;

  // Detect topic category
  const isSale = /sale|discount|off|deal|offer|promo|save|price|free/i.test(lower);
  const isEvent = /event|webinar|workshop|meetup|launch|party|livestream|opening/i.test(lower);
  const isTip = /tip|how to|guide|tutorial|hack|advice|learn|secret/i.test(lower);
  const isQuestion = /\?|poll|thought|opinion|vote|feedback|which/i.test(lower);

  if (isSale) {
    return `🔥 EXCLUSIVE OFFER: ${headline}\n\nWe’ve got something exciting for you! ${cleanTopic}.\n\n⏰ Don't miss out — this is available for a limited time.\n\n👇 Click below or message us directly to claim yours today!\n\n${hashtags} #SpecialOffer #Deals`;
  }

  if (isEvent) {
    return `🎉 SAVE THE DATE: ${headline}!\n\n${cleanTopic}.\n\nGet ready for an incredible experience with our team and community.\n\n👉 Tag a friend who should join us, and drop a comment below if you're coming! 🙌\n\n${hashtags} #Events #Community`;
  }

  if (isTip) {
    return `💡 Pro Tip: ${headline}\n\n${cleanTopic}.\n\nTaking small, consistent steps makes all the difference in achieving top results. Try this out and let us know how it works for you!\n\n💬 Have questions or your own tips to share? Join the conversation in the comments below!\n\n${hashtags} #TipsAndTricks #Growth`;
  }

  if (isQuestion) {
    return `🤔 Quick Question for You:\n\n${cleanTopic}\n\nWe want to hear from our amazing community! Drop your thoughts, experiences, or votes in the comments below 👇❤️\n\n${hashtags} #Discussion #Feedback`;
  }

  if (hasVideo) {
    return `🎬 Watch Now: ${headline}\n\n${cleanTopic}.\n\nCheck out the video above to see all the details in action! Let us know what you think in the comments.\n\n✨ Like and share this with someone who needs to see it!\n\n${hashtags} #VideoUpdate #Trending`;
  }

  return `✨ ${headline}\n\n${cleanTopic}.\n\nWe're always excited to bring you the best updates and keep you informed. Stay tuned for more exciting developments coming soon!\n\n👉 Like, follow, and share your thoughts in the comments below! ❤️\n\n${hashtags || "#Trending #Updates"}`;
}

export const generateCaption = createServerFn({ method: "POST" })
  .validator((input: { topic: string; tone?: string; imageUrl?: string }) => ({
    topic: input.topic.trim().slice(0, 500),
    tone: (input.tone ?? "").trim().slice(0, 50),
    imageUrl: (input.imageUrl ?? "").trim(),
  }))
  .middleware([authMiddleware])
  .handler(async ({ data }) => {
    if (!data.topic && !data.imageUrl) {
      return { ok: false as const, error: "Please enter a topic or concept for the post." };
    }

    const effectiveTopic = data.topic || "an exciting new update from our brand";
    const isVideo =
      data.imageUrl.includes("video") ||
      data.imageUrl.endsWith(".mp4") ||
      data.imageUrl.endsWith(".mov");

    const systemPrompt =
      "You are a world-class social media copywriter for Facebook Pages. " +
      "Write a high-converting, natural, engaging Facebook Page post based directly on the provided topic and key points. " +
      "Requirements:\n" +
      "- Focus closely on the user's specific topic, product, service, or message (do NOT write generic filler).\n" +
      "- Start with an eye-catching hook / headline (with appropriate emojis).\n" +
      "- Provide structured, easy-to-read body paragraphs with line breaks.\n" +
      "- Include a strong, engaging Call-To-Action (CTA) encouraging comments, shares, or visits.\n" +
      "- End with 2-4 highly relevant hashtags matching the topic keywords.\n" +
      "- Do NOT include markdown quotes around the whole post or preamble like 'Here is your post:'. Output only the post copy.";

    const userPrompt = `Topic / Details: ${effectiveTopic}\nRequested Tone: ${data.tone || "engaging, clear, and professional"}${
      data.imageUrl ? `\nMedia Attached: ${isVideo ? "Video" : "Image"}` : ""
    }`;

    const aiText = await callAiProviders(userPrompt, systemPrompt);

    if (aiText) {
      return { ok: true as const, text: aiText };
    }

    // High quality intelligent contextual fallback
    const fallbackText = generateSmartFallback(effectiveTopic, data.tone, isVideo);
    return { ok: true as const, text: fallbackText };
  });

export const clearHistory = createServerFn({ method: "POST" })
  .middleware([authMiddleware])
  .handler(async ({ context }) => {
    const sql = await getSql();
    await sql`
      delete from facebook_posts
      where user_id = ${context.userId} and status not in ('pending', 'posting')
    `;
    return { ok: true as const };
  });

