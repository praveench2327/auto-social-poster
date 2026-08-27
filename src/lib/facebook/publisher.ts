import { getSql } from "@/lib/db";
import { decryptSecret } from "./crypto";
import {
  FacebookApiError,
  publishFacebookPhoto,
  publishFacebookText,
} from "./graph";

type DuePost = {
  id: number;
  user_id: string;
  body: string;
  image_url: string | null;
};

type PageRow = {
  page_id: string;
  access_token: string;
  mode: string;
};

export async function publishOnePost(post: DuePost): Promise<void> {
  const sql = await getSql();
  const pages = await sql<PageRow>`
    select page_id, access_token, mode from facebook_pages where user_id = ${post.user_id}
  `;
  const page = pages[0];
  if (!page) {
    await sql`
      update facebook_posts
      set status = 'failed', error = 'No Facebook Page connected'
      where id = ${post.id} and user_id = ${post.user_id} and status = 'posting'
    `;
    return;
  }

  try {
    let platformId = "";
    if (page.mode === "demo") {
      platformId = `demo_${post.id}_${Date.now()}`;
    } else {
      const token = decryptSecret(page.access_token);
      if (post.image_url) {
        const result = await publishFacebookPhoto(
          page.page_id,
          token,
          post.body,
          post.image_url,
        );
        platformId = result.post_id || result.id || "";
      } else {
        const result = await publishFacebookText(page.page_id, token, post.body);
        platformId = result.id || "";
      }
      if (!platformId) throw new FacebookApiError("Facebook returned no post id");
    }

    await sql`
      update facebook_posts
      set status = 'posted',
          platform_post_id = ${platformId},
          posted_at = now(),
          error = null
      where id = ${post.id} and user_id = ${post.user_id}
    `;
  } catch (err) {
    console.error("[publishOnePost failed]:", err);
    const message = err instanceof Error ? err.message : "Publish failed";
    await sql`
      update facebook_posts
      set status = 'failed', error = ${message.slice(0, 400)}
      where id = ${post.id} and user_id = ${post.user_id}
    `;
  }
}

export async function flushDueForUser(userId: string): Promise<number> {
  const sql = await getSql();
  const due = await sql<DuePost>`
    update facebook_posts
    set status = 'posting'
    where id in (
      select id from facebook_posts
      where user_id = ${userId}
        and status = 'pending'
        and publish_at <= now()
      order by publish_at asc
      limit 8
    )
    returning id, user_id, body, image_url
  `;
  for (const post of due) {
    await publishOnePost(post);
  }
  return due.length;
}

export async function flushDueAll(): Promise<number> {
  const sql = await getSql();
  const due = await sql<DuePost>`
    update facebook_posts
    set status = 'posting'
    where id in (
      select id from facebook_posts
      where status = 'pending' and publish_at <= now()
      order by publish_at asc
      limit 12
    )
    returning id, user_id, body, image_url
  `;
  for (const post of due) {
    await publishOnePost(post);
  }
  return due.length;
}

const g = globalThis as typeof globalThis & { __pagepressPublisher__?: boolean };

export function ensurePublisherLoop() {
  if (g.__pagepressPublisher__) return;
  g.__pagepressPublisher__ = true;
  setInterval(() => {
    void flushDueAll().catch((err) => {
      console.error("[pagepress] auto-publish", err);
    });
  }, 20_000);
}
