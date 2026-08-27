import { useEffect, useMemo, useState } from "react";
import { format, formatDistanceToNow } from "date-fns";
import {
  CalendarClock,
  Check,
  Facebook,
  LoaderCircle,
  PenLine,
  RefreshCw,
  Send,
  Sparkles,
  Unplug,
  X,
} from "lucide-react";
import { UserButton } from "@/lib/auth/gates";
import { useCurrentUser } from "@/lib/auth/use-current-user";
import {
  cancelPost,
  connectDemoPage,
  connectWithToken,
  createPost,
  disconnectFacebook,
  flushNow,
  generateCaption,
  getFacebookAuthUrl,
  getFacebookStatus,
  listPosts,
  retryPost,
  type PageStatus,
  type PostRow,
} from "@/lib/facebook/fns";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Mark } from "@/components/mark";

function localDatetimeValue(d: Date) {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function statusTone(status: string): "ok" | "warn" | "danger" | "info" | "neutral" {
  if (status === "posted") return "ok";
  if (status === "pending" || status === "posting") return "info";
  if (status === "failed") return "danger";
  return "neutral";
}

export function Studio() {
  const user = useCurrentUser();
  const [status, setStatus] = useState<PageStatus | null>(null);
  const [posts, setPosts] = useState<PostRow[] | null>(null);
  const [body, setBody] = useState("");
  const [imageUrl, setImageUrl] = useState("");
  const [when, setWhen] = useState(() => localDatetimeValue(new Date(Date.now() + 5 * 60 * 1000)));
  const [topic, setTopic] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [tokenPageId, setTokenPageId] = useState("");
  const [tokenPageName, setTokenPageName] = useState("");
  const [tokenValue, setTokenValue] = useState("");
  const [showToken, setShowToken] = useState(false);

  async function refresh() {
    try {
      const [s, p] = await Promise.all([getFacebookStatus(), listPosts()]);
      setStatus(s);
      setPosts(p);
    } catch {
      setNotice("Could not load your Page. Sign in again if this persists.");
    }
  }

  useEffect(() => {
    void refresh();
    const id = window.setInterval(() => {
      void listPosts().then(setPosts).catch(() => {});
      void flushNow().catch(() => {});
    }, 15000);
    return () => window.clearInterval(id);
  }, []);

  const queued = useMemo(
    () => (posts ?? []).filter((p) => p.status === "pending" || p.status === "posting"),
    [posts],
  );
  const history = useMemo(
    () => (posts ?? []).filter((p) => p.status !== "pending" && p.status !== "posting"),
    [posts],
  );

  async function onConnectFacebook() {
    setBusy("oauth");
    setNotice(null);
    try {
      const result = await getFacebookAuthUrl({ data: { origin: window.location.origin } });
      if (!result.ok) {
        setNotice(result.error);
        return;
      }
      window.location.assign(result.authUrl);
    } finally {
      setBusy(null);
    }
  }

  async function onDemo() {
    setBusy("demo");
    const result = await connectDemoPage();
    if (result.ok) {
      setNotice("Demo Page connected. Scheduled posts will auto-publish in this app.");
      await refresh();
    }
    setBusy(null);
  }

  async function onToken() {
    setBusy("token");
    const result = await connectWithToken({
      data: { pageId: tokenPageId, pageName: tokenPageName, accessToken: tokenValue },
    });
    if (!result.ok) setNotice(result.error);
    else {
      setNotice(`Connected ${result.pageName}.`);
      setShowToken(false);
      setTokenValue("");
      await refresh();
    }
    setBusy(null);
  }

  async function onDisconnect() {
    setBusy("disconnect");
    await disconnectFacebook();
    await refresh();
    setBusy(null);
  }

  async function onWrite() {
    setBusy("ai");
    setNotice(null);
    const result = await generateCaption({
      data: {
        topic: topic || body || "an upcoming announcement and update",
        tone: "engaging and professional",
        imageUrl,
      },
    });
    if (!result.ok) setNotice(result.error);
    else setBody(result.text);
    setBusy(null);
  }

  async function onSchedule(immediate: boolean) {
    setBusy("save");
    setNotice(null);
    const publishAt = immediate ? new Date().toISOString() : new Date(when).toISOString();
    const result = await createPost({
      data: { body, imageUrl, publishAt },
    });
    if (!result.ok) setNotice(result.error);
    else {
      setBody("");
      setImageUrl("");
      setTopic("");
      setNotice(immediate ? "Sending to Facebook…" : "Queued. PagePress will post it automatically.");
      await refresh();
    }
    setBusy(null);
  }

  return (
    <div className="mx-auto flex min-h-dvh max-w-6xl flex-col px-4 pb-16 pt-5 sm:px-6">
      <header className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2.5 text-accent">
          <Mark className="size-8" />
          <div>
            <p className="font-display text-lg leading-none text-fg">PagePress</p>
            <p className="mt-1 text-xs text-fg-muted">Facebook auto-publisher</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className="hidden text-sm text-fg-muted sm:inline">
            {user?.displayName ?? user?.primaryEmail ?? ""}
          </span>
          <UserButton />
        </div>
      </header>

      <section className="mt-8 grid gap-4 lg:grid-cols-[1.4fr_0.9fr]">
        <div className="rounded-xl border border-border bg-surface p-5 sm:p-7">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h1 className="font-display text-3xl tracking-tight sm:text-4xl">Write once. It posts itself.</h1>
              <p className="mt-2 max-w-xl text-sm leading-relaxed text-fg-muted">
                Connect a single Facebook Page. Queue copy for later. PagePress publishes when the clock hits.
              </p>
            </div>
            <PenLine className="hidden size-5 text-fg-subtle sm:block" />
          </div>

          <div className="mt-6 grid gap-3 sm:grid-cols-[1fr_auto]">
            <Input
              value={topic}
              onChange={(e) => setTopic(e.target.value)}
              placeholder="Topic for the writer — e.g. weekend hours, new drop"
            />
            <Button variant="secondary" onClick={() => void onWrite()} disabled={busy === "ai"}>
              {busy === "ai" ? <LoaderCircle className="size-4 animate-spin" /> : <Sparkles className="size-4" />}
              Generate with AI
            </Button>
          </div>

          <label className="mt-4 block text-xs font-medium text-fg-muted">Post</label>
          <Textarea
            className="mt-1.5"
            value={body}
            onChange={(e) => setBody(e.target.value)}
            placeholder="What should go on the Page?"
            maxLength={5000}
          />
          <div className="mt-1 flex justify-end text-xs tabular-nums text-fg-subtle">{body.length}/5000</div>

          <label className="mt-2 block text-xs font-medium text-fg-muted">Image URL (optional)</label>
          <Input
            className="mt-1.5"
            value={imageUrl}
            onChange={(e) => setImageUrl(e.target.value)}
            placeholder="https://…"
          />

          <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-end">
            <div className="flex-1">
              <label className="block text-xs font-medium text-fg-muted">Publish at</label>
              <Input
                className="mt-1.5"
                type="datetime-local"
                value={when}
                onChange={(e) => setWhen(e.target.value)}
              />
            </div>
            <Button
              variant="secondary"
              onClick={() => void onSchedule(false)}
              disabled={!status?.connected || busy === "save"}
            >
              <CalendarClock className="size-4" />
              Queue
            </Button>
            <Button onClick={() => void onSchedule(true)} disabled={!status?.connected || busy === "save"}>
              {busy === "save" ? <LoaderCircle className="size-4 animate-spin" /> : <Send className="size-4" />}
              Post now
            </Button>
          </div>
          {notice ? <p className="mt-3 text-sm text-accent">{notice}</p> : null}
        </div>

        <aside className="rounded-xl border border-border bg-surface p-5 sm:p-6">
          <div className="flex items-center gap-2 text-fg">
            <Facebook className="size-4" />
            <h2 className="text-sm font-medium">Facebook Page</h2>
          </div>

          {!status ? (
            <p className="mt-4 text-sm text-fg-muted">Checking connection…</p>
          ) : status.connected ? (
            <div className="mt-4 space-y-3">
              <p className="font-display text-2xl leading-tight">{status.pageName}</p>
              <div className="flex flex-wrap gap-2">
                <Badge tone={status.mode === "demo" ? "warn" : "ok"}>
                  {status.mode === "demo" ? "Demo mode" : "Live Page"}
                </Badge>
                {status.pageId ? <Badge>{status.pageId}</Badge> : null}
              </div>
              <p className="text-sm leading-relaxed text-fg-muted">
                {status.mode === "demo"
                  ? "Posts auto-publish inside PagePress so you can try the scheduler. Connect a live Page when Meta Login is configured."
                  : "Scheduled posts go out through the Graph API using this Page’s token."}
              </p>
              <Button variant="ghost" size="sm" onClick={() => void onDisconnect()} disabled={busy === "disconnect"}>
                <Unplug className="size-4" />
                Disconnect
              </Button>
            </div>
          ) : (
            <div className="mt-4 space-y-3">
              <p className="text-sm leading-relaxed text-fg-muted">
                Connect your Facebook Page to auto-publish scheduled posts.
              </p>

              {/* Direct Quick Connection Form */}
              <div className="space-y-2.5 rounded-lg border border-border bg-bg/60 p-3.5">
                <p className="text-xs font-semibold text-fg">Connect Your Page</p>
                <Input
                  placeholder="Page Name (e.g. My Brand)"
                  value={tokenPageName}
                  onChange={(e) => setTokenPageName(e.target.value)}
                />
                <Input
                  placeholder="Page ID or Username (optional)"
                  value={tokenPageId}
                  onChange={(e) => setTokenPageId(e.target.value)}
                />
                <Input
                  placeholder="Page Access Token (optional)"
                  type="password"
                  value={tokenValue}
                  onChange={(e) => setTokenValue(e.target.value)}
                />
                <Button
                  size="sm"
                  className="w-full"
                  onClick={() => {
                    if (!tokenPageName && !tokenPageId) {
                      setNotice("Please enter at least a Page Name or ID.");
                      return;
                    }
                    void onToken();
                  }}
                  disabled={busy === "token"}
                >
                  {busy === "token" ? <LoaderCircle className="size-4 animate-spin mr-1" /> : null}
                  Connect Page
                </Button>
              </div>

              <div className="relative flex items-center justify-center my-2">
                <div className="w-full border-t border-border" />
                <span className="absolute bg-surface px-2 text-xs text-fg-subtle">or</span>
              </div>

              <Button
                variant="secondary"
                className="w-full"
                onClick={() => void onDemo()}
                disabled={busy === "demo"}
              >
                {busy === "demo" ? <LoaderCircle className="size-4 animate-spin mr-1" /> : null}
                Connect Demo Page (Instant)
              </Button>
            </div>
          )}
        </aside>
      </section>

      <section className="mt-8 grid gap-6 lg:grid-cols-2">
        <QueueColumn
          title="Queue"
          empty="Nothing waiting. Queue a post and PagePress will send it."
          posts={queued}
          onCancel={async (id) => {
            await cancelPost({ data: { id } });
            await refresh();
          }}
        />
        <QueueColumn
          title="History"
          empty="Published and cancelled posts land here."
          posts={history}
          onRetry={async (id) => {
            await retryPost({ data: { id } });
            await refresh();
          }}
        />
      </section>
    </div>
  );
}

function QueueColumn({
  title,
  empty,
  posts,
  onCancel,
  onRetry,
}: {
  title: string;
  empty: string;
  posts: PostRow[];
  onCancel?: (id: number) => Promise<void>;
  onRetry?: (id: number) => Promise<void>;
}) {
  return (
    <div>
      <div className="mb-3 flex items-baseline justify-between">
        <h2 className="font-display text-xl">{title}</h2>
        <span className="text-xs tabular-nums text-fg-subtle">{posts.length}</span>
      </div>
      {posts.length === 0 ? (
        <p className="rounded-lg border border-dashed border-border bg-surface/60 px-4 py-8 text-sm text-fg-muted">
          {empty}
        </p>
      ) : (
        <ul className="space-y-2">
          {posts.map((post) => (
            <li key={post.id} className="rounded-lg border border-border bg-surface p-4">
              <div className="flex items-start justify-between gap-3">
                <p className="line-clamp-3 text-sm leading-relaxed">{post.body}</p>
                <Badge tone={statusTone(post.status)}>{post.status}</Badge>
              </div>
              <p className="mt-2 text-xs text-fg-subtle">
                {post.status === "posted" && post.postedAt
                  ? `Posted ${formatDistanceToNow(new Date(post.postedAt), { addSuffix: true })}`
                  : `Scheduled ${format(new Date(post.publishAt), "MMM d, h:mm a")}`}
              </p>
              {post.error ? <p className="mt-1 text-xs text-danger">{post.error}</p> : null}
              <div className="mt-2 flex gap-2">
                {onCancel && (post.status === "pending" || post.status === "failed") ? (
                  <Button variant="ghost" size="sm" onClick={() => void onCancel(post.id)}>
                    <X className="size-3.5" />
                    Cancel
                  </Button>
                ) : null}
                {onRetry && post.status === "failed" ? (
                  <Button variant="ghost" size="sm" onClick={() => void onRetry(post.id)}>
                    <RefreshCw className="size-3.5" />
                    Retry
                  </Button>
                ) : null}
                {post.status === "posted" ? (
                  <span className="inline-flex items-center gap-1 text-xs text-ok">
                    <Check className="size-3.5" />
                    Sent
                  </span>
                ) : null}
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
