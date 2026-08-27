import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { completeFacebookOAuth } from "@/lib/facebook/fns";

export const Route = createFileRoute("/facebook-callback")({
  component: FacebookCallback,
  validateSearch: (search: Record<string, unknown>) => ({
    code: typeof search.code === "string" ? search.code : "",
    state: typeof search.state === "string" ? search.state : "",
    error: typeof search.error === "string" ? search.error : "",
  }),
});

function FacebookCallback() {
  const { code, state, error } = Route.useSearch();
  const navigate = useNavigate();
  const [message, setMessage] = useState("Connecting your Facebook Page…");

  useEffect(() => {
    let cancelled = false;
    async function run() {
      if (error) {
        setMessage("Facebook cancelled the connection.");
        setTimeout(() => navigate({ to: "/" }), 1600);
        return;
      }
      if (!code || !state) {
        setMessage("Missing OAuth code. Returning home.");
        setTimeout(() => navigate({ to: "/" }), 1600);
        return;
      }
      const origin = window.location.origin;
      const result = await completeFacebookOAuth({ data: { code, state, origin } });
      if (cancelled) return;
      if (!result.ok) {
        setMessage(result.error);
        setTimeout(() => navigate({ to: "/" }), 2200);
        return;
      }
      setMessage(`Connected ${result.pageName}.`);
      setTimeout(() => navigate({ to: "/" }), 900);
    }
    void run();
    return () => {
      cancelled = true;
    };
  }, [code, state, error, navigate]);

  return (
    <main className="grid min-h-dvh place-items-center px-6">
      <p className="max-w-md text-center font-display text-xl text-fg">{message}</p>
    </main>
  );
}
