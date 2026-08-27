import { useState } from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { authClient, GROK_PROVIDERS, authEnabled, signIn } from "@/lib/auth/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Loader2, Mail, Lock, User, AlertCircle } from "lucide-react";

export const Route = createFileRoute("/login")({ component: Login });

function Login() {
  const navigate = useNavigate();
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!email || !password) {
      setError("Please fill in all required fields.");
      return;
    }

    if (mode === "signup") {
      if (!name.trim()) {
        setError("Please enter your name.");
        return;
      }
      if (password !== confirmPassword) {
        setError("Passwords do not match.");
        return;
      }
      if (password.length < 6) {
        setError("Password must be at least 6 characters long.");
        return;
      }
    }

    setIsLoading(true);

    try {
      if (mode === "signup") {
        const { error: signUpError } = await authClient.signUp.email({
          name: name.trim(),
          email: email.trim(),
          password,
          callbackURL: "/",
        });

        if (signUpError) {
          setError(signUpError.message || "Failed to create account.");
          return;
        }

        navigate({ to: "/" });
      } else {
        const { error: signInError } = await authClient.signIn.email({
          email: email.trim(),
          password,
          callbackURL: "/",
        });

        if (signInError) {
          setError(signInError.message || "Invalid email or password.");
          return;
        }

        navigate({ to: "/" });
      }
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError("An unexpected error occurred. Please try again.");
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <main className="grid min-h-dvh place-items-center px-4 py-8 bg-bg">
      <div className="w-full max-w-md rounded-2xl border border-border bg-surface p-7 sm:p-8 shadow-[0_20px_50px_-28px_rgba(26,24,20,0.35)]">
        <div className="text-center">
          <p className="text-xs font-semibold tracking-[0.2em] text-accent uppercase">PagePress</p>
          <h1 className="mt-2 font-display text-3xl font-medium tracking-tight text-fg">
            {mode === "signin" ? "Welcome back" : "Create an account"}
          </h1>
          <p className="mt-1.5 text-sm leading-relaxed text-fg-muted">
            {mode === "signin"
              ? "Sign in to manage and schedule your Facebook posts"
              : "Sign up with your details to start publishing"}
          </p>
        </div>

        {/* Mode Toggle */}
        <div className="mt-6 grid grid-cols-2 gap-1 rounded-lg border border-border bg-bg/50 p-1">
          <button
            type="button"
            onClick={() => {
              setMode("signin");
              setError(null);
            }}
            className={`rounded-md py-2 text-sm font-medium transition-all ${
              mode === "signin"
                ? "bg-surface text-fg shadow-sm"
                : "text-fg-muted hover:text-fg"
            }`}
          >
            Sign In
          </button>
          <button
            type="button"
            onClick={() => {
              setMode("signup");
              setError(null);
            }}
            className={`rounded-md py-2 text-sm font-medium transition-all ${
              mode === "signup"
                ? "bg-surface text-fg shadow-sm"
                : "text-fg-muted hover:text-fg"
            }`}
          >
            Sign Up
          </button>
        </div>

        {error && (
          <div className="mt-4 flex items-center gap-2 rounded-lg border border-danger/20 bg-danger/10 px-3.5 py-2.5 text-xs text-danger">
            <AlertCircle className="size-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="mt-5 space-y-3.5">
          {mode === "signup" && (
            <div>
              <label className="block text-xs font-medium text-fg-muted mb-1">Full Name</label>
              <div className="relative">
                <Input
                  type="text"
                  placeholder="Jane Doe"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="pl-9"
                  disabled={isLoading}
                  required
                />
                <User className="absolute left-3 top-3.5 size-4 text-fg-subtle" />
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs font-medium text-fg-muted mb-1">Email Address</label>
            <div className="relative">
              <Input
                type="email"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="pl-9"
                disabled={isLoading}
                required
              />
              <Mail className="absolute left-3 top-3.5 size-4 text-fg-subtle" />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-fg-muted mb-1">Password</label>
            <div className="relative">
              <Input
                type="password"
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="pl-9"
                disabled={isLoading}
                required
              />
              <Lock className="absolute left-3 top-3.5 size-4 text-fg-subtle" />
            </div>
          </div>

          {mode === "signup" && (
            <div>
              <label className="block text-xs font-medium text-fg-muted mb-1">Confirm Password</label>
              <div className="relative">
                <Input
                  type="password"
                  placeholder="••••••••"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="pl-9"
                  disabled={isLoading}
                  required
                />
                <Lock className="absolute left-3 top-3.5 size-4 text-fg-subtle" />
              </div>
            </div>
          )}

          <Button type="submit" className="w-full mt-2" disabled={isLoading}>
            {isLoading && <Loader2 className="size-4 animate-spin mr-2" />}
            {mode === "signin" ? "Sign In" : "Create Account"}
          </Button>
        </form>

        <div className="mt-6">
          <div className="relative flex items-center justify-center">
            <div className="w-full border-t border-border" />
            <span className="absolute bg-surface px-2.5 text-xs text-fg-subtle uppercase">
              Or continue with
            </span>
          </div>

          <div className="mt-4">
            <Button
              variant="secondary"
              className="w-full flex items-center justify-center gap-2 font-medium"
              disabled={isLoading}
              onClick={async () => {
                setIsLoading(true);
                setError(null);
                try {
                  const res = await authClient.signIn.social({
                    provider: "google",
                    callbackURL: "/",
                  });
                  if (res?.error) {
                    setError(res.error.message || "Failed to initiate Google sign in.");
                  }
                } catch (err: unknown) {
                  if (err instanceof Error) setError(err.message);
                  else setError("Google sign-in error occurred.");
                } finally {
                  setIsLoading(false);
                }
              }}
            >
              <svg className="size-4" viewBox="0 0 24 24">
                <path
                  fill="#4285F4"
                  d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                />
                <path
                  fill="#34A853"
                  d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                />
                <path
                  fill="#FBBC05"
                  d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                />
                <path
                  fill="#EA4335"
                  d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                />
              </svg>
              Continue with Google
            </Button>
          </div>
        </div>

        <div className="mt-6 text-center text-xs text-fg-muted">
          {mode === "signin" ? (
            <p>
              Don't have an account?{" "}
              <button
                type="button"
                onClick={() => {
                  setMode("signup");
                  setError(null);
                }}
                className="font-medium text-accent hover:underline"
              >
                Sign up
              </button>
            </p>
          ) : (
            <p>
              Already have an account?{" "}
              <button
                type="button"
                onClick={() => {
                  setMode("signin");
                  setError(null);
                }}
                className="font-medium text-accent hover:underline"
              >
                Sign in
              </button>
            </p>
          )}
        </div>
      </div>
    </main>
  );
}

