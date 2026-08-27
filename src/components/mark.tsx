export function Mark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden="true">
      <rect width="32" height="32" rx="8" fill="currentColor" />
      <path
        d="M10 22V10h7.2c2.6 0 4.3 1.6 4.3 4 0 1.7-1 3-2.5 3.5L22 22h-2.6l-2.6-4.3H12.4V22H10zm2.4-6.5h4.4c1.3 0 2.1-.7 2.1-1.8s-.8-1.7-2.1-1.7h-4.4v3.5z"
        fill="var(--color-bg)"
      />
    </svg>
  );
}
