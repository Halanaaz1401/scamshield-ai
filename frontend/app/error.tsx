"use client";

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div className="flex flex-col items-center justify-center p-6 text-center">
      <p className="text-red-400">{error.message || "An unexpected error occurred"}</p>
      <button
        onClick={() => reset()}
        className="mt-4 rounded px-4 py-2 text-sm bg-zinc-800 text-zinc-200 hover:bg-zinc-700"
      >
        Retry
      </button>
    </div>
  );
}
