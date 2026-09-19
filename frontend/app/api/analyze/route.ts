import { NextRequest, NextResponse } from "next/server";

/**
 * Allow up to 60 seconds for this serverless function.
 * Render free-tier can take 30-60s to cold-start after 15 min of inactivity.
 * Without this, Vercel's default budget may cut off the request prematurely.
 */
export const maxDuration = 60;

const BACKEND_API_URL = process.env.BACKEND_API_URL || "";

export async function OPTIONS() {
  return new NextResponse(null, {
    status: 200,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type,Authorization",
    },
  });
}

export async function POST(req: NextRequest) {
  if (!BACKEND_API_URL) {
    return NextResponse.json(
      {
        error: {
          code: "BACKEND_UNREACHABLE",
          message:
            "BACKEND_API_URL environment variable is not configured. " +
            "Set it to https://scamshield-ai-o7i4.onrender.com in Vercel → Settings → Environment Variables.",
        },
      },
      { status: 502 }
    );
  }
  try {
    const body = await req.json();
    const backendUrl = `${BACKEND_API_URL}/analyze`;

    // 55-second timeout — gives Render's free-tier cold-start (30-60s) a chance
    // to complete within our 60-second maxDuration budget.
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 55_000);

    let response: Response;
    try {
      response = await fetch(backendUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeoutId);
    }

    const data = await response.json();

    return NextResponse.json(data, {
      status: response.status,
      headers: {
        "Access-Control-Allow-Origin": "*",
      },
    });
  } catch (error: unknown) {
    const isTimeout =
      error instanceof Error &&
      (error.name === "AbortError" || error.message.includes("aborted"));
    const errorMessage = isTimeout
      ? "ScamShield threat engine is warming up (cold start). Please retry in 15 seconds."
      : error instanceof Error
      ? error.message
      : "Internal Server Error";
    return NextResponse.json(
      {
        error: {
          code: isTimeout ? "BACKEND_COLD_START" : "BACKEND_UNREACHABLE",
          message: `Failed to communicate with ScamShield threat engine: ${errorMessage}`,
        },
      },
      { status: 502 }
    );
  }
}
