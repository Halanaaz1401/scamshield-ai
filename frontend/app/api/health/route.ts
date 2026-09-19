import { NextResponse } from "next/server";

/** Allow full 60-second budget for this route (used as keep-alive ping target). */
export const maxDuration = 60;

const BACKEND_API_URL = process.env.BACKEND_API_URL || "";

export async function GET() {
  if (!BACKEND_API_URL) {
    return NextResponse.json({ status: "degraded", engine: "unconfigured" }, { status: 200 });
  }
  try {
    const backendUrl = `${BACKEND_API_URL}/health`;
    const response = await fetch(backendUrl, {
      method: "GET",
      headers: { Accept: "application/json" },
    });
    const data = await response.json();
    return NextResponse.json(data, { status: response.status });
  } catch {
    return NextResponse.json({ status: "degraded", engine: "local-edge" }, { status: 200 });
  }
}
