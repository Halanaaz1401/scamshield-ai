import { NextResponse } from "next/server";

const BACKEND_API_URL = process.env.BACKEND_API_URL || "http://127.0.0.1:8000";

export async function GET() {
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
