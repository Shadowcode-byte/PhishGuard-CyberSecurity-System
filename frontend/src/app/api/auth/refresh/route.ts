import { NextRequest, NextResponse } from "next/server";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://backend:8000/api/v1" || "https://phishguard-znvu.onrender.com";

export async function POST(req: NextRequest) {
  const refreshToken = req.cookies.get("pg_refresh")?.value;
  if (!refreshToken) {
    return NextResponse.json({ error: "No refresh token" }, { status: 401 });
  }
  try {
    const backendRes = await fetch(`${API_BASE}/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    if (!backendRes.ok) {
      const res = NextResponse.json({ error: "Refresh failed" }, { status: 401 });
      res.cookies.delete("pg_refresh");
      return res;
    }
    const data = await backendRes.json();
    return NextResponse.json(data);
  } catch {
    return NextResponse.json({ error: "Refresh error" }, { status: 500 });
  }
}
