import { NextRequest, NextResponse } from "next/server";

export async function POST(req: NextRequest) {
  try {
    const { refresh_token } = await req.json();
    if (!refresh_token || typeof refresh_token !== "string") {
      return NextResponse.json({ error: "Missing refresh_token" }, { status: 400 });
    }
    const res = NextResponse.json({ ok: true });
    res.cookies.set("pg_refresh", refresh_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/api/auth",
      maxAge: 60 * 60 * 24 * 7,
    });
    return res;
  } catch {
    return NextResponse.json({ error: "Invalid request" }, { status: 400 });
  }
}
