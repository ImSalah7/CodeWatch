import { NextResponse, type NextRequest } from "next/server";

const API_BASE_URL = (process.env.API_BASE_URL ?? "http://localhost:8443").replace(/\/+$/, "");
const API_TOKEN = (process.env.MYSCAN_API_KEY ?? "").trim();

function withToken(pathname: string, search: string): string {
  if (!API_TOKEN) return `${API_BASE_URL}${pathname}${search}`;
  const sep = search ? "&" : "?";
  return `${API_BASE_URL}${pathname}${search}${sep}token=${encodeURIComponent(API_TOKEN)}`;
}

export function proxy(request: NextRequest) {
  const { pathname, search } = request.nextUrl;

  if (pathname === "/health") {
    return NextResponse.rewrite(`${API_BASE_URL}/health`);
  }

  if (pathname.startsWith("/api/")) {
    return NextResponse.rewrite(withToken(pathname, search));
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/api/:path*", "/health"],
};
