// middleware.js — Vercel Edge Middleware
// Protects /dashboard.html via HTTP Basic Authentication.
// Runs on Vercel's Edge Runtime (no Node.js APIs).

export const config = {
  matcher: '/dashboard.html',
};

// Master credentials — move these to Vercel Environment Variables in production:
// ADMIN_USERNAME and ADMIN_PASSWORD set via the Vercel project dashboard.
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'AuraStudioPassword2026';

const UNAUTHORIZED = new Response('Access Denied — Authentication Required.', {
  status: 401,
  headers: {
    'WWW-Authenticate': 'Basic realm="AURA Secure Admin Studio"',
    'Content-Type': 'text/plain',
  },
});

export default function middleware(request) {
  const authHeader = request.headers.get('Authorization');

  // Reject immediately if no Authorization header is present
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return UNAUTHORIZED;
  }

  // Decode the Base64-encoded "username:password" token
  const base64Token = authHeader.slice('Basic '.length);
  const decoded = atob(base64Token);
  const colonIndex = decoded.indexOf(':');

  // Guard against malformed credentials (no colon separator)
  if (colonIndex === -1) {
    return UNAUTHORIZED;
  }

  const username = decoded.slice(0, colonIndex);
  const password = decoded.slice(colonIndex + 1);

  // Validate against master credentials
  if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD) {
    return UNAUTHORIZED;
  }

  // Credentials verified — allow the request to pass through
  return; // Returning undefined signals Next.js/Vercel to continue normally
}
