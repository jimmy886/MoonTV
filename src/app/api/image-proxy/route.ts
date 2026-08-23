import { NextResponse } from 'next/server';

// 通用 CORS/反代 路由（edge）。用于把豆瓣等被墙/跨域的站点抓回来。
// 用法： https://<你的域名>/api/proxy?url=<目标地址URL编码>
export const runtime = 'edge';

function isBlockedHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  if (
    h === 'localhost' ||
    h.endsWith('.local') ||
    h === '127.0.0.1' ||
    h === '::1' ||
    h === '0.0.0.0'
  ) {
    return true;
  }
  // 私有网段 SSRF 防护
  const ipv4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const [a, b] = [Number(ipv4[1]), Number(ipv4[2])];
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
  }
  if (h.startsWith('fc') || h.startsWith('fd') || h.includes(':')) {
    if (h !== '::1') return false; // 其他 IPv6 放行
  }
  return false;
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const target = searchParams.get('url');

  if (!target) {
    return NextResponse.json({ error: 'Missing url parameter' }, { status: 400 });
  }

  let targetUrl: URL;
  try {
    targetUrl = new URL(target);
  } catch {
    return NextResponse.json({ error: 'Invalid url' }, { status: 400 });
  }

  if (targetUrl.protocol !== 'http:' && targetUrl.protocol !== 'https:') {
    return NextResponse.json({ error: 'Unsupported protocol' }, { status: 400 });
  }

  if (isBlockedHost(targetUrl.hostname)) {
    return NextResponse.json({ error: 'Blocked host' }, { status: 403 });
  }

  try {
    const upstream = await fetch(targetUrl.toString(), {
      headers: {
        'User-Agent':
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        Referer: targetUrl.origin + '/',
        Accept: '*/*',
      },
      redirect: 'follow',
    });

    const headers = new Headers();
    const contentType = upstream.headers.get('content-type');
    if (contentType) headers.set('Content-Type', contentType);
    headers.set('Cache-Control', 'public, max-age=3600, s-maxage=3600');
    headers.set('Access-Control-Allow-Origin', '*');
    headers.set('Vercel-CDN-Cache-Control', 'public, s-maxage=3600');

    if (!upstream.body) {
      return NextResponse.json(
        { error: 'Empty response from upstream' },
        { status: 502 }
      );
    }

    return new Response(upstream.body, {
      status: upstream.status,
      headers,
    });
  } catch (error) {
    return NextResponse.json(
      { error: 'Upstream fetch failed', details: (error as Error).message },
      { status: 502 }
    );
  }
}
