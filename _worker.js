// _worker.js

// Docker镜像仓库主机地址（默认）
let hub_host = 'registry-1.docker.io';
// Docker认证服务器地址
const auth_url = 'https://auth.docker.io';

let 屏蔽爬虫UA = ['netcraft'];

/** @type {ResponseInit} 用于 CORS 预检响应 */
const PREFLIGHT_INIT = {
  status: 204,
  headers: {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET,POST,PUT,PATCH,TRACE,DELETE,HEAD,OPTIONS',
    'access-control-allow-headers': '*',
    'access-control-max-age': '1728000'
  }
};

/** 构造响应 */
function makeRes(body, status = 200, headers = {}) {
  headers['access-control-allow-origin'] = '*';
  return new Response(body, { status, headers });
}

/** 构造新的URL对象（保护 try/catch） */
function newUrl(urlStr, base) {
  try {
    console.log(`Constructing new URL object with path ${urlStr} and base ${base}`);
    return new URL(urlStr, base);
  } catch (err) {
    console.error('newUrl parse error:', err);
    return null;
  }
}

/** ngnix 伪装页 */
async function nginx() {
  const text = `
  <!DOCTYPE html>
  <html>
  <head><title>Welcome to nginx!</title>
  <style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif}</style>
  </head>
  <body>
  <h1>Welcome to nginx!</h1>
  <p>If you see this page, the nginx web server is successfully installed and working.</p>
  <p><em>Thank you for using nginx.</em></p>
  </body>
  </html>
  `;
  return text;
}

/** 搜索界面 HTML */
async function searchInterface() {
  const html = `...`; // 这里为了简洁略去长 HTML，实际代码中可保留你原来的完整 searchInterface() 字符串
  return html;
}

/** 从 request 获取 header 的小工具 */
function getReqHeaderFromReq(request, key) {
  return request.headers.get(key);
}

/** 把 request 转换成 fetch init，确保 cf 在 cf 字段 */
function makeFetchInitFromRequest(request, extraHeaders = {}, cfOptions = {}) {
  const newHeaders = new Headers();
  for (const [k, v] of request.headers) newHeaders.set(k, v);
  for (const [k, v] of Object.entries(extraHeaders || {})) newHeaders.set(k, v);

  return {
    method: request.method,
    headers: newHeaders,
    body: (['GET', 'HEAD'].includes(request.method)) ? undefined : request.body,
    redirect: 'follow',
    cf: cfOptions
  };
}

/** 更稳健的 ADD：把环境变量转换为数组 */
async function ADD(envadd) {
  if (!envadd) return [];
  // 用 \s 匹配所有空白，去掉双引号单引号
  var addtext = envadd.replace(/[\s"']+/g, ',').replace(/,+/g, ',');
  if (addtext.charAt(0) == ',') addtext = addtext.slice(1);
  if (addtext.charAt(addtext.length - 1) == ',') addtext = addtext.slice(0, addtext.length - 1);
  if (!addtext) return [];
  const add = addtext.split(',');
  return add;
}

/** 主导出对象 */
export default {
  async fetch(request, env, ctx) {
    const getReqHeader = (k) => request.headers.get(k);
    let url = new URL(request.url);
    const userAgentHeader = request.headers.get('User-Agent');
    const userAgent = userAgentHeader ? userAgentHeader.toLowerCase() : "null";

    // 动态合并 UA 黑名单（如果 env.UA 存在）
    if (env.UA) {
      try {
        const addList = await ADD(env.UA);
        屏蔽爬虫UA = 屏蔽爬虫UA.concat(addList);
      } catch (e) {
        console.error('ADD(env.UA) parse error', e);
      }
    }

    // 解析 ns / hubhost 等
    const ns = url.searchParams.get('ns');
    const hostname = url.searchParams.get('hubhost') || url.hostname;
    const hostTop = hostname.split('.')[0];

    // 根据主机名选择对应的上游地址（routeByHosts 保留原逻辑）
    function routeByHosts(host) {
      const routes = {
        "quay": "quay.io",
        "gcr": "gcr.io",
        "k8s-gcr": "k8s.gcr.io",
        "k8s": "registry.k8s.io",
        "ghcr": "ghcr.io",
        "cloudsmith": "docker.cloudsmith.io",
        "nvcr": "nvcr.io",
        "test": "registry-1.docker.io",
      };
      if (host in routes) return [routes[host], false];
      else return [hub_host, true];
    }

    let checkHost;
    if (ns) {
      if (ns === 'docker.io') {
        hub_host = 'registry-1.docker.io';
      } else {
        hub_host = ns;
      }
    } else {
      checkHost = routeByHosts(hostTop);
      hub_host = checkHost[0];
    }

    const fakePage = checkHost ? checkHost[1] : false;
    console.log(`域名头部: ${hostTop} 反代地址: ${hub_host} searchInterface: ${fakePage}`);

    // 改变目标 hostname
    url.hostname = hub_host;

    // 简单的 UA 屏蔽（返回 nginx 伪装页）
    if (屏蔽爬虫UA.some(fxxk => userAgent.includes(fxxk)) && 屏蔽爬虫UA.length > 0) {
      return new Response(await nginx(), {
        headers: { 'Content-Type': 'text/html; charset=UTF-8' }
      });
    }

    // 处理浏览器访问 / search 接口等
    const hubParams = ['/v1/search', '/v1/repositories'];
    if ( (userAgent && userAgent.includes('mozilla')) || hubParams.some(param => url.pathname.includes(param)) ) {
      if (url.pathname === '/') {
        if (env.URL302) {
          return Response.redirect(env.URL302, 302);
        } else if (env.URL) {
          if (env.URL.toLowerCase() === 'nginx') {
            return new Response(await nginx(), { headers: { 'Content-Type': 'text/html; charset=UTF-8' }});
          } else {
            // 将请求直接转发到 env.URL
            // 注意：这里使用 fetch(env.URL, init) 而非 fetch(new Request(...), init) 以避免覆盖歧义
            const forwardInit = makeFetchInitFromRequest(request, { Host: new URL(env.URL).hostname }, { cacheTtl: 60 });
            return fetch(env.URL, forwardInit);
          }
        } else {
          if (fakePage) {
            return new Response(await searchInterface(), {
              headers: { 'Content-Type': 'text/html; charset=UTF-8' }
            });
          }
        }
      } else {
        // /v1/ 路径特殊处理
        if (url.pathname.startsWith('/v1/')) {
          url.hostname = 'index.docker.io';
        } else if (fakePage) {
          url.hostname = 'hub.docker.com';
        }

        // 特殊处理 q=library/xxx
        if (url.searchParams.get('q')?.includes('library/') && url.searchParams.get('q') != 'library/') {
          const search = url.searchParams.get('q');
          url.searchParams.set('q', search.replace('library/', ''));
        }

        // 直接代理并返回（构造明确 init）
        const init = makeFetchInitFromRequest(request, { Host: url.hostname }, { cacheTtl: 60 });
        return fetch(url.href, init);
      }
    }

    // 对特定编码的处理（谨慎替换，优先解码或仅针对明确参数）
    if (!/%2F/.test(url.search) && /%3A/.test(url.toString())) {
      // 尝试解码并在 q 参数中处理，避免对整串 URL 做复杂 lookahead 替换
      try {
        const decoded = decodeURIComponent(url.toString());
        // 如果 q 参数存在且包含 'library:' 风格的编码，修正为 library/
        if (decoded.includes('library:') && url.searchParams.get('q')) {
          const q = decodeURIComponent(url.searchParams.get('q'));
          if (q.includes('library/')) {
            // 不作改动
          } else if (q.includes('library:')) {
            url.searchParams.set('q', q.replace('library:', 'library/'));
          }
        }
      } catch (e) {
        // 若 decode 出错则忽略（不阻断主流程）
        console.warn('decodeURIComponent error for url', e);
      }
    }

    // token 请求（直接转发到 auth.docker.io）
    if (url.pathname.includes('/token')) {
      const token_parameter = {
        headers: {
          'Host': 'auth.docker.io',
          'User-Agent': getReqHeader("User-Agent") || '',
          'Accept': getReqHeader("Accept") || '*/*',
          'Accept-Language': getReqHeader("Accept-Language") || '',
          'Accept-Encoding': getReqHeader("Accept-Encoding") || '',
          'Connection': 'keep-alive',
          'Cache-Control': 'max-age=0'
        },
        cf: { cacheTtl: 60 }
      };
      const token_url = auth_url + url.pathname + url.search;
      return fetch(token_url, token_parameter);
    }

    // 修改 /v2/ 路径：确保当目标是 registry-1.docker.io 且缺失 /v2/library 前缀时自动插入
    if (hub_host === 'registry-1.docker.io' && url.pathname.startsWith('/v2/') && !url.pathname.startsWith('/v2/library/')) {
      // 更宽松地插入 library
      url.pathname = '/v2/library/' + url.pathname.slice('/v2/'.length);
      console.log(`modified_url: ${url.pathname}`);
    }

    // 对 /v2/.../manifests | blobs | tags 等需要先拿 token 的请求进行 token 流程
    if (
      url.pathname.startsWith('/v2/') &&
      (
        url.pathname.includes('/manifests/') ||
        url.pathname.includes('/blobs/') ||
        url.pathname.includes('/tags/') ||
        url.pathname.endsWith('/tags/list')
      )
    ) {
      // 提取 repo 名
      let repo = '';
      const v2Match = url.pathname.match(/^\/v2\/(.+?)(?:\/(manifests|blobs|tags)\/|\/(tags)\/?$)/);
      if (v2Match) {
        repo = v2Match[1];
      } else {
        const v2Match2 = url.pathname.match(/^\/v2\/(.+?)(\/|$)/);
        if (v2Match2) repo = v2Match2[1];
      }

      if (repo) {
        try {
          const tokenUrl = `${auth_url}/token?service=registry.docker.io&scope=repository:${repo}:pull`;
          const tokenRes = await fetch(tokenUrl, {
            headers: {
              'User-Agent': getReqHeader("User-Agent") || 'cf-worker',
              'Accept': getReqHeader("Accept") || '*/*'
            },
            cf: { cacheTtl: 60 }
          });

          if (!tokenRes.ok) {
            console.error('token fetch failed status:', tokenRes.status);
            // 回退直接代理（上游会给出 Www-Authenticate）
            const fallbackInit = makeFetchInitFromRequest(request, { Host: hub_host }, { cacheTtl: 60 });
            return fetch(url.href, fallbackInit);
          }

          const tokenData = await tokenRes.json().catch(e => {
            console.error('tokenRes.json() error', e);
            return {};
          });

          // 兼容 token 或 access_token 字段
          const token = tokenData.token || tokenData.access_token;
          if (!token) {
            console.error('no token found in token response', tokenData);
            const fallbackInit = makeFetchInitFromRequest(request, { Host: hub_host }, { cacheTtl: 60 });
            return fetch(url.href, fallbackInit);
          }

          // 用 token 发起真实请求
          const paramHeaders = {
            'Host': hub_host,
            'User-Agent': getReqHeader("User-Agent") || '',
            'Accept': getReqHeader("Accept") || '',
            'Accept-Language': getReqHeader("Accept-Language") || '',
            'Accept-Encoding': getReqHeader("Accept-Encoding") || '',
            'Connection': 'keep-alive',
            'Cache-Control': 'max-age=0',
            'Authorization': `Bearer ${token}`
          };
          if (request.headers.has("X-Amz-Content-Sha256")) {
            paramHeaders['X-Amz-Content-Sha256'] = getReqHeader("X-Amz-Content-Sha256");
          }

          const fetchInit = makeFetchInitFromRequest(request, paramHeaders, { cacheTtl: 3600 });
          const original_response = await fetch(url.href, fetchInit);
          // 直接透传 body stream（若需要检查文本，可 .text()）
          const response_headers = original_response.headers;
          const new_response_headers = new Headers(response_headers);

          // 替换 Www-Authenticate 中的 auth.docker.io => worker 域，尽量只替换 host
          if (new_response_headers.get("Www-Authenticate")) {
            const authHeader = new_response_headers.get("Www-Authenticate");
            try {
              const workerHostname = new URL(request.url).hostname;
              new_response_headers.set("Www-Authenticate", authHeader.replace(/auth\.docker\.io/g, workerHostname));
            } catch (e) {
              console.warn('replace Www-Authenticate failed', e);
            }
          }

          if (new_response_headers.get("Location")) {
            const location = new_response_headers.get("Location");
            console.info(`Found redirection location, redirecting to ${location}`);
            return httpHandler(request, location, hub_host);
          }

          return new Response(original_response.body, {
            status: original_response.status,
            headers: new_response_headers
          });

        } catch (e) {
          console.error('token handling error', e);
          const fallbackInit = makeFetchInitFromRequest(request, { Host: hub_host }, { cacheTtl: 60 });
          return fetch(url.href, fallbackInit);
        }
      }
    }

    // 构造通用请求参数（最终走这一条）
    const parameterHeaders = {
      'Host': hub_host,
      'User-Agent': getReqHeader("User-Agent") || '',
      'Accept': getReqHeader("Accept") || '*/*',
      'Accept-Language': getReqHeader("Accept-Language") || '',
      'Accept-Encoding': getReqHeader("Accept-Encoding") || '',
      'Connection': 'keep-alive',
      'Cache-Control': 'max-age=0'
    };
    if (request.headers.has("Authorization")) parameterHeaders.Authorization = getReqHeader("Authorization");
    if (request.headers.has("X-Amz-Content-Sha256")) parameterHeaders['X-Amz-Content-Sha256'] = getReqHeader("X-Amz-Content-Sha256");

    const init = makeFetchInitFromRequest(request, parameterHeaders, { cacheTtl: 3600 });
    const original_response = await fetch(url.href, init);
    const response_headers = original_response.headers;
    const new_response_headers = new Headers(response_headers);
    const status = original_response.status;

    // 替换 Www-Authenticate 域名为 worker 域（仅替换 host）
    if (new_response_headers.get("Www-Authenticate")) {
      const authHeader = new_response_headers.get("Www-Authenticate");
      try {
        const workerHostname = new URL(request.url).hostname;
        new_response_headers.set("Www-Authenticate", authHeader.replace(/auth\.docker\.io/g, workerHostname));
      } catch (e) {
        console.warn('replace Www-Authenticate failed', e);
      }
    }

    // 处理 Location 重定向
    if (new_response_headers.get("Location")) {
      const location = new_response_headers.get("Location");
      console.info(`Found redirection location, redirecting to ${location}`);
      return httpHandler(request, location, hub_host);
    }

    // 设置返回头，与 CORS
    new_response_headers.set('access-control-expose-headers', '*');
    new_response_headers.set('access-control-allow-origin', '*');
    // 可调整缓存策略
    new_response_headers.set('Cache-Control', 'max-age=1500');

    // 删除可能会影响前端的安全头（按需）
    new_response_headers.delete('content-security-policy');
    new_response_headers.delete('content-security-policy-report-only');
    new_response_headers.delete('clear-site-data');

    // 直接透传 body 流（避免重复消费）
    return new Response(original_response.body, {
      status,
      headers: new_response_headers
    });
  } // end fetch
}; // end export

/** 
 * 处理 HTTP 请求（例如 Location 重定向时调用）
 * @param {Request} req
 * @param {string} pathname
 * @param {string} baseHost
 */
function httpHandler(req, pathname, baseHost) {
  const reqHdrRaw = req.headers;

  // 处理预检
  if (req.method === 'OPTIONS' && reqHdrRaw.has('access-control-request-headers')) {
    return new Response(null, PREFLIGHT_INIT);
  }

  const reqHdrNew = new Headers(reqHdrRaw);
  // 删除 Authorization（S3 特殊情况）
  reqHdrNew.delete("Authorization");

  const urlObj = newUrl(pathname, 'https://' + baseHost);
  if (!urlObj) {
    return makeRes('Bad URL', 400, { 'Content-Type': 'text/plain' });
  }

  const reqInit = {
    method: req.method,
    headers: reqHdrNew,
    redirect: 'follow',
    body: (['GET', 'HEAD'].includes(req.method) ? undefined : req.body),
    cf: { cacheTtl: 60 }
  };
  return proxy(urlObj, reqInit, '');
}

/** 代理实现：fetch 上游并清理头 */
async function proxy(urlObj, reqInit, rawLen) {
  const res = await fetch(urlObj.href, reqInit);
  const resHdrOld = res.headers;
  const resHdrNew = new Headers(resHdrOld);

  if (rawLen) {
    const newLen = resHdrOld.get('content-length') || '';
    if (rawLen !== newLen) {
      return makeRes(res.body, 400, {
        '--error': `bad len: ${newLen}, except: ${rawLen}`,
        'access-control-expose-headers': '--error',
      });
    }
  }

  const status = res.status;
  resHdrNew.set('access-control-expose-headers', '*');
  resHdrNew.set('access-control-allow-origin', '*');
  resHdrNew.set('Cache-Control', 'max-age=1500');
  resHdrNew.delete('content-security-policy');
  resHdrNew.delete('content-security-policy-report-only');
  resHdrNew.delete('clear-site-data');

  return new Response(res.body, {
    status,
    headers: resHdrNew
  });
}
