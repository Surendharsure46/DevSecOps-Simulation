import type { Deployment, Files, Finding, ImageInfo } from './types';
import { helmetEnabled, moduleLoadError, parameterised, poweredByHidden, routeBlock, sessionCookie, sqlInjectable, usesEval } from './appmodel';
import { parseYamlDocs } from './yaml';
import { dockerRun } from './container';

// Staging cluster: Kyverno admission, rollouts, the running ShopFlow app (HTTP) and OWASP ZAP.

export const STAGING_HOST = 'staging.shopflow.local';

const ORDERS = [
  { id: 5001, customer_id: 'C-1001', total: 129.9, status: 'shipped' },
  { id: 5002, customer_id: 'C-1001', total: 18.5, status: 'delivered' },
  { id: 5003, customer_id: 'C-2044', total: 245.0, status: 'processing' },
];

export interface RunningApp {
  files: Files;
  installed: Record<string, string>;
}

export interface HttpResponse {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
}

function headersFor(app: RunningApp): Record<string, string> {
  const h: Record<string, string> = {};
  if (!poweredByHidden(app.files, app.installed)) h['X-Powered-By'] = 'Express';
  if (helmetEnabled(app.files, app.installed))
    Object.assign(h, {
      'Content-Security-Policy': "default-src 'self';base-uri 'self';frame-ancestors 'self';object-src 'none';script-src 'self';upgrade-insecure-requests",
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'SAMEORIGIN',
      'Referrer-Policy': 'no-referrer',
    });
  const c = sessionCookie(app.files, app.installed);
  if (c.present) h['Set-Cookie'] = `connect.sid=s%3AqX1b9VtQ2k.Hk3s8f; Path=/${c.httpOnly ? '; HttpOnly' : ''}${c.secure ? '; Secure' : ''}${c.sameSite ? '; SameSite=' + c.sameSite : ''}`;
  h['Content-Type'] = 'application/json; charset=utf-8';
  return h;
}

export function httpRequest(app: RunningApp, method: string, rawPath: string, body: string | null): HttpResponse {
  const url = new URL(rawPath, 'https://x');
  const path = url.pathname;
  const headers = headersFor(app);
  const reply = (b: unknown, status = 200, statusText = 'OK'): HttpResponse => ({ status, statusText, headers, body: JSON.stringify(b) });
  const orders = app.files['src/routes/orders.js'];
  if (method === 'GET' && (path === '/' || path === '/health')) return reply({ status: 'ok', service: 'shopflow-api' });
  if (method === 'GET' && path === '/api/orders') {
    const blk = routeBlock(orders, 'get', '/orders');
    if (!blk) return reply({ error: 'not found' }, 404, 'Not Found');
    const c = url.searchParams.get('customer') ?? '';
    if (sqlInjectable(blk) && /['"\\]/.test(c)) return reply({ error: 'syntax error at or near "' + c.slice(0, 12) + '"' }, 500, 'Internal Server Error');
    return reply(ORDERS.filter((o) => o.customer_id === c));
  }
  const rm = /^\/api\/orders\/([^/]+)\/receipt$/.exec(path);
  if (method === 'GET' && rm) {
    const blk = routeBlock(orders, 'get', '/orders/:id/receipt');
    if (!blk) return reply({ error: 'not found' }, 404, 'Not Found');
    if (parameterised(blk) && !/^\d+$/.test(rm[1])) return reply({ error: 'invalid input syntax for type integer' }, 400, 'Bad Request');
    const o = ORDERS.find((x) => String(x.id) === rm[1]);
    return o ? reply({ order_id: o.id, total: o.total }) : reply({ error: 'not found' }, 404, 'Not Found');
  }
  if (method === 'POST' && path === '/api/orders/discount') {
    const blk = routeBlock(orders, 'post', '/orders/discount');
    if (!blk) return reply({ error: 'not found' }, 404, 'Not Found');
    let input: Record<string, unknown> = {};
    try {
      input = JSON.parse(body ?? '{}') as Record<string, unknown>;
    } catch {
      return reply({ error: 'Unexpected token in JSON' }, 400, 'Bad Request');
    }
    if (usesEval(blk)) return reply({ total: 90, warning: 'expression evaluated server-side' });
    const p = Number(input.percent);
    if (!Number.isFinite(p) || p < 0 || p > 100) return reply({ error: 'percent must be a number between 0 and 100' }, 400, 'Bad Request');
    return reply({ total: 100 - p });
  }
  return reply({ error: 'not found' }, 404, 'Not Found');
}

// ---------- ZAP ----------

export interface ZapAlert {
  id: number;
  name: string;
  risk: 'High' | 'Medium' | 'Low';
  urls: string[];
}

export function zapAlerts(app: RunningApp, base: string, active: boolean): ZapAlert[] {
  const a: ZapAlert[] = [];
  const pages = [`${base}/`, `${base}/health`, `${base}/api/orders?customer=C-1001`];
  if (!helmetEnabled(app.files, app.installed)) {
    a.push({ id: 10038, name: 'Content Security Policy (CSP) Header Not Set', risk: 'Medium', urls: pages });
    a.push({ id: 10020, name: 'Missing Anti-clickjacking Header', risk: 'Medium', urls: pages });
    a.push({ id: 10021, name: 'X-Content-Type-Options Header Missing', risk: 'Low', urls: pages });
    if (base.startsWith('https')) a.push({ id: 10035, name: 'Strict-Transport-Security Header Not Set', risk: 'Low', urls: pages });
  }
  if (!poweredByHidden(app.files, app.installed)) a.push({ id: 10037, name: 'Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s)', risk: 'Low', urls: pages });
  const c = sessionCookie(app.files, app.installed);
  if (c.present && !c.httpOnly) a.push({ id: 10010, name: 'Cookie No HttpOnly Flag', risk: 'Low', urls: [`${base}/`] });
  if (c.present && !c.secure) a.push({ id: 10011, name: 'Cookie Without Secure Flag', risk: 'Low', urls: [`${base}/`] });
  if (c.present && !c.sameSite) a.push({ id: 10054, name: 'Cookie without SameSite Attribute', risk: 'Low', urls: [`${base}/`] });
  if (active) {
    const orders = app.files['src/routes/orders.js'];
    const sq: string[] = [];
    if (sqlInjectable(routeBlock(orders, 'get', '/orders'))) sq.push(`${base}/api/orders?customer=C-1001`);
    if (sqlInjectable(routeBlock(orders, 'get', '/orders/:id/receipt'))) sq.push(`${base}/api/orders/5001/receipt`);
    if (sq.length) a.push({ id: 40018, name: 'SQL Injection', risk: 'High', urls: sq });
    if (usesEval(routeBlock(orders, 'post', '/orders/discount'))) a.push({ id: 90019, name: 'Server Side Code Injection', risk: 'High', urls: [`${base}/api/orders/discount`] });
  }
  return a;
}

const ZAP_FIX: Record<number, string> = {
  10038: 'Add security headers with helmet: app.use(helmet())',
  10020: 'helmet sets X-Frame-Options / frame-ancestors',
  10021: 'helmet sets X-Content-Type-Options: nosniff',
  10035: 'helmet sets Strict-Transport-Security',
  10037: "helmet removes it, or app.disable('x-powered-by')",
  10010: 'express-session cookie: { httpOnly: true }',
  10011: 'express-session cookie: { secure: true }',
  10054: "express-session cookie: { sameSite: 'lax' }",
  40018: 'Use parameterised queries for every SQL statement',
  90019: 'Remove eval(); parse input into a number and validate its range',
};

export function zapToFinding(z: ZapAlert): Finding {
  return { tool: 'zap', ruleId: String(z.id), severity: z.risk === 'High' ? 'HIGH' : z.risk === 'Medium' ? 'MEDIUM' : 'LOW', title: z.name, url: z.urls[0], detail: `${z.urls.length} URL(s)`, remediation: ZAP_FIX[z.id] };
}

// ---------- Kubernetes / Kyverno ----------

type Obj = Record<string, unknown>;
const get = (o: unknown, path: string): unknown => path.split('.').reduce<unknown>((x, k) => (x && typeof x === 'object' ? (x as Obj)[k] : undefined), o);

export interface Violation {
  policy: string;
  rule: string;
  message: string;
}

export interface Workload {
  kind: string;
  name: string;
  namespace: string;
  containers: Obj[];
  podSecurity: Obj;
}

export function parseWorkloads(src: string): { workloads: Workload[]; error: string | null } {
  try {
    const docs = parseYamlDocs(src) as Obj[];
    return {
      workloads: docs
        .filter((d) => d && typeof d === 'object')
        .map((d) => ({
          kind: String(d.kind ?? ''),
          name: String(get(d, 'metadata.name') ?? ''),
          namespace: String(get(d, 'metadata.namespace') ?? 'default'),
          containers: ((get(d, 'spec.template.spec.containers') ?? get(d, 'spec.containers') ?? []) as Obj[]),
          podSecurity: ((get(d, 'spec.template.spec.securityContext') ?? get(d, 'spec.securityContext') ?? {}) as Obj),
        })),
      error: null,
    };
  } catch (e) {
    return { workloads: [], error: `error: error parsing YAML: line ${(e as { line?: number }).line ?? '?'}: ${(e as Error).message}` };
  }
}

export function kyverno(w: Workload): Violation[] {
  const v: Violation[] = [];
  if (!['Deployment', 'Pod', 'StatefulSet', 'DaemonSet'].includes(w.kind)) return v;
  for (const c of w.containers) {
    const sc = (c.securityContext as Obj) ?? {};
    if (sc.privileged === true) v.push({ policy: 'disallow-privileged-containers', rule: 'autogen-privileged-containers', message: 'Privileged mode is disallowed. The fields spec.containers[*].securityContext.privileged must be unset or set to `false`.' });
    if (sc.allowPrivilegeEscalation !== false) v.push({ policy: 'disallow-privilege-escalation', rule: 'autogen-privilege-escalation', message: 'Privilege escalation is disallowed. spec.containers[*].securityContext.allowPrivilegeEscalation must be set to `false`.' });
    if (sc.runAsNonRoot !== true && w.podSecurity.runAsNonRoot !== true) v.push({ policy: 'require-run-as-nonroot', rule: 'autogen-run-as-non-root', message: 'Running as root is not allowed. spec.securityContext.runAsNonRoot or spec.containers[*].securityContext.runAsNonRoot must be set to `true`.' });
    const img = String(c.image ?? '');
    if (!img.includes(':') || img.endsWith(':latest')) v.push({ policy: 'disallow-latest-tag', rule: 'autogen-validate-image-tag', message: "Using a mutable image tag e.g. 'latest' is not allowed." });
    if (!get(c, 'resources.limits.memory') || !get(c, 'resources.requests.cpu')) v.push({ policy: 'require-requests-limits', rule: 'autogen-validate-resources', message: 'CPU and memory resource requests and memory limits are required for containers.' });
  }
  return v;
}

export function kyvernoFindings(w: Workload, file: string): Finding[] {
  return kyverno(w).map((x) => ({ tool: 'kyverno', ruleId: x.policy, severity: /privileged|nonroot/.test(x.policy) ? 'HIGH' : 'MEDIUM', title: x.message, file, detail: `${w.kind}/${w.name} · rule ${x.rule}`, remediation: 'Fix the securityContext, image tag or resources in the manifest.' }));
}

export function denyMessage(w: Workload, file: string, v: Violation[]): string[] {
  const out = [`Error from server: error when creating "${file}": admission webhook "validate.kyverno.svc-fail" denied the request:`, '', `resource ${w.kind}/${w.namespace}/${w.name} was blocked due to the following policies`, ''];
  const by: Record<string, Violation[]> = {};
  v.forEach((x) => (by[x.policy] ??= []).push(x));
  for (const [p, xs] of Object.entries(by)) {
    out.push(`${p}:`);
    xs.forEach((x) => out.push(`  ${x.rule}: 'validation error: ${x.message}'`));
  }
  return out;
}

export function rollout(image: string, registry: Record<string, ImageInfo>, commit: string): { ok: boolean; log: string[]; dep?: Deployment } {
  const img = registry[image];
  const wait = 'Waiting for deployment "shopflow-api" rollout to finish: 0 of 2 updated replicas are available...';
  if (!img) return { ok: false, log: [wait, `  shopflow-api-7c9d5b-xk2lp   0/1   ErrImagePull   image "${image}" not found in registry`, 'error: deployment "shopflow-api" exceeded its progress deadline'] };
  const run = dockerRun(img);
  if (!run.ok) return { ok: false, log: [wait, '  shopflow-api-7c9d5b-xk2lp   0/1   CrashLoopBackOff', ...run.log.map((l) => '  ' + l), 'error: deployment "shopflow-api" exceeded its progress deadline'] };
  const err = moduleLoadError(img.files, img.installed);
  if (err) return { ok: false, log: [wait, '  shopflow-api-7c9d5b-xk2lp   0/1   CrashLoopBackOff', ...err.split('\n').map((l) => '  ' + l), 'error: deployment "shopflow-api" exceeded its progress deadline'] };
  return { ok: true, log: ['deployment "shopflow-api" successfully rolled out'], dep: { image, commit, files: img.files, installed: img.installed, at: Date.now() } };
}
