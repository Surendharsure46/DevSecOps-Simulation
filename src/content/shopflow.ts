import type { Files } from '../engine/types';
import { resolve, writeLock, type PkgJson } from '../engine/sca';
import { moduleLoadError, parameterised, routeBlock, sqlInjectable, usesEval } from '../engine/appmodel';
import type { TestCase } from '../engine/shell';

// ShopFlow: the synthetic sample application every lab starts from.

export const TEAM = {
  priya: 'Priya Natarajan <priya@shopflow.dev>',
  marco: 'Marco Bellini <marco@shopflow.dev>',
  dana: 'Dana Okoye <dana@shopflow.dev>',
};

/** package.json + a lockfile pinned to the given versions. */
export function npmFiles(deps: Record<string, string>, locked: Record<string, string>, dev: Record<string, string> = { jest: '^29.7.0' }): Files {
  const pkg: PkgJson = { name: 'shopflow-api', version: '1.4.0', scripts: { start: 'node src/server.js', test: 'jest' }, dependencies: deps, devDependencies: dev };
  const { installed } = resolve(pkg, locked);
  return { 'package.json': JSON.stringify(pkg, null, 2) + '\n', 'package-lock.json': writeLock(pkg, installed) };
}

export const README = `# ShopFlow API

Order and checkout service for the ShopFlow web shop.

    npm install
    npm test
    npm start

Configuration comes from environment variables (see .env.example).
Never commit real credentials.
`;

export const GITIGNORE = 'node_modules/\ncoverage/\n.env\n*.log\n';

export const SERVER_JS = `const express = require('express');
const orders = require('./routes/orders');
const products = require('./routes/products');

const app = express();
app.use(express.json());

app.get('/health', (req, res) => res.json({ status: 'ok' }));
app.use('/api', orders);
app.use('/api', products);

app.get('*', (req, res) => res.status(404).json({ error: 'not found' }));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(\`ShopFlow API listening on \${port}\`));

module.exports = app;
`;

export const DB_JS = `const { Pool } = require('pg');

const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: 'shopflow',
});

module.exports = {
  query: async (text, params) => (await pool.query(text, params)).rows,
};
`;

export const ORDERS_SAFE = `const express = require('express');
const db = require('../db');

const router = express.Router();

// GET /api/orders?customer=C-1001
router.get('/orders', async (req, res) => {
  const rows = await db.query(
    'SELECT id, total, status FROM orders WHERE customer_id = $1',
    [req.query.customer],
  );
  res.json(rows);
});

// GET /api/orders/:id/receipt
router.get('/orders/:id/receipt', async (req, res) => {
  const rows = await db.query('SELECT order_id, total FROM receipts WHERE order_id = $1', [req.params.id]);
  res.json(rows[0]);
});

// POST /api/orders/discount  { "percent": 10 }
router.post('/orders/discount', async (req, res) => {
  const percent = Number(req.body.percent);
  if (!Number.isFinite(percent) || percent < 0 || percent > 100) {
    return res.status(400).json({ error: 'percent must be a number between 0 and 100' });
  }
  res.json({ total: 100 - percent });
});

module.exports = router;
`;

export const ORDERS_VULN = `const express = require('express');
const db = require('../db');

const router = express.Router();

// GET /api/orders?customer=C-1001
router.get('/orders', async (req, res) => {
  const customer = req.query.customer;
  const sql = "SELECT id, total, status FROM orders WHERE customer_id = '" + customer + "'";
  const rows = await db.query(sql);
  res.json(rows);
});

// GET /api/orders/:id/receipt
router.get('/orders/:id/receipt', async (req, res) => {
  const rows = await db.query(\`SELECT order_id, total FROM receipts WHERE order_id = \${req.params.id}\`);
  res.json(rows[0]);
});

// POST /api/orders/discount  { "expr": "total * 0.9" }
// Marketing asked for "flexible" discount formulas.
router.post('/orders/discount', async (req, res) => {
  const total = 100;
  const result = eval(req.body.expr);
  res.json({ total: result });
});

module.exports = router;
`;

export const PRODUCTS_JS = `const express = require('express');
const db = require('../db');

const router = express.Router();

// Featured category is a compile-time constant (never user input).
const FEATURED_CATEGORY = 7;

// GET /api/products/featured
router.get('/products/featured', async (req, res) => {
  const rows = await db.query('SELECT id, name, price FROM products WHERE category_id = ' + FEATURED_CATEGORY);
  res.json(rows);
});

// GET /api/products/:id
router.get('/products/:id', async (req, res) => {
  const rows = await db.query('SELECT id, name, price FROM products WHERE id = $1', [req.params.id]);
  res.json(rows[0] || null);
});

module.exports = router;
`;

export const PRODUCTS_SAFE = PRODUCTS_JS.replace(
  "db.query('SELECT id, name, price FROM products WHERE category_id = ' + FEATURED_CATEGORY)",
  "db.query('SELECT id, name, price FROM products WHERE category_id = $1', [FEATURED_CATEGORY])",
);

export const CART_JS_OK = `// Cart helpers used by the checkout flow.

function cartTotal(items) {
  return items.reduce((sum, item) => sum + item.price * item.quantity, 0);
}

function applyCoupon(total, coupon) {
  if (!coupon) return total;
  return Math.max(0, total - coupon.amount);
}

module.exports = { cartTotal, applyCoupon };
`;

const CART_TEST_SRC = `const { cartTotal, applyCoupon } = require('../src/lib/cart');

test('sums price x quantity for every line', () => {
  expect(cartTotal([{ price: 10, quantity: 2 }, { price: 5, quantity: 1 }])).toBe(25);
});

test('empty cart is zero', () => {
  expect(cartTotal([])).toBe(0);
});

test('coupon never makes the total negative', () => {
  expect(applyCoupon(5, { amount: 10 })).toBe(0);
});
`;

const ORDERS_TEST_SRC = `// Route contract tests for the orders API (in-memory database).
describe('orders', () => {
  test('GET /api/orders filters by customer');
  test('GET /api/orders/:id/receipt returns one receipt');
  test('POST /api/orders/discount returns a total');
});
`;

export const DOCKERFILE_OK = `FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY src ./src
USER node
EXPOSE 3000
HEALTHCHECK CMD wget -qO- http://localhost:3000/health || exit 1
CMD ["node", "src/server.js"]
`;

export const DOCKERIGNORE_OK = '.git\nnode_modules\n.env\n*.log\ntests\n';

export function baseFiles(extra: Files = {}): Files {
  return {
    'README.md': README,
    '.gitignore': GITIGNORE,
    '.env.example': 'DB_HOST=localhost\nDB_USER=shopflow\nDB_PASSWORD=<set-me>\nPORT=3000\n',
    ...npmFiles({ express: '^4.21.2', pg: '^8.13.1' }, { express: '4.21.2', pg: '8.13.1', jest: '29.7.0' }),
    'src/server.js': SERVER_JS,
    'src/db.js': DB_JS,
    'src/routes/orders.js': ORDERS_SAFE,
    'src/routes/products.js': PRODUCTS_SAFE,
    'src/lib/cart.js': CART_JS_OK,
    'tests/cart.test.js': CART_TEST_SRC,
    'tests/orders.test.js': ORDERS_TEST_SRC,
    ...extra,
  };
}

// ---------------------------------------------------------------------------
// Unit tests run by `npm test` (locally and in CI)

/** Load a dependency-free CommonJS module from the repo and execute it for real. */
function loadModule(files: Files, path: string): Record<string, unknown> {
  const src = files[path];
  if (src === undefined) throw new Error(`Cannot find module '../${path.replace(/\.js$/, '')}' from 'tests'`);
  const module = { exports: {} as Record<string, unknown> };
  new Function('module', 'exports', 'require', src)(module, module.exports, (n: string) => {
    throw new Error(`Cannot require '${n}' in the unit-test sandbox`);
  });
  return module.exports;
}

function cartCase(name: string, call: string, fn: (m: Record<string, unknown>) => unknown, expected: unknown): TestCase {
  return {
    suite: 'tests/cart.test.js',
    name,
    run: (fs) => {
      try {
        const actual = fn(loadModule(fs, 'src/lib/cart.js'));
        return actual === expected ? null : `expect(received).toBe(expected)\n\nExpected: ${JSON.stringify(expected)}\nReceived: ${JSON.stringify(actual)}\n\n  at ${call}`;
      } catch (e) {
        return `${(e as Error).name}: ${(e as Error).message}`;
      }
    },
  };
}

type Fn = (...a: unknown[]) => unknown;

export const CART_TESTS: TestCase[] = [
  cartCase('sums price x quantity for every line', 'cartTotal([{price:10,quantity:2},{price:5,quantity:1}])', (m) => (m.cartTotal as Fn)([{ price: 10, quantity: 2 }, { price: 5, quantity: 1 }]), 25),
  cartCase('empty cart is zero', 'cartTotal([])', (m) => (m.cartTotal as Fn)([]), 0),
  cartCase('coupon never makes the total negative', 'applyCoupon(5, {amount:10})', (m) => (m.applyCoupon as Fn)(5, { amount: 10 }), 0),
];

function routeCase(name: string, method: string, path: string, check: (b: string) => string | null): TestCase {
  return {
    suite: 'tests/orders.test.js',
    name,
    run: (fs) => {
      const b = routeBlock(fs['src/routes/orders.js'], method, path);
      return b ? check(b) : `Expected route ${method.toUpperCase()} ${path} to be registered — received 404 Not Found`;
    },
  };
}

export const ORDER_TESTS: TestCase[] = [
  routeCase('GET /api/orders filters by customer', 'get', '/orders', (b) => (/customer_id/.test(b) && /res\.json\(/.test(b) ? null : 'Expected orders to be filtered by customer_id and returned as JSON')),
  routeCase('GET /api/orders/:id/receipt returns one receipt', 'get', '/orders/:id/receipt', (b) => (/receipts/.test(b) && /req\.params\.id/.test(b) ? null : 'Expected the receipt to be looked up by req.params.id')),
  routeCase('POST /api/orders/discount returns a total', 'post', '/orders/discount', (b) => (/total/.test(b) && /res\.(status\(\d+\)\.)?json\(/.test(b) ? null : 'Expected a JSON body with a "total" field')),
];

export const SERVER_TEST: TestCase = { suite: 'tests/server.test.js', name: 'server boots and loads all modules', run: (fs, installed) => moduleLoadError(fs, installed) };

export const PRODUCTS_TEST: TestCase = {
  suite: 'tests/products.test.js',
  name: 'GET /api/products/featured lists the featured category',
  run: (fs) => {
    const b = routeBlock(fs['src/routes/products.js'], 'get', '/products/featured');
    if (!b) return 'Expected route GET /products/featured to be registered — received 404 Not Found';
    return /FEATURED_CATEGORY|category_id/.test(b) ? null : 'Expected the featured category filter to remain';
  },
};

export function ordersSecure(fs: Files): { list: boolean; receipt: boolean; discount: boolean } {
  const src = fs['src/routes/orders.js'];
  const list = routeBlock(src, 'get', '/orders');
  const receipt = routeBlock(src, 'get', '/orders/:id/receipt');
  const discount = routeBlock(src, 'post', '/orders/discount');
  return {
    list: !!list && !sqlInjectable(list) && parameterised(list),
    receipt: !!receipt && !sqlInjectable(receipt) && parameterised(receipt),
    discount: !!discount && !usesEval(discount),
  };
}
