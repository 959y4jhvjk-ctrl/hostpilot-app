#!/usr/bin/env node
/**
 * HostPilot smoke tests — no external services required
 * Exit 0 if all pass
 */
const http = require('http');
const crypto = require('crypto');

const BASE = process.env.TEST_BASE || 'http://127.0.0.1:' + (process.env.PORT || 3001);
let passed = 0, failed = 0;
const results = [];

function req(method, path, body, token) {
  return new Promise((resolve, reject) => {
    const u = new URL(BASE + path);
    const data = body ? JSON.stringify(body) : null;
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers.Authorization = 'Bearer ' + token;
    if (data) headers['Content-Length'] = Buffer.byteLength(data);
    const r = http.request({ hostname: u.hostname, port: u.port, path: u.pathname + u.search, method, headers }, res => {
      let b = '';
      res.on('data', c => b += c);
      res.on('end', () => {
        let j = {};
        try { j = b ? JSON.parse(b) : {}; } catch { j = { raw: b }; }
        resolve({ status: res.statusCode, body: j });
      });
    });
    r.on('error', reject);
    r.setTimeout(12000, () => { r.destroy(); reject(new Error('timeout')); });
    if (data) r.write(data);
    r.end();
  });
}

function ok(name, cond, detail) {
  if (cond) { passed++; results.push('OK  ' + name); }
  else { failed++; results.push('FAIL ' + name + (detail ? ' — ' + detail : '')); }
}

async function main() {
  const ts = Date.now();
  const emailA = `buyer_a_${ts}@test.local`;
  const emailB = `buyer_b_${ts}@test.local`;

  try {
    let r = await req('GET', '/api/health');
    ok('health', r.status === 200 && r.body.status === 'ok');

    r = await req('GET', '/api/properties');
    ok('unauth 401', r.status === 401);

    r = await req('POST', '/api/auth/register', {
      email: emailA, password: 'password123', first_name: 'BuyerA', organization_name: 'OrgA'
    });
    const tokA = r.body.token;
    ok('register A', r.status === 200 || r.status === 201, String(r.status));

    r = await req('POST', '/api/auth/register', {
      email: emailB, password: 'password123', first_name: 'BuyerB', organization_name: 'OrgB'
    });
    const tokB = r.body.token;
    ok('register B', !!tokB);

    r = await req('POST', '/api/auth/login', { email: emailA, password: 'wrong' });
    ok('bad password', r.status === 401 || r.status === 400);

    r = await req('POST', '/api/properties', { name: 'PropA', address: '1 rue Test', checkout_time: '11h00' }, tokA);
    const propA = r.body.property && r.body.property.id;
    ok('create property', !!propA);

    r = await req('GET', '/api/properties', null, tokB);
    const idsB = (r.body.properties || []).map(p => p.id);
    ok('tenant isolation', !idsB.includes(propA));

    r = await req('POST', '/api/reservations', {
      property_id: propA, guest_name: 'Guest', check_in: '2028-01-10', check_out: '2028-01-12', total_amount: 100
    }, tokA);
    const rid = r.body.reservation && r.body.reservation.id;
    ok('create reservation', !!rid);

    r = await req('POST', `/api/reservations/${rid}/checkin-link`, {}, tokA);
    ok('checkin link', !!(r.body.token || r.body.checkin_url));

    r = await req('POST', `/api/reservations/${rid}/checkout`, {}, tokA);
    const task1 = r.body.cleaning_task_id;
    r = await req('POST', `/api/reservations/${rid}/checkout`, {}, tokA);
    ok('checkout idempotent', r.body.idempotent === true && r.body.cleaning_task_id === task1);

    r = await req('POST', `/api/reservations/${rid}/checkout`, {}, tokB);
    ok('cross-tenant checkout denied', r.status === 403 || r.status === 404);

    r = await req('POST', '/api/email/test', { to: 'x@test.local' }, tokA);
    ok('email not configured', r.status === 503 && (r.body.error === 'EMAIL_NOT_CONFIGURED' || r.body.error));

    r = await req('POST', '/api/integrations/airbnb/sync', {}, tokA);
    ok('sync not fake success', r.status === 503 || r.body.ok === false || r.body.error);

    r = await req('POST', '/api/billing/create-checkout-session', { plan: 'pro' }, tokA);
    ok('stripe not configured honest', r.status === 503 || (r.body.message && r.body.message.includes('Config')));

  } catch (e) {
    failed++;
    results.push('FAIL exception — ' + e.message);
  }

  console.log(results.join('\n'));
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}

main();
