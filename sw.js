importScripts('crypto-core.js');
const base = self.registration.scope;
let cachedKey = null, cachedManifest = null, generation = 0;
self.addEventListener('install', event => event.waitUntil(self.skipWaiting()));
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));
self.addEventListener('message', event => {
  if (event.data?.type !== 'logout') return;
  event.waitUntil((async () => {
    generation++; cachedKey = null; cachedManifest = null;
    try { await SiteCrypto.keyRecord(base, 'delete'); event.ports[0]?.postMessage({ok:true}); }
    catch { event.ports[0]?.postMessage({ok:false}); }
  })());
});
const network = name => fetch(new URL(name, base), {cache:'no-store'});
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url), root = new URL(base);
  if (event.request.method !== 'GET' || url.origin !== root.origin || !url.pathname.startsWith(root.pathname)) return;
  const name = url.pathname.slice(root.pathname.length);
  if (['key.json','sw.js','crypto-core.js','THIRD_PARTY_LICENSES.txt','.nojekyll'].includes(name) || name.startsWith('c/')) return;
  event.respondWith((async () => {
    try {
      const epoch = generation;
      const record = await SiteCrypto.keyRecord(base, 'get');
      if (!record || (!record.remember && (!record.expires || Date.now() >= record.expires))) {
        if (record) await SiteCrypto.keyRecord(base, 'delete');
        cachedKey = null; cachedManifest = null;
        throw Error('鍵がありません。');
      }
      // Structured cloning produces a new CryptoKey on every read; compare the
      // public check identity, never export the stored non-extractable key.
      const info = await (await network('key.json')).json();
      const identity = info.salt + ':' + info.check;
      if (cachedKey !== identity) {
        if (!await SiteCrypto.verifyCheck(record.key, info)) throw Error('鍵が違います。');
        const response = await network('c/manifest.bin');
        if (!response.ok) throw Error('取得できません。');
        const manifest = JSON.parse(new TextDecoder().decode(await SiteCrypto.decryptBlob(record.key, await response.arrayBuffer())));
        if (epoch !== generation) throw Error('ログアウトしました。');
        cachedManifest = manifest; cachedKey = identity;
      }
      const entry = SiteCrypto.manifestLookup(cachedManifest, url.href, base);
      if (!entry || !/^[a-f0-9]{32}$/.test(entry.id)) throw Error('見つかりません。');
      const response = await network('c/' + entry.id + '.bin');
      if (!response.ok) throw Error('取得できません。');
      const bytes = await SiteCrypto.decryptBlob(record.key, await response.arrayBuffer());
      if (epoch !== generation) throw Error('ログアウトしました。');
      return new Response(bytes, {headers:{'Content-Type':entry.type, 'Cache-Control':'no-store'}});
    } catch {
      cachedKey = null; cachedManifest = null;
      if (event.request.mode === 'navigate') {
        const response = await network('index.html');
        return new Response(await response.arrayBuffer(), {status:response.status, headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'}});
      }
      return new Response('認証が必要です。', {status:401, headers:{'Cache-Control':'no-store'}});
    }
  })());
});
