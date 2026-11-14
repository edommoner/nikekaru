/* Shared by the loader, service worker and Node's vm. No app content. */
(function (scope) {
  const encode = value => new TextEncoder().encode(value);
  const from64 = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
  const validMetadata = info => info?.v === 1 && info.kdf === 'PBKDF2-SHA256' && info.iterations === 600000 && from64(info.salt).length === 16;
  async function deriveKey(password, info) {
    if (!validMetadata(info)) throw Error('鍵の形式が違います。');
    const material = await crypto.subtle.importKey('raw', encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({name:'PBKDF2', hash:'SHA-256', salt:from64(info.salt), iterations:info.iterations}, material, {name:'AES-GCM', length:256}, false, ['decrypt']);
  }
  async function decryptBlob(key, bytes) {
    const data = new Uint8Array(bytes);
    return crypto.subtle.decrypt({name:'AES-GCM', iv:data.slice(0,12)}, key, data.slice(12));
  }
  async function verifyCheck(key, info) {
    try { return new TextDecoder().decode(await decryptBlob(key, from64(info.check))) === 'nikekaru-key-check-v1'; }
    catch { return false; }
  }
  function manifestLookup(manifest, url, base) {
    const request = new URL(url), root = new URL(base);
    if (request.origin !== root.origin || !request.pathname.startsWith(root.pathname)) return null;
    let name;
    try { name = decodeURIComponent(request.pathname.slice(root.pathname.length)) || 'index.html'; } catch { return null; }
    return Object.hasOwn(manifest, name) ? manifest[name] : null;
  }
  // A separate database per scope avoids sharing keys between sites on the same origin.
  async function keyRecord(base, operation, value) {
    const db = await new Promise((resolve,reject) => {
      const request = indexedDB.open('nikekaru-site:' + new URL(base).pathname, 1);
      request.onupgradeneeded = () => request.result.createObjectStore('keys');
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    try {
      return await new Promise((resolve,reject) => {
        const tx = db.transaction('keys', operation === 'get' ? 'readonly' : 'readwrite');
        const store = tx.objectStore('keys');
        const request = operation === 'get' ? store.get('active') : operation === 'put' ? store.put(value,'active') : store.delete('active');
        tx.oncomplete = () => resolve(request.result);
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error);
      });
    } finally { db.close(); }
  }
  scope.SiteCrypto = {deriveKey, decryptBlob, verifyCheck, manifestLookup, keyRecord};
})(self);
