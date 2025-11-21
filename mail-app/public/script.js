// script.js for mail-app (paste entire file)
const API_BASE = ''; // same origin (served by server)
let TOKEN = null;
let LOGGED_IN_EMAIL = null;
let PRIVATE_KEY_JWK = null; // stored in localStorage as 'mail_private_jwk'

// UTILS: robust base64 <-> ArrayBuffer and string helpers
// Safe implementations that handle large buffers and keep types consistent.

function bufToB64(buffer) {
  // Accept ArrayBuffer or TypedArray
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  // convert to binary string in chunks to avoid call-stack issues
  const chunkSize = 0x8000; // 32KB chunks
  let binary = '';
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode.apply(null, chunk);
  }
  return btoa(binary);
}

function b64ToBuf(b64) {
  // decode base64 to ArrayBuffer
  const binary = atob(b64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer; // return ArrayBuffer
}

function strToBuf(s) { return new TextEncoder().encode(s); }
function bufToStr(buf) { return new TextDecoder().decode(buf); }



// --- KEY HELPERS (Web Crypto) ---
// Generate RSA key pair (for both encryption OAEP and signing PSS)
async function generateRsaKeypair() {
  // We'll generate 2048-bit RSA, allow usages for encrypt/decrypt & sign/verify
  // Browsers may require separate key usages; we'll export separate keys if needed.
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1,0,1]),
      hash: "SHA-256"
    },
    true,
    ["encrypt", "decrypt"]
  );
  // For signing we also generate a separate RSA-PSS key pair (recommended)
  const signPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-PSS",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1,0,1]),
      hash: "SHA-256"
    },
    true,
    ["sign", "verify"]
  );
  return { enc: keyPair, sign: signPair };
}

async function exportPublicKeyToPem(key) {
  const spki = await window.crypto.subtle.exportKey("spki", key);
  const b64 = bufToB64(spki);
  const pem = `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
  return pem;
}

async function exportPrivateJwk(key) {
  return await window.crypto.subtle.exportKey("jwk", key);
}

async function importPublicKeyFromPem(pem, usage, algName) {
  // pem => ArrayBuffer (SPKI)
  const b64 = pem.replace(/-----.*-----/g, '').replace(/\s+/g,'');
  const buf = b64ToBuf(b64);
  if (algName === 'RSA-OAEP') {
    return await window.crypto.subtle.importKey('spki', buf, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, usage);
  } else if (algName === 'RSA-PSS') {
    return await window.crypto.subtle.importKey('spki', buf, { name: 'RSA-PSS', hash: 'SHA-256' }, true, usage);
  } else {
    throw new Error('Unsupported algName');
  }
}

async function importPrivateKeyFromJwk(jwk, usage, algName) {
  if (algName === 'RSA-OAEP') {
    return await window.crypto.subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, usage);
  } else if (algName === 'RSA-PSS') {
    return await window.crypto.subtle.importKey('jwk', jwk, { name: 'RSA-PSS', hash: 'SHA-256' }, true, usage);
  } else {
    throw new Error('Unsupported algName');
  }
}



// --- Password-based encryption helpers (PBKDF2 -> AES-GCM) ---

// Derive an AES-GCM key from a password and salt (Uint8Array)
async function deriveKeyFromPassword(password, saltUint8) {
  const pwUtf8 = new TextEncoder().encode(password);
  const pwKey = await window.crypto.subtle.importKey('raw', pwUtf8, { name: 'PBKDF2' }, false, ['deriveKey']);
  const key = await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltUint8,
      iterations: 100000,
      hash: 'SHA-256'
    },
    pwKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  return key;
}

// Encrypt JSON-string privateBundle with password; returns { ciphertextB64, saltB64, ivB64 }
async function encryptPrivateBundle(privateBundleObj, password) {
  const plain = new TextEncoder().encode(JSON.stringify(privateBundleObj));
  const salt = window.crypto.getRandomValues(new Uint8Array(16)); // 128-bit salt
  const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for GCM
  const key = await deriveKeyFromPassword(password, salt);
  const cipherBuf = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain);
  return {
    ciphertext: bufToB64(cipherBuf),
    salt: bufToB64(salt.buffer),
    iv: bufToB64(iv.buffer)
  };
}

// Decrypt server-provided encrypted bundle {ciphertext, salt, iv} (base64) with password
// Returns parsed JSON object (the private JWK bundle)
async function decryptPrivateBundle(encryptedObj, password) {
  const saltBuf = b64ToBuf(encryptedObj.salt);
  const ivBuf = b64ToBuf(encryptedObj.iv);
  const cipherBuf = b64ToBuf(encryptedObj.ciphertext);
  const salt = new Uint8Array(saltBuf);
  const iv = new Uint8Array(ivBuf);
  const key = await deriveKeyFromPassword(password, salt);
  const plainBuf = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipherBuf);
  const plainText = new TextDecoder().decode(plainBuf);
  return JSON.parse(plainText);
}




// --- Registration flow (updated): encrypt private bundle with password and send encrypted blob to server ---
async function registerUser(email, password) {
  // generate keypairs
  const { enc, sign } = await generateRsaKeypair();

  // export public keys (PEM)
  const publicEncPem = await exportPublicKeyToPem(enc.publicKey);
  const publicSignPem = await exportPublicKeyToPem(sign.publicKey);

  // export private JWKs (keep local copy for convenience)
  const privateEncJwk = await exportPrivateJwk(enc.privateKey);
  const privateSignJwk = await exportPrivateJwk(sign.privateKey);
  const privBundle = { enc: privateEncJwk, sign: privateSignJwk, email };

  // store local copy (optional convenience backup)
  localStorage.setItem('mail_private_jwk', JSON.stringify(privBundle));
  PRIVATE_KEY_JWK = privBundle;

  // encrypt the private bundle with a key derived from the user's password
  const encrypted = await encryptPrivateBundle(privBundle, password);
  // send register to server with public keys and encrypted private blob
  const publicBundle = { publicEncPem, publicSignPem };
  const res = await fetch('/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email,
      password,
      publicKeyPem: JSON.stringify(publicBundle),
      encryptedPrivate: encrypted // { ciphertext, salt, iv } all base64
    })
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.message || 'Register failed');
  return data;
}




// --- Login flow (updated): after auth, fetch encrypted private blob and decrypt with password ---
async function loginUser(email, password) {
  const res = await fetch('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.message || 'Login failed');

  TOKEN = data.token;
  LOGGED_IN_EMAIL = email;

  // If server returned encryptedPrivate blob, try to decrypt it with provided password
  if (data.encryptedPrivate) {
    try {
      const decrypted = await decryptPrivateBundle(data.encryptedPrivate, password);
      // Store decrypted JWK bundle locally for this browser (so you can decrypt without re-entering password)
      localStorage.setItem('mail_private_jwk', JSON.stringify(decrypted));
      PRIVATE_KEY_JWK = decrypted;
    } catch (e) {
      // Decryption failed (wrong password or corrupt blob)
      console.warn('Failed to decrypt private bundle from server:', e);
      // Do NOT throw here because user can still have local keys or re-import
    }
  } else {
    // fallback: load private jwk from localStorage (existing UX)
    const priv = localStorage.getItem('mail_private_jwk');
    if (priv) PRIVATE_KEY_JWK = JSON.parse(priv);
  }
  return data;
}




// --- Compose & Send (client-side hybrid crypto) ---
// Steps:
// 1) fetch recipient public keys (/pubkey/:email) => returns JSON-stringified bundle { publicEncPem, publicSignPem }
// 2) generate AES-GCM key, encrypt message content -> ciphertext & iv
// 3) export AES key raw, encrypt AES key with recipient's publicEncPem (RSA-OAEP) => encKey (base64)
// 4) sign ciphertext with sender private sign key (RSA-PSS) => signature (base64)
// 5) send bundle {ciphertext, iv, encKey, signature} to server via /send (with token)
async function sendEncryptedMail(to, subject, bodyText) {
  if (!TOKEN) throw new Error('Not logged in');

  // fetch recipient public key bundle
  const r = await fetch(`/pubkey/${encodeURIComponent(to)}`);
  if (!r.ok) {
    const err = await r.json();
    throw new Error(err.message || 'Cannot fetch recipient public key');
  }
  const pb = await r.json();
  // pb.publicKeyPem is JSON-stringified bundle
  const publicBundle = JSON.parse(pb.publicKeyPem);
  const recipientEncPem = publicBundle.publicEncPem;
  const recipientSignPem = publicBundle.publicSignPem;

  // import recipient public keys
  const recipientEncKey = await importPublicKeyFromPem(recipientEncPem, ['encrypt'], 'RSA-OAEP');
  // note: we will verify signature later using sender public key fetched from server when receiving

  // generate AES-GCM key
  const aesKey = await window.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV recommended for GCM

  // encrypt message (text)
  const ciphertextBuf = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, strToBuf(bodyText));

  // export AES key raw and encrypt it with recipient's RSA-OAEP public key
  const rawAes = await window.crypto.subtle.exportKey('raw', aesKey);
  const encKeyBuf = await window.crypto.subtle.encrypt({ name: 'RSA-OAEP' }, recipientEncKey, rawAes);

  // import sender signing private key from localStorage
  if (!PRIVATE_KEY_JWK || !PRIVATE_KEY_JWK.sign) throw new Error('Missing local private signing key. Register first.');
  const senderPrivSign = await importPrivateKeyFromJwk(PRIVATE_KEY_JWK.sign, ['sign'], 'RSA-PSS');

  // create signature over ciphertext (we sign the ciphertext bytes)
  const signatureBuf = await window.crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, senderPrivSign, ciphertextBuf);

  // base64-encode pieces
  const bundle = {
    ciphertext: bufToB64(ciphertextBuf),
    iv: bufToB64(iv.buffer),
    encKey: bufToB64(encKeyBuf),
    signature: bufToB64(signatureBuf)
  };

  // send to server
  const res = await fetch('/send', {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + TOKEN,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ to, subject, bundle })
  });
  const j = await res.json();
  if (!res.ok) throw new Error(j.message || 'Send failed');
  return j;
}

// --- Fetch inbox and decrypt messages ---
async function fetchAndDecryptInbox() {
  if (!TOKEN) throw new Error('Not logged in');
  const res = await fetch('/inbox', {
    headers: { Authorization: 'Bearer ' + TOKEN }
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.message || 'Inbox fetch failed');
  }
  const mails = await res.json(); // array of {id, from, subject, bundle, date}
  const output = [];
  for (const m of mails) {
    try {
      const { bundle } = m;
      // load sender public signing key to verify signature
      const from = m.from;
      const resp = await fetch(`/pubkey/${encodeURIComponent(from)}`);
      const pb = await resp.json();
      const senderPubBundle = JSON.parse(pb.publicKeyPem);
      const senderSignPem = senderPubBundle.publicSignPem;
      const senderPubSignKey = await importPublicKeyFromPem(senderSignPem, ['verify'], 'RSA-PSS');

      // import our private RSA-OAEP key to decrypt AES key
      if (!PRIVATE_KEY_JWK || !PRIVATE_KEY_JWK.enc) throw new Error('Missing private decrypt key locally');
      const myPrivEnc = await importPrivateKeyFromJwk(PRIVATE_KEY_JWK.enc, ['decrypt'], 'RSA-OAEP');

      // decode pieces
      const encKeyBuf = b64ToBuf(bundle.encKey);
      const rawAes = await window.crypto.subtle.decrypt({ name: 'RSA-OAEP' }, myPrivEnc, encKeyBuf);

      // import AES key and decrypt ciphertext
      const aesKey = await window.crypto.subtle.importKey('raw', rawAes, { name: 'AES-GCM' }, false, ['decrypt']);
      const iv = b64ToBuf(bundle.iv);
      const ciphertextBuf = b64ToBuf(bundle.ciphertext);
      const plainBuf = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(iv) }, aesKey, ciphertextBuf);
      const plainText = bufToStr(plainBuf);

      // verify signature
      const signatureBuf = b64ToBuf(bundle.signature);
      const verified = await window.crypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, senderPubSignKey, signatureBuf, ciphertextBuf);

      output.push({
        id: m.id,
        from: m.from,
        subject: m.subject,
        body: plainText,
        signature_valid: verified,
        date: m.date
      });
    } catch (err) {
      output.push({
        id: m.id,
        from: m.from,
        subject: m.subject,
        body: '[decryption or verification failed: ' + (err.message || err) + ']',
        signature_valid: false,
        date: m.date
      });
    }
  }
  return output;
}

// --- UI helpers (very small) ---
function showLogin() {
  document.getElementById('login-screen').classList.remove('hidden');
  document.getElementById('mail-screen').classList.add('hidden');
}
function showMail(email) {
  document.getElementById('login-screen').classList.add('hidden');
  document.getElementById('mail-screen').classList.remove('hidden');
  document.getElementById('user-email').textContent = email;
}
function showTab(tab) {
  document.getElementById('inbox-tab').classList.toggle('hidden', tab !== 'inbox');
  document.getElementById('compose-tab').classList.toggle('hidden', tab !== 'compose');
}


// --- Import private key UI handlers (for demo/local decryption) ---
function showImportPrivate() {
  const area = document.getElementById('import-keys-area');
  if (area) area.classList.remove('hidden');
}

function hideImportPrivate() {
  const area = document.getElementById('import-keys-area');
  if (area) area.classList.add('hidden');
  const ta = document.getElementById('importPrivTextarea');
  if (ta) ta.value = '';
  const msg = document.getElementById('importPrivMsg');
  if (msg) msg.textContent = '';
}

async function importPrivateBundle() {
  const ta = document.getElementById('importPrivTextarea');
  const msg = document.getElementById('importPrivMsg');
  msg.textContent = 'Importing...';
  try {
    const raw = ta.value.trim();
    if (!raw) throw new Error('Paste the private JWK JSON you saved at registration.');
    let obj;
    try { obj = JSON.parse(raw); } catch (e) { throw new Error('Invalid JSON'); }
    // minimal validation
    if (!obj.enc || !obj.sign) throw new Error('JWK bundle must contain "enc" and "sign" objects.');
    obj.email = obj.email || LOGGED_IN_EMAIL || (obj.enc && obj.enc.kid) || '';
    // store
    localStorage.setItem('mail_private_jwk', JSON.stringify(obj));
    PRIVATE_KEY_JWK = obj;
    msg.textContent = 'Imported. Refreshing inbox...';
    hideImportPrivate();
    // attempt to refresh inbox now that private keys are present
    try { await refreshInbox(); } catch (e) { console.error('refresh after import failed', e); }
  } catch (err) {
    msg.textContent = 'Import failed: ' + (err.message || err);
  }
}

function cancelImportPrivate() {
  hideImportPrivate();
}


// --- Hook up DOM events ---
window.register = async function () {
  try {
    const email = document.getElementById('newEmail').value.trim();
    const password = document.getElementById('newPassword').value;
    if (!email || !password) return alert('fill email + password');
    document.getElementById('register-msg').textContent = 'Generating keys... (may take a second)';
    await registerUser(email, password);
    document.getElementById('register-msg').textContent = 'Registered! Please login.';
    setTimeout(() => window.location.href = 'index.html', 800);
  } catch (e) {
    alert('Register error: ' + (e.message || e));
    document.getElementById('register-msg').textContent = '';
  }
};

window.login = async function () {
  try {
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;
    if (!email || !password) return alert('fill email + password');
    await loginUser(email, password);
    showMail(email);

    // If private keys are missing locally, show import widget (so user can paste them).
    if (!PRIVATE_KEY_JWK || !PRIVATE_KEY_JWK.enc) {
      // show import UI so the user can paste the private JWK bundle
      showImportPrivate();
      // still attempt inbox fetch (will show decryption failed message until keys imported)
      try { await refreshInbox(); } catch (e) { console.warn('Inbox fetch after login failed (keys missing)', e); }
      return;
    }

    // normal flow
    await refreshInbox();
  } catch (e) {
    alert('Login error: ' + (e.message || e));
  }
};



// Persist private keys across logout so user can decrypt later in same browser.
// We clear auth token and UI state but keep the private key bundle in localStorage.
// If you want a full "forget keys" action, add a separate button that calls clearLocalPrivateKeys().
window.logout = function () {
  TOKEN = null;
  LOGGED_IN_EMAIL = null;
  // DO NOT remove mail_private_jwk from localStorage so keys persist for future logins.
  // localStorage.removeItem('mail_private_jwk'); // intentionally commented out
  PRIVATE_KEY_JWK = PRIVATE_KEY_JWK || (localStorage.getItem('mail_private_jwk') ? JSON.parse(localStorage.getItem('mail_private_jwk')) : null);
  showLogin();
};


window.sendMail = async function () {
  try {
    const to = document.getElementById('to').value.trim();
    const subject = document.getElementById('subject').value;
    const body = document.getElementById('body').value;
    if (!to || !subject || !body) return alert('to, subject, body required');
    document.getElementById('send-msg').textContent = 'Sending...';
    await sendEncryptedMail(to, subject, body);
    document.getElementById('send-msg').textContent = 'Sent!';
    document.getElementById('body').value = '';
    await refreshInbox();
  } catch (e) {
    alert('Send error: ' + (e.message || e));
    document.getElementById('send-msg').textContent = '';
  }
};

async function refreshInbox() {
  try {
    const list = await fetchAndDecryptInbox();
    const container = document.getElementById('inbox');
    container.innerHTML = '';
    if (!list.length) container.textContent = '(no messages)';
    for (const m of list) {
      const el = document.createElement('div');
      el.className = 'mail-item';
      el.innerHTML = `<b>From:</b> ${m.from} <br><b>Subject:</b> ${m.subject} <br> <pre>${m.body}</pre><small >Signature valid: ${m.signature_valid}</small>`;
      container.appendChild(el);
    }
  } catch (e) {
    console.error(e);
    document.getElementById('inbox').textContent = 'Error loading inbox: ' + (e.message || e);
  }
}

// On load: show login screen
document.addEventListener('DOMContentLoaded', () => {
  showLogin();
});
