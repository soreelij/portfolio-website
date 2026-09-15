// Unencrypted password gate. Fetches manifest.json (salt/iv/iterations/
// ciphertext — none of it secret on its own) and, on submit, derives an
// AES-256 key from the entered password via PBKDF2-SHA256 and attempts to
// decrypt. A wrong password fails the AES-GCM auth tag check cleanly; nothing
// about the real content is ever fetched or rendered until that succeeds.
const form = document.getElementById('gate');
const input = document.getElementById('password');
const errorEl = document.getElementById('error');
const submitBtn = form.querySelector('button');

// Remembers a correct password on this device so a returning visitor skips
// retyping it — plaintext in localStorage, readable by anyone with access
// to this browser/device. Fine for a party-invite gate (not protecting
// anything sensitive); don't reuse this password anywhere it would matter.
const STORAGE_KEY = 'party-password';

// Hidden synchronously (not just on catch) so a returning visitor with a
// still-valid cached password never even sees the form flash before this
// swaps it out for the real page.
const cachedPassword = localStorage.getItem(STORAGE_KEY);
if (cachedPassword) form.style.visibility = 'hidden';

function b64ToBytes(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
}

async function deriveKey(password, salt, iterations) {
    const baseKey = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(password),
        'PBKDF2',
        false,
        ['deriveKey'],
    );
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt'],
    );
}

async function unlock(password) {
    const res = await fetch('./manifest.json', { cache: 'no-store' });
    const manifest = await res.json();

    const salt = b64ToBytes(manifest.salt);
    const iv = b64ToBytes(manifest.iv);
    const ciphertext = b64ToBytes(manifest.ciphertext);

    const key = await deriveKey(password, salt, manifest.iterations);
    const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return JSON.parse(new TextDecoder().decode(plainBuf));
}

function render(payload) {
    if (payload.title) document.title = payload.title;

    // The gate's own styling (centers/styles the password form) would
    // otherwise persist on <html>/<body> and fight with the real app's
    // layout — the app expects normal document flow, not a flex-centered,
    // fixed-height body.
    document.getElementById('gate-style')?.remove();

    const style = document.createElement('style');
    style.textContent = payload.css;
    document.head.appendChild(style);

    document.body.innerHTML = payload.bodyHtml;

    const blob = new Blob([payload.js], { type: 'text/javascript' });
    const script = document.createElement('script');
    script.type = 'module';
    script.src = URL.createObjectURL(blob);
    document.body.appendChild(script);
}

form.addEventListener('submit', async (event) => {
    event.preventDefault();
    errorEl.textContent = '';
    submitBtn.disabled = true;

    try {
        const payload = await unlock(input.value);
        localStorage.setItem(STORAGE_KEY, input.value);
        render(payload);
    } catch {
        errorEl.textContent = "incorrect password.\nare you sure you're invited?";
        submitBtn.disabled = false;
    }
});

// Runs once on load, before the visitor ever touches the form. A stale
// cached password (e.g. it was changed since) fails the same clean way a
// wrong manual guess does — just clear it and fall back to the (now
// visible) form instead of showing an error nobody asked for.
if (cachedPassword) {
    unlock(cachedPassword)
        .then(render)
        .catch(() => {
            localStorage.removeItem(STORAGE_KEY);
            form.style.visibility = 'visible';
        });
}
