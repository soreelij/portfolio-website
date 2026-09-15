// Unencrypted password gate. Fetches manifest.json (salt/iv/iterations/
// ciphertext — none of it secret on its own) and, on submit, derives an
// AES-256 key from the entered password via PBKDF2-SHA256 and attempts to
// decrypt. A wrong password fails the AES-GCM auth tag check cleanly; nothing
// about the real content is ever fetched or rendered until that succeeds.
const form = document.getElementById('gate');
const input = document.getElementById('password');
const errorEl = document.getElementById('error');
const submitBtn = form.querySelector('button');

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
        render(payload);
    } catch {
        errorEl.textContent = "incorrect password.\nare you sure you're invited?";
        submitBtn.disabled = false;
    }
});
