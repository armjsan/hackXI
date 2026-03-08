document.getElementById('form-a').addEventListener('submit', async () => {
    const btn = document.getElementById('btn-a');
    const errorEl = document.getElementById('error-a');
    btn.disabled = true;
    errorEl.style.display = 'none';

    try {
        const res = await fetch('/api/auth/verify-a', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: document.getElementById('username').value,
                password_a: document.getElementById('password_a').value,
            }),
        });
        const data = await res.json();

        if (data.success && data.requires_b) {
            document.getElementById('phase-a').style.display = 'none';
            document.getElementById('phase-b').style.display = 'block';
            document.getElementById('password_b').focus();
        } else if (data.locked) {
            window.location.href = '/locked';
        } else {
            errorEl.textContent = data.error || 'Invalid credentials';
            errorEl.style.display = 'block';
        }
    } catch {
        errorEl.textContent = 'Connection error. Please try again.';
        errorEl.style.display = 'block';
    }
    btn.disabled = false;
});

document.getElementById('form-b').addEventListener('submit', async () => {
    const btn = document.getElementById('btn-b');
    const errorEl = document.getElementById('error-b');
    btn.disabled = true;
    errorEl.style.display = 'none';

    try {
        const res = await fetch('/api/auth/verify-b', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                password_b: document.getElementById('password_b').value,
            }),
        });
        const data = await res.json();

        if (data.success) {
            window.location.href = data.redirect || '/home';
        } else {
            errorEl.textContent = data.error || 'Verification failed';
            errorEl.style.display = 'block';
            // B failure forces restart
            setTimeout(() => {
                document.getElementById('phase-b').style.display = 'none';
                document.getElementById('phase-a').style.display = 'block';
                document.getElementById('password_a').value = '';
                document.getElementById('password_b').value = '';
                document.getElementById('username').focus();
            }, 2000);
        }
    } catch {
        errorEl.textContent = 'Connection error. Please try again.';
        errorEl.style.display = 'block';
    }
    btn.disabled = false;
});
