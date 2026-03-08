document.getElementById('register-form').addEventListener('submit', async () => {
    const btn = document.getElementById('btn-reg');
    const errEl = document.getElementById('error-reg');
    btn.disabled = true;
    errEl.style.display = 'none';

    const email = document.getElementById('reg-email').value.trim();
    const passwordA = document.getElementById('reg-password-a').value;
    const confirm = document.getElementById('reg-confirm').value;

    if (!email || !passwordA) {
        errEl.textContent = 'All fields are required';
        errEl.style.display = 'block';
        btn.disabled = false;
        return;
    }
    if (passwordA.length < 8) {
        errEl.textContent = 'Password must be at least 8 characters';
        errEl.style.display = 'block';
        btn.disabled = false;
        return;
    }
    if (passwordA !== confirm) {
        errEl.textContent = 'Passwords do not match';
        errEl.style.display = 'block';
        btn.disabled = false;
        return;
    }

    try {
        const res = await fetch('/api/auth/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password_a: passwordA }),
        });
        const data = await res.json();

        if (data.success) {
            document.getElementById('register-form-container').style.display = 'none';
            document.getElementById('register-success').style.display = 'block';
        } else {
            errEl.textContent = data.error || 'Registration failed';
            errEl.style.display = 'block';
        }
    } catch {
        errEl.textContent = 'Connection error. Please try again.';
        errEl.style.display = 'block';
    }
    btn.disabled = false;
});
