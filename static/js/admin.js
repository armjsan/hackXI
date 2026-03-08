// Tab switching
document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById('tab-' + tab.dataset.tab).classList.add('active');

        if (tab.dataset.tab === 'tickets') loadTickets();
        if (tab.dataset.tab === 'users') loadUsers();
        if (tab.dataset.tab === 'events') loadEvents();
        if (tab.dataset.tab === 'recovery') loadRecoveryUsers();
        if (tab.dataset.tab === 'settings') loadSettings();
    });
});

// Load initial data
loadUsers();
loadTicketCount();

// ---- Tickets ----

async function loadTickets() {
    try {
        const res = await fetch('/api/admin/tickets');
        const tickets = await res.json();
        const body = document.getElementById('tickets-body');
        const table = document.getElementById('tickets-table');
        const empty = document.getElementById('tickets-empty');

        if (tickets.length === 0) {
            table.style.display = 'none';
            empty.style.display = 'block';
        } else {
            table.style.display = '';
            empty.style.display = 'none';
            body.innerHTML = tickets.map(t => `
                <tr>
                    <td>${t.created_at}</td>
                    <td><strong>${esc(t.username)}</strong></td>
                    <td>${esc(t.email)}</td>
                    <td>${esc(t.description)}</td>
                    <td>
                        <button class="btn btn-sm btn-primary" onclick="acknowledgeTicket(${t.id})">Acknowledge</button>
                    </td>
                </tr>
            `).join('');
        }
        updateTicketCount(tickets.length);
    } catch { }
}

async function loadTicketCount() {
    try {
        const res = await fetch('/api/admin/tickets');
        const tickets = await res.json();
        updateTicketCount(tickets.length);
    } catch { }
}

function updateTicketCount(count) {
    const badge = document.getElementById('ticket-count');
    const ticketTab = document.querySelector('[data-tab="tickets"]');
    if (count > 0) {
        badge.textContent = count + ' pending';
        badge.style.display = 'inline-block';
        ticketTab.textContent = `Tickets (${count})`;
    } else {
        badge.style.display = 'none';
        ticketTab.textContent = 'Tickets';
    }
}

async function acknowledgeTicket(eventId) {
    try {
        await fetch(`/api/admin/tickets/${eventId}/acknowledge`, { method: 'POST' });
        loadTickets();
    } catch { }
}

// ---- Users ----

async function loadUsers() {
    try {
        const res = await fetch('/api/admin/users');
        const users = await res.json();
        const body = document.getElementById('users-body');
        body.innerHTML = users.map(u => `
            <tr>
                <td><strong>${esc(u.username)}</strong></td>
                <td>${esc(u.email)}</td>
                <td>${u.is_locked
                    ? '<span class="status-badge badge-locked">Locked</span>'
                    : '<span class="status-badge badge-active">Active</span>'
                }</td>
                <td>${u.failed_a_count}</td>
                <td>${u.failed_b_count}</td>
                <td>${u.is_first_login
                    ? '<span class="status-badge badge-warning">Yes</span>'
                    : 'No'
                }</td>
                <td>${u.is_admin ? 'Yes' : 'No'}</td>
                <td>${u.created_at}</td>
                <td>
                    <button class="btn btn-sm btn-outline" onclick="viewUserEvents(${u.id})">Events</button>
                </td>
            </tr>
        `).join('');
    } catch { }
}

// ---- Events ----

async function loadEvents(userId) {
    try {
        const filter = document.getElementById('event-filter').value;
        let url = '/api/admin/events?per_page=100';
        if (filter) url += '&event_type=' + filter;
        if (userId) url += '&user_id=' + userId;
        const res = await fetch(url);
        const events = await res.json();
        const body = document.getElementById('events-body');
        body.innerHTML = events.map(e => {
            let rowClass = '';
            if (e.event_type === 'B_FAIL' || e.event_type === 'A_LOCKOUT' || e.event_type === 'DUMMY_REUSE') rowClass = 'row-danger';
            else if (e.event_type === 'A_FAIL') rowClass = 'row-warning';
            else if (e.event_type === 'LOGIN_SUCCESS' || e.event_type === 'PASSWORD_CHANGED') rowClass = 'row-success';
            return `
                <tr class="${rowClass}">
                    <td>${e.created_at}</td>
                    <td>${esc(e.username)}</td>
                    <td><span class="status-badge ${badgeClass(e.event_type)}">${e.event_type}</span></td>
                    <td>${esc(e.description)}</td>
                    <td>${e.ip_address || '-'}</td>
                </tr>
            `;
        }).join('');
    } catch { }
}

function viewUserEvents(userId) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.querySelector('[data-tab="events"]').classList.add('active');
    document.getElementById('tab-events').classList.add('active');
    loadEvents(userId);
}

// ---- Recovery ----

async function loadRecoveryUsers() {
    try {
        const res = await fetch('/api/admin/users');
        const users = await res.json();
        users.sort((a, b) => b.is_locked - a.is_locked);
        const sel = document.getElementById('recovery-user');
        sel.innerHTML = users.map(u =>
            `<option value="${u.id}">${esc(u.username)} ${u.is_locked ? '(LOCKED)' : ''}</option>`
        ).join('');
    } catch { }
}

async function verifyToken() {
    const userId = document.getElementById('recovery-user').value;
    const token = document.getElementById('recovery-token').value.trim();
    const resultEl = document.getElementById('token-result');
    const resetForm = document.getElementById('reset-form');

    if (!token) { showResult(resultEl, 'Please enter the token', true); return; }

    try {
        const res = await fetch('/api/admin/verify-token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_id: parseInt(userId), token_c: token }),
        });
        const data = await res.json();
        if (data.valid) {
            showResult(resultEl, 'Token verified successfully!', false);
            resetForm.style.display = 'block';
        } else {
            showResult(resultEl, 'Invalid token. Verification failed.', true);
            resetForm.style.display = 'none';
        }
    } catch {
        showResult(resultEl, 'Connection error', true);
    }
}

async function resetUser() {
    const userId = document.getElementById('recovery-user').value;
    const newA = document.getElementById('new-a').value;
    const newB = document.getElementById('new-b').value;
    const resultEl = document.getElementById('reset-result');

    if (!newA || !newB) { showResult(resultEl, 'Both passwords are required', true); return; }
    if (newA.length < 8) { showResult(resultEl, 'Password A must be at least 8 characters', true); return; }

    try {
        const res = await fetch('/api/admin/reset-user', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                user_id: parseInt(userId),
                new_password_a: newA,
                new_password_b: newB,
            }),
        });
        const data = await res.json();
        if (data.success) {
            resultEl.className = 'success-msg';
            resultEl.innerHTML = `Account reset successfully!<br><strong>New Token C:</strong> ${esc(data.new_token_c)}<br><em>Save this token - it will not be shown again.</em>`;
            resultEl.style.display = 'block';
            document.getElementById('new-a').value = '';
            document.getElementById('new-b').value = '';
            document.getElementById('recovery-token').value = '';
            loadUsers();
        } else {
            showResult(resultEl, data.error, true);
        }
    } catch {
        showResult(resultEl, 'Connection error', true);
    }
}

// ---- Settings ----

async function loadSettings() {
    try {
        const res = await fetch('/api/admin/settings');
        const s = await res.json();
        document.getElementById('set-max-a-attempts').value = s.max_failed_a_attempts || 5;
        document.getElementById('set-max-b-attempts').value = s.max_failed_b_attempts || 3;
        document.getElementById('set-smtp-enabled').checked = s.smtp_enabled === 'true';
        document.getElementById('set-smtp-server').value = s.smtp_server || '';
        document.getElementById('set-smtp-port').value = s.smtp_port || 587;
        document.getElementById('set-smtp-username').value = s.smtp_username || '';
        document.getElementById('set-smtp-password').value = s.smtp_password || '';
        document.getElementById('set-smtp-from').value = s.smtp_from_email || '';
        document.getElementById('set-admin-email').value = s.admin_email || '';
    } catch { }
}

async function saveSettings() {
    const resultEl = document.getElementById('settings-result');
    try {
        const res = await fetch('/api/admin/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                max_failed_a_attempts: document.getElementById('set-max-a-attempts').value,
                max_failed_b_attempts: document.getElementById('set-max-b-attempts').value,
                smtp_enabled: document.getElementById('set-smtp-enabled').checked ? 'true' : 'false',
                smtp_server: document.getElementById('set-smtp-server').value,
                smtp_port: document.getElementById('set-smtp-port').value,
                smtp_username: document.getElementById('set-smtp-username').value,
                smtp_password: document.getElementById('set-smtp-password').value,
                smtp_from_email: document.getElementById('set-smtp-from').value,
                admin_email: document.getElementById('set-admin-email').value,
            }),
        });
        const data = await res.json();
        if (data.success) {
            showResult(resultEl, 'Settings saved successfully!', false);
        }
    } catch {
        showResult(resultEl, 'Connection error', true);
    }
}

// ---- Create User Modal ----

function showCreateModal() {
    document.getElementById('create-modal').style.display = 'flex';
    document.getElementById('create-error').style.display = 'none';
    document.getElementById('create-success').style.display = 'none';
    document.getElementById('new-username').value = '';
    document.getElementById('new-email').value = '';
    document.getElementById('new-pass-b').value = '';
}

function hideCreateModal() {
    document.getElementById('create-modal').style.display = 'none';
}

async function createUser() {
    const errEl = document.getElementById('create-error');
    const successEl = document.getElementById('create-success');
    errEl.style.display = 'none';
    successEl.style.display = 'none';

    const body = {
        username: document.getElementById('new-username').value.trim(),
        email: document.getElementById('new-email').value.trim(),
        password_b: document.getElementById('new-pass-b').value,
    };

    if (!body.username || !body.email || !body.password_b) {
        errEl.textContent = 'All fields are required';
        errEl.style.display = 'block';
        return;
    }

    try {
        const res = await fetch('/api/admin/create-user', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        const data = await res.json();
        if (data.success) {
            successEl.className = 'success-msg';
            successEl.innerHTML =
                `User created!<br>` +
                `<strong>Temporary Password A:</strong> ${esc(data.dummy_password_a)}<br>` +
                `<strong>Token C:</strong> ${esc(data.token_c)}<br>` +
                `<em>Save these credentials - they will not be shown again.<br>` +
                `The user must change Password A on first login.</em>`;
            successEl.style.display = 'block';
            loadUsers();
            loadTicketCount();
        } else {
            errEl.textContent = data.error;
            errEl.style.display = 'block';
        }
    } catch {
        errEl.textContent = 'Connection error';
        errEl.style.display = 'block';
    }
}

// ---- Admin Logout ----

async function adminLogout() {
    await fetch('/api/admin/logout', { method: 'POST' });
    window.location.href = '/admin/login';
}

// ---- Helpers ----

function esc(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
}

function badgeClass(type) {
    if (type === 'B_FAIL' || type === 'A_LOCKOUT' || type === 'DUMMY_REUSE') return 'badge-locked';
    if (type === 'A_FAIL') return 'badge-warning';
    if (type === 'LOGIN_SUCCESS' || type === 'PASSWORD_CHANGED') return 'badge-active';
    if (type === 'USER_CREATED') return 'badge-warning';
    return '';
}

function showResult(el, msg, isError) {
    el.className = isError ? 'error-msg' : 'success-msg';
    el.textContent = msg;
    el.style.display = 'block';
}
