const expenseCategories = ['Food', 'Transport', 'Housing', 'Utilities', 'Health', 'Shopping', 'Education', 'Entertainment', 'Other'];
const incomeCategories = ['Salary', 'Freelance', 'Gift', 'Other'];
const categoryColors = ['#d98566', '#6e9ca0', '#789276', '#e2bd69', '#a58eae', '#d49a56', '#7393b7', '#a9ae62', '#9a8b7b'];
const state = { user: null, csrf: '', transactions: [], budget: 180000, security: null, page: 'overview', editingId: null, toastTimer: null, securityDialogMode: null };
const $ = (selector, parent = document) => parent.querySelector(selector);
const money = cents => new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: 0 }).format(cents / 100);
const exactMoney = cents => new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(cents / 100);
const dateFormat = value => new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric', year: 'numeric' }).format(new Date(`${value}T12:00:00`));
const escapeText = value => String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
const localDate = (value = new Date()) => `${value.getFullYear()}-${String(value.getMonth() + 1).padStart(2, '0')}-${String(value.getDate()).padStart(2, '0')}`;

async function request(url, options = {}) {
  const headers = { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) };
  if (options.mutate && state.csrf) headers['X-CSRF-Token'] = state.csrf;
  const response = await fetch(url, { ...options, headers, credentials: 'same-origin' });
  const data = await response.json().catch(() => ({}));
  if (response.status === 401 && !['/api/login', '/api/register', '/api/login/totp'].includes(url)) {
    state.user = null;
    showAuth();
  }
  if (!response.ok) throw new Error(data.error || 'Something went wrong. Please try again.');
  return data;
}

function showToast(message) {
  const toast = $('#toast');
  toast.textContent = message;
  toast.classList.add('visible');
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => toast.classList.remove('visible'), 2800);
}

function showAuth() {
  $('#app-view').hidden = true;
  $('#auth-view').hidden = false;
  $('#auth-form').reset();
  $('#auth-form').hidden = false;
  $('#totp-login-form').reset();
  $('#totp-login-form').hidden = true;
  $('#auth-switch').hidden = false;
  $('#demo-note').hidden = false;
  state.csrf = '';
  $('#auth-error').hidden = true;
}

function showApp() {
  $('#auth-view').hidden = true;
  $('#app-view').hidden = false;
  $('#avatar').textContent = state.user.name.trim().charAt(0).toUpperCase();
  $('#today-label').textContent = new Intl.DateTimeFormat('en-US', { weekday: 'short', month: 'short', day: 'numeric' }).format(new Date());
  renderPage();
}

async function loadApp() {
  const data = await request('/api/bootstrap');
  state.user = data.user;
  state.csrf = data.csrf_token;
  state.transactions = data.transactions;
  state.budget = data.budget_cents;
  state.security = null;
  showApp();
}

function currentMonthTransactions() {
  const month = localDate().slice(0, 7);
  return state.transactions.filter(transaction => transaction.date.slice(0, 7) === month);
}

function getTotals(items) {
  return items.reduce((totals, transaction) => {
    totals[transaction.kind] += transaction.amount_cents;
    return totals;
  }, { expense: 0, income: 0 });
}

function pageHeading(eyebrow, title, description, actions = '') {
  return `<div class="page-heading"><div><p class="eyebrow">${eyebrow}</p><h1>${title}</h1><p class="subheading">${description}</p></div><div class="heading-actions">${actions}</div></div>`;
}

function metric(label, value, foot, footClass = '') {
  return `<article class="metric"><div class="metric-label">${label}</div><div class="metric-value">${value}</div><div class="metric-foot ${footClass}">${foot}</div></article>`;
}

function transactionRows(transactions, withActions = false) {
  if (!transactions.length) return `<tr><td colspan="${withActions ? 5 : 4}" class="empty-state">No transactions yet. Add your first one to get started.</td></tr>`;
  return transactions.map(item => `<tr>
    <td>${escapeText(item.title)}${item.note ? `<div class="panel-caption">${escapeText(item.note)}</div>` : ''}</td>
    <td>${dateFormat(item.date)}</td><td><span class="pill">${escapeText(item.category)}</span></td>
    <td class="amount ${item.kind}">${item.kind === 'income' ? '+' : '-'}${exactMoney(item.amount_cents)}</td>
    ${withActions ? `<td><div class="table-actions"><button class="row-action" data-edit="${item.id}" type="button">Edit</button><button class="row-action" data-delete="${item.id}" type="button">Delete</button></div></td>` : ''}
  </tr>`).join('');
}

function tablePanel(items, withActions = false, title = 'Recent transactions') {
  return `<section class="panel section-spacer"><div class="panel-header"><div><h2 class="panel-title">${title}</h2><div class="panel-caption">${items.length} ${items.length === 1 ? 'entry' : 'entries'} recorded</div></div>${state.page === 'overview' ? '<button class="text-button" data-page="transactions" type="button">View all &#8594;</button>' : ''}</div><div class="table-wrap"><table class="transaction-table"><thead><tr><th>Description</th><th>Date</th><th>Category</th><th class="text-right">Amount</th>${withActions ? '<th class="text-right">Actions</th>' : ''}</tr></thead><tbody>${transactionRows(items, withActions)}</tbody></table></div></section>`;
}

function monthlyChart() {
  const now = new Date();
  const months = Array.from({ length: 6 }, (_, index) => new Date(now.getFullYear(), now.getMonth() - 5 + index, 1));
  const totals = months.map(month => {
    const key = `${month.getFullYear()}-${String(month.getMonth() + 1).padStart(2, '0')}`;
    return state.transactions.filter(item => item.kind === 'expense' && item.date.startsWith(key)).reduce((sum, item) => sum + item.amount_cents, 0);
  });
  const max = Math.max(...totals, 1);
  return `<div class="chart">${months.map((month, index) => {
    const level = totals[index] ? Math.max(5, Math.min(100, Math.round(totals[index] / max * 20) * 5)) : 0;
    return `<div class="chart-column ${index === 5 ? 'current' : ''}"><div class="bar-track"><span class="bar bar-height-${level}" title="${exactMoney(totals[index])}"></span></div><span class="chart-label">${new Intl.DateTimeFormat('en-US', { month: 'short' }).format(month)}</span></div>`;
  }).join('')}</div>`;
}

function categoryBreakdown(items) {
  const byCategory = new Map();
  items.filter(item => item.kind === 'expense').forEach(item => byCategory.set(item.category, (byCategory.get(item.category) || 0) + item.amount_cents));
  const sorted = [...byCategory.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
  const total = sorted.reduce((sum, entry) => sum + entry[1], 0);
  if (!sorted.length) return '<div class="empty-state">Your spending categories will appear here.</div>';
  return `<div class="category-list">${sorted.map(([category, amount], index) => `<div class="category-row" data-color="${index % categoryColors.length}"><span class="category-dot"></span><span class="category-name">${escapeText(category)}</span><span class="category-amount">${money(amount)}</span><progress class="category-meta" max="100" value="${Math.round(amount / total * 100)}" aria-label="${escapeText(category)} share"></progress></div>`).join('')}</div>`;
}

function renderOverview() {
  const monthItems = currentMonthTransactions();
  const totals = getTotals(monthItems);
  const remaining = state.budget - totals.expense;
  const savings = totals.income ? Math.round((totals.income - totals.expense) / totals.income * 100) : 0;
  const percent = state.budget ? Math.min(100, Math.round(totals.expense / state.budget * 100)) : 0;
  const actions = '<button class="button button-outline" data-export type="button">Export CSV</button><button class="button button-primary" data-add type="button">+ Add transaction</button>';
  return `${pageHeading('YOUR FINANCIAL SNAPSHOT', `Hello, ${escapeText(state.user.name.split(' ')[0])}.`, 'Here is how your money is moving this month.', actions)}
    <section class="metric-grid" aria-label="Monthly summary">
      ${metric('SPENT THIS MONTH', money(totals.expense), `${monthItems.filter(item => item.kind === 'expense').length} purchases recorded`)}
      ${metric('BUDGET REMAINING', money(remaining), remaining >= 0 ? `${percent}% of monthly budget used` : 'You are over your monthly budget', remaining >= 0 ? 'positive' : 'warning')}
      ${metric('INCOME THIS MONTH', money(totals.income), `${monthItems.filter(item => item.kind === 'income').length} income ${monthItems.filter(item => item.kind === 'income').length === 1 ? 'entry' : 'entries'}`, 'positive')}
      ${metric('SAVINGS RATE', `${savings}%`, totals.income ? 'Income minus spending' : 'Add income to see your rate')}
    </section>
    <section class="dashboard-grid">
      <article class="panel"><div class="panel-header"><div><h2 class="panel-title">Spending over time</h2><div class="panel-caption">Monthly expenses, last six months</div></div><span class="pill">USD</span></div><div class="chart-wrap">${monthlyChart()}</div><div class="panel-footer"><span>Each bar is one month of spending</span><span>Current month highlighted</span></div></article>
      <article class="panel"><div class="panel-header"><div><h2 class="panel-title">Where it goes</h2><div class="panel-caption">Top spending categories this month</div></div></div>${categoryBreakdown(monthItems)}<div class="panel-footer"><span>Monthly budget</span><span>${money(state.budget)}</span></div><div class="budget-line"><div class="budget-values"><strong>${money(totals.expense)}</strong><span>of ${money(state.budget)}</span></div><progress class="budget-progress ${percent >= 100 ? 'over' : ''}" max="100" value="${percent}" aria-label="Monthly budget used"></progress><div class="budget-caption"><span>${Math.max(0, 100 - percent)}% remaining</span><button class="text-button" data-page="settings" type="button">Adjust budget</button></div></div></article>
    </section>
    ${tablePanel(state.transactions.slice(0, 5))}`;
}

function renderTransactions() {
  const actions = '<button class="button button-outline" data-export type="button">Export CSV</button><button class="button button-primary" data-add type="button">+ Add transaction</button>';
  return `${pageHeading('YOUR LEDGER', 'Transactions', 'A searchable record of your income and spending.', actions)}
    <section class="panel"><div class="panel-header"><div><h2 class="panel-title">All activity</h2><div class="panel-caption" id="result-count">${state.transactions.length} entries</div></div><div class="filters"><input id="search-transactions" type="search" placeholder="Search transactions" aria-label="Search transactions"><select id="filter-kind" aria-label="Filter by transaction type"><option value="all">All types</option><option value="expense">Expenses</option><option value="income">Income</option></select><select id="filter-category" aria-label="Filter by category"><option value="all">All categories</option>${[...new Set([...expenseCategories, ...incomeCategories])].map(category => `<option>${category}</option>`).join('')}</select></div></div><div class="table-wrap"><table class="transaction-table"><thead><tr><th>Description</th><th>Date</th><th>Category</th><th class="text-right">Amount</th><th class="text-right">Actions</th></tr></thead><tbody id="transaction-results">${transactionRows(state.transactions, true)}</tbody></table></div></section>`;
}

function renderSettings() {
  return `${pageHeading('PREFERENCES', 'Settings', 'Set a spending target and review how this app protects your data.')}
    <div class="settings-layout"><section class="panel settings-section"><p class="eyebrow">MONTHLY PLAN</p><h2>Spending budget</h2><p>Your budget is compared with expenses dated in the current calendar month. It is a planning guide, not a bank restriction.</p><form id="budget-form" class="budget-form"><label>Monthly limit <span class="field-hint">USD</span><input name="amount" type="number" min="0.01" max="1000000" step="0.01" value="${(state.budget / 100).toFixed(2)}" required></label><button class="button button-primary" type="submit">Save budget</button></form></section>
    <section class="panel settings-section"><p class="eyebrow">SECURITY & PRIVACY</p><h2>Built to keep your data yours</h2><p>This local project demonstrates practical security controls for a personal finance app.</p><div class="security-list"><div class="security-item"><div><strong>Passwords are hashed</strong>PBKDF2-HMAC-SHA256 with a unique salt; plaintext passwords are never stored.</div></div><div class="security-item"><div><strong>Sessions stay on the server</strong>Random, expiring session IDs use HttpOnly and SameSite cookies.</div></div><div class="security-item"><div><strong>Changes require a CSRF token</strong>Mutating API requests validate a session token and same-origin requests.</div></div><div class="security-item"><div><strong>Queries are parameterized</strong>SQLite statements separate user input from SQL commands.</div></div><div class="security-item"><div><strong>Records are account-scoped</strong>Each query checks ownership before reading, editing, or deleting a transaction.</div></div></div></section></div>`;
}

function renderSecurity() {
  const security = state.security;
  const actions = '<button class="button button-outline" data-refresh-security type="button">Refresh activity</button>';
  if (!security) return `${pageHeading('ACCOUNT PROTECTION', 'Security', 'Recent sign-ins, account alerts, and two-factor authentication.', actions)}<section class="panel empty-state">Loading security activity...</section>`;
  const labels = {
    'account.created': 'Account created', 'login.success': 'Successful sign-in',
    'login.failure': 'Unsuccessful sign-in', 'login.challenge_started': 'Second-factor challenge started',
    'logout': 'Signed out', 'transaction.created': 'Transaction added',
    'transaction.updated': 'Transaction edited', 'transaction.deleted': 'Transaction deleted',
    'budget.updated': 'Budget changed', 'totp.setup_started': 'Two-factor setup started',
    'totp.enabled': 'Two-factor enabled', 'totp.disabled': 'Two-factor disabled',
    'totp.enrollment_failed': 'Two-factor enrollment rejected',
    'totp.disable_rejected': 'Two-factor change rejected',
    'totp.setup_rejected': 'Two-factor setup rejected',
    'request.origin_rejected': 'Request origin rejected', 'request.csrf_rejected': 'Security token rejected',
    'security.alert_acknowledged': 'Security alert reviewed',
  };
  const alerts = security.alerts.length ? security.alerts.map(alert => `<div class="security-alert"><span class="severity-dot severity-${escapeText(alert.severity)}"></span><div><div class="security-alert-title">${escapeText(alert.summary)}</div><div class="panel-caption">${dateFormat(alert.created_at.slice(0, 10))} · ${escapeText(alert.severity)}</div>${alert.acknowledged_at ? '<span class="alert-reviewed">Reviewed</span>' : `<button class="row-action alert-acknowledge" data-ack-alert="${alert.id}" type="button">Mark reviewed</button>`}</div></div>`).join('') : '<div class="empty-state">No security alerts.</div>';
  const events = security.events.length ? security.events.map(event => `<tr><td>${escapeText(labels[event.event_type] || 'Security event')}</td><td><span class="severity-label severity-${escapeText(event.severity)}">${escapeText(event.severity)}</span></td><td>${dateFormat(event.occurred_at.slice(0, 10))}</td></tr>`).join('') : '<tr><td colspan="3" class="empty-state">Security activity will appear here.</td></tr>';
  const totpAction = security.totp_enabled
    ? '<button class="button button-outline" data-totp-disable type="button">Turn off two-factor</button>'
    : '<button class="button button-primary" data-totp-enable type="button">Set up two-factor</button>';
  return `${pageHeading('ACCOUNT PROTECTION', 'Security', 'Recent sign-ins, account alerts, and two-factor authentication.', actions)}
    <section class="metric-grid security-metrics" aria-label="Security summary">
      ${metric('FAILED SIGN-INS · 24H', String(security.failed_login_24h), 'For this account', security.failed_login_24h ? 'warning' : '')}
      ${metric('SUCCESSFUL SIGN-INS · 24H', String(security.successful_login_24h), 'Password and second-factor verified')}
      ${metric('OPEN ALERTS', String(security.open_alerts), 'Recent suspicious activity', security.open_alerts ? 'warning' : 'positive')}
      ${metric('TWO-FACTOR AUTH', security.totp_enabled ? 'Enabled' : 'Off', security.totp_enabled ? 'Authenticator required at sign-in' : 'Optional account protection', security.totp_enabled ? 'positive' : '')}
    </section>
    <section class="security-layout">
      <article class="panel"><div class="panel-header"><div><h2 class="panel-title">Recent account activity</h2><div class="panel-caption">Sign-ins and changes to this account only</div></div></div><div class="table-wrap"><table class="transaction-table security-events-table"><thead><tr><th>Activity</th><th>Severity</th><th>Date</th></tr></thead><tbody>${events}</tbody></table></div></article>
      <div class="security-side-column"><article class="panel"><div class="panel-header"><div><h2 class="panel-title">Security alerts</h2><div class="panel-caption">Repeated failures and rejected request patterns</div></div></div><div class="security-alert-list">${alerts}</div></article>
      <article class="panel totp-panel"><div class="panel-header"><div><h2 class="panel-title">Two-factor authentication</h2><div class="panel-caption">Time-based one-time password (TOTP)</div></div></div><div class="settings-section"><p>${security.totp_enabled ? 'A current authenticator code or recovery code is required at sign-in.' : 'Use an authenticator app for an additional sign-in check. Your existing login continues to work until enrollment is confirmed.'}</p>${totpAction}<p class="panel-caption totp-guidance">Recovery codes are shown once during setup. Store them offline; they are not sent by email.</p></div></article></div>
    </section>`;
}

async function refreshSecurity() {
  state.security = null;
  renderPage();
  try {
    state.security = await request('/api/security/summary');
    if (state.page === 'security') renderPage();
  } catch (error) { showToast(error.message); }
}

function renderPage() {
  const content = $('#page-content');
  $('#breadcrumb-page').textContent = state.page.toUpperCase();
  document.querySelectorAll('.nav-item').forEach(button => button.classList.toggle('active', button.dataset.page === state.page));
  content.innerHTML = state.page === 'overview' ? renderOverview() : state.page === 'transactions' ? renderTransactions() : state.page === 'security' ? renderSecurity() : renderSettings();
  if (state.page === 'transactions') bindFilters();
  if (state.page === 'settings') $('#budget-form').addEventListener('submit', saveBudget);
}

function bindFilters() {
  const apply = () => {
    const query = $('#search-transactions').value.trim().toLowerCase();
    const kind = $('#filter-kind').value;
    const category = $('#filter-category').value;
    const filtered = state.transactions.filter(item => (kind === 'all' || item.kind === kind) && (category === 'all' || item.category === category) && `${item.title} ${item.note} ${item.category}`.toLowerCase().includes(query));
    $('#transaction-results').innerHTML = transactionRows(filtered, true);
    $('#result-count').textContent = `${filtered.length} of ${state.transactions.length} entries`;
  };
  $('#search-transactions').addEventListener('input', apply);
  $('#filter-kind').addEventListener('change', apply);
  $('#filter-category').addEventListener('change', apply);
}

function setAuthMode(register) {
  $('#auth-form').dataset.mode = register ? 'register' : 'login';
  $('#name-field').hidden = !register;
  $('#auth-title').textContent = register ? 'Create your account' : 'Welcome back';
  $('#auth-subtitle').textContent = register ? 'Start with a private, local money dashboard.' : 'Sign in to pick up where you left off.';
  $('#auth-eyebrow').textContent = register ? 'A FRESH START' : 'YOUR MONEY, IN FOCUS';
  $('#auth-switch-copy').textContent = register ? 'Already have an account?' : 'New here?';
  $('#auth-switch').textContent = register ? 'Sign in' : 'Create an account';
  $('#auth-submit').innerHTML = register ? 'Create account <span aria-hidden="true">&#8594;</span>' : 'Sign in <span aria-hidden="true">&#8594;</span>';
  $('#auth-form').elements.password.autocomplete = register ? 'new-password' : 'current-password';
  $('#auth-error').hidden = true;
}

function openTransaction(item = null) {
  state.editingId = item ? item.id : null;
  const form = $('#transaction-form');
  form.reset();
  form.elements.title.value = item?.title || '';
  form.elements.amount.value = item ? (item.amount_cents / 100).toFixed(2) : '';
  form.elements.kind.value = item?.kind || 'expense';
  updateCategories();
  form.elements.category.value = item?.category || 'Food';
  form.elements.date.value = item?.date || localDate();
  form.elements.note.value = item?.note || '';
  $('#dialog-title').textContent = item ? 'Edit transaction' : 'Add transaction';
  $('#dialog-eyebrow').textContent = item ? 'UPDATE ENTRY' : 'NEW ENTRY';
  $('#save-transaction').textContent = item ? 'Save changes' : 'Save transaction';
  $('#transaction-error').hidden = true;
  $('#transaction-dialog').showModal();
  form.elements.title.focus();
}

function updateCategories() {
  const select = $('#category-select');
  const current = select.value;
  const options = $('#transaction-form').elements.kind.value === 'income' ? incomeCategories : expenseCategories;
  select.replaceChildren(...options.map(category => {
    const option = document.createElement('option');
    option.value = category;
    option.textContent = category;
    return option;
  }));
  if (options.includes(current)) select.value = current;
}

function openSecurityDialog(mode, content) {
  state.securityDialogMode = mode;
  $('#security-dialog-content').innerHTML = content;
  $('#security-dialog').showModal();
  $('#security-dialog-content').querySelector('input')?.focus();
}

function openTotpSetup() {
  openSecurityDialog('totp-setup', `<div class="dialog-heading"><div><p class="eyebrow">TWO-FACTOR AUTHENTICATION</p><h2>Confirm your password</h2></div><button class="icon-button" data-security-close type="button" aria-label="Close dialog">&#10005;</button></div><p class="muted">Re-enter your password to begin setting up an authenticator.</p><div id="security-dialog-error" class="form-error" role="alert" hidden></div><label>Password<input name="password" type="password" autocomplete="current-password" maxlength="128" required></label><div class="dialog-actions"><button class="button button-muted" data-security-close type="button">Cancel</button><button class="button button-primary" type="submit">Continue</button></div>`);
}

function showTotpConfirmation(data) {
  state.totpSetupSecret = data.secret;
  state.securityDialogMode = 'totp-confirm';
  $('#security-dialog-content').innerHTML = `<div class="dialog-heading"><div><p class="eyebrow">TWO-FACTOR AUTHENTICATION</p><h2>Add to your authenticator</h2></div><button class="icon-button" data-security-close type="button" aria-label="Close dialog">&#10005;</button></div><p class="muted">Add this account manually in your authenticator app. This setup secret is shown once; confirm with the current six-digit code.</p><div class="totp-secret"><span>SETUP SECRET</span><code>${escapeText(data.secret)}</code></div><p class="totp-uri-label">Manual setup URI</p><code class="totp-uri">${escapeText(data.otpauth_uri)}</code><div id="security-dialog-error" class="form-error" role="alert" hidden></div><label>Authenticator code<input name="code" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="000000" required></label><div class="dialog-actions"><button class="button button-muted" data-security-close type="button">Cancel</button><button class="button button-primary" type="submit">Verify and enable</button></div>`;
  $('#security-dialog-content').querySelector('input').focus();
}

function showRecoveryCodes(codes) {
  state.securityDialogMode = 'recovery-codes';
  state.recoveryCodes = codes;
  $('#security-dialog-content').innerHTML = `<div class="dialog-heading"><div><p class="eyebrow">SAVE THESE NOW</p><h2>Recovery codes</h2></div></div><p class="muted">Each code works once if you lose your authenticator. Store these somewhere private and offline. They will not be shown again.</p><ol class="recovery-code-list">${codes.map(code => `<li><code>${escapeText(code)}</code></li>`).join('')}</ol><div class="dialog-actions"><button class="button button-outline" data-download-recovery type="button">Download codes</button><button class="button button-primary" data-security-finish type="button">Done</button></div>`;
}

function openTotpDisable() {
  openSecurityDialog('totp-disable', `<div class="dialog-heading"><div><p class="eyebrow">TWO-FACTOR AUTHENTICATION</p><h2>Turn off two-factor</h2></div><button class="icon-button" data-security-close type="button" aria-label="Close dialog">&#10005;</button></div><p class="muted">Confirm your password and a current authenticator or unused recovery code. Existing sessions stay active.</p><div id="security-dialog-error" class="form-error" role="alert" hidden></div><label>Password<input name="password" type="password" autocomplete="current-password" maxlength="128" required></label><label>Authenticator or recovery code<input name="code" type="text" autocomplete="one-time-code" maxlength="64" required></label><div class="dialog-actions"><button class="button button-muted" data-security-close type="button">Cancel</button><button class="button button-primary" type="submit">Turn off</button></div>`);
}

function downloadRecoveryCodes() {
  if (!state.recoveryCodes) return;
  const content = `Smart Expense Tracker recovery codes\nKeep these codes private. Each code can be used once.\n\n${state.recoveryCodes.join('\n')}\n`;
  const url = URL.createObjectURL(new Blob([content], { type: 'text/plain;charset=utf-8' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = 'spennywise-recovery-codes.txt';
  link.click();
  URL.revokeObjectURL(url);
}

$('#security-dialog-form').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = form.querySelector('button[type="submit"]');
  const mode = state.securityDialogMode;
  submit.disabled = true;
  try {
    if (mode === 'totp-setup') {
      const data = await request('/api/security/totp/setup', {
        method: 'POST', body: JSON.stringify({ password: form.elements.password.value }), mutate: true,
      });
      showTotpConfirmation(data);
    } else if (mode === 'totp-confirm') {
      const data = await request('/api/security/totp/confirm', {
        method: 'POST', body: JSON.stringify({ code: form.elements.code.value }), mutate: true,
      });
      showRecoveryCodes(data.recovery_codes);
    } else if (mode === 'totp-disable') {
      await request('/api/security/totp/disable', {
        method: 'POST', body: JSON.stringify({ password: form.elements.password.value, code: form.elements.code.value }), mutate: true,
      });
      $('#security-dialog').close();
      showToast('Two-factor authentication turned off.');
    }
  } catch (error) {
    const errorElement = $('#security-dialog-error');
    if (errorElement) {
      errorElement.textContent = error.message;
      errorElement.hidden = false;
    } else showToast(error.message);
  } finally {
    const currentSubmit = form.querySelector('button[type="submit"]');
    if (currentSubmit) currentSubmit.disabled = false;
  }
});

function csvCell(value) {
  let text = String(value ?? '');
  if (/^[\s\u0000-\u001f]*[=+@\-]/.test(text)) text = `'${text}`;
  return `"${text.replaceAll('"', '""')}"`;
}

function exportCsv() {
  const rows = [['Description', 'Date', 'Category', 'Type', 'Amount USD', 'Note'], ...state.transactions.map(item => [item.title, item.date, item.category, item.kind, (item.amount_cents / 100).toFixed(2), item.note])];
  const csv = rows.map(row => row.map(csvCell).join(',')).join('\r\n');
  const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = `spennywise-transactions-${localDate()}.csv`;
  link.click();
  URL.revokeObjectURL(url);
  showToast('Your CSV export is ready.');
}

async function saveBudget(event) {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button');
  button.disabled = true;
  try {
    const data = await request('/api/budget', { method: 'PATCH', body: JSON.stringify({ amount: event.currentTarget.elements.amount.value }), mutate: true });
    state.budget = data.budget_cents;
    showToast('Monthly budget updated.');
  } catch (error) { showToast(error.message); }
  finally { button.disabled = false; }
}

document.addEventListener('click', async event => {
  const pageButton = event.target.closest('[data-page]');
  if (pageButton) {
    state.page = pageButton.dataset.page;
    renderPage();
    if (state.page === 'security') void refreshSecurity();
    return;
  }
  if (event.target.closest('[data-refresh-security]')) { await refreshSecurity(); return; }
  const acknowledgeButton = event.target.closest('[data-ack-alert]');
  if (acknowledgeButton) {
    try {
      await request(`/api/security/alerts/${acknowledgeButton.dataset.ackAlert}/acknowledge`, {
        method: 'POST', body: '{}', mutate: true,
      });
      await refreshSecurity();
    } catch (error) { showToast(error.message); }
    return;
  }
  if (event.target.closest('[data-totp-enable]')) { openTotpSetup(); return; }
  if (event.target.closest('[data-totp-disable]')) { openTotpDisable(); return; }
  if (event.target.closest('[data-download-recovery]')) { downloadRecoveryCodes(); return; }
  if (event.target.closest('[data-security-finish]')) { $('#security-dialog').close(); return; }
  if (event.target.closest('[data-security-close]')) { $('#security-dialog').close(); return; }
  if (event.target.closest('[data-add]')) { openTransaction(); return; }
  if (event.target.closest('[data-export]')) { exportCsv(); return; }
  const editButton = event.target.closest('[data-edit]');
  if (editButton) {
    const item = state.transactions.find(transaction => transaction.id === Number(editButton.dataset.edit));
    if (item) openTransaction(item);
    return;
  }
  const deleteButton = event.target.closest('[data-delete]');
  if (deleteButton) {
    const item = state.transactions.find(transaction => transaction.id === Number(deleteButton.dataset.delete));
    if (!item || !confirm(`Delete "${item.title}"? This cannot be undone.`)) return;
    try {
      await request(`/api/transactions/${item.id}`, { method: 'DELETE', mutate: true });
      state.transactions = state.transactions.filter(transaction => transaction.id !== item.id);
      renderPage();
      showToast('Transaction deleted.');
    } catch (error) { showToast(error.message); }
  }
});

$('#auth-switch').addEventListener('click', () => setAuthMode($('#auth-form').dataset.mode !== 'register'));
$('#demo-fill').addEventListener('click', () => {
  setAuthMode(false);
  $('#auth-form').elements.email.value = 'demo@example.com';
  $('#auth-form').elements.password.value = 'DemoPass!2026';
  $('#auth-form').elements.password.focus();
});

$('#auth-form').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const register = form.dataset.mode === 'register';
  const payload = { email: form.elements.email.value, password: form.elements.password.value };
  if (register) payload.name = form.elements.name.value;
  const submit = $('#auth-submit');
  submit.disabled = true;
  try {
    const data = await request(register ? '/api/register' : '/api/login', { method: 'POST', body: JSON.stringify(payload) });
    if (data.requires_totp) {
      state.csrf = data.csrf_token;
      $('#auth-form').hidden = true;
      $('#totp-login-form').hidden = false;
      $('#auth-switch').hidden = true;
      $('#demo-note').hidden = true;
      $('#auth-eyebrow').textContent = 'SECOND FACTOR REQUIRED';
      $('#auth-title').textContent = 'Verify it is you';
      $('#auth-subtitle').textContent = 'Enter a current authenticator code or an unused recovery code.';
      $('#totp-login-form').elements.code.focus();
      return;
    }
    state.user = data.user;
    state.csrf = data.csrf_token;
    await loadApp();
  } catch (error) {
    $('#auth-error').textContent = error.message;
    $('#auth-error').hidden = false;
  } finally { submit.disabled = false; }
});

$('#totp-login-form').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = form.querySelector('button[type="submit"]');
  submit.disabled = true;
  try {
    const data = await request('/api/login/totp', {
      method: 'POST', body: JSON.stringify({ code: form.elements.code.value }), mutate: true,
    });
    state.user = data.user;
    state.csrf = data.csrf_token;
    form.reset();
    await loadApp();
  } catch (error) {
    if (error.message.toLowerCase().includes('challenge expired')) {
      showAuth();
      setAuthMode(false);
    }
    $('#auth-error').textContent = error.message;
    $('#auth-error').hidden = false;
    form.elements.code.select();
  } finally { submit.disabled = false; }
});

$('#logout-button').addEventListener('click', async () => {
  try { await request('/api/logout', { method: 'POST', body: '{}', mutate: true }); } catch {}
  state.user = null;
  state.csrf = '';
  state.transactions = [];
  state.security = null;
  showAuth();
  setAuthMode(false);
});

$('#security-dialog').addEventListener('click', event => {
  if (event.target === $('#security-dialog')) $('#security-dialog').close();
});

$('#security-dialog').addEventListener('close', () => {
  state.totpSetupSecret = null;
  state.recoveryCodes = null;
  state.securityDialogMode = null;
  $('#security-dialog-content').replaceChildren();
  if (state.page === 'security' && state.user) void refreshSecurity();
});

$('#transaction-form').elements.kind.addEventListener('change', updateCategories);
$('#dialog-close').addEventListener('click', () => $('#transaction-dialog').close());
$('#dialog-cancel').addEventListener('click', () => $('#transaction-dialog').close());
$('#transaction-form').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = {
    title: form.elements.title.value,
    amount: form.elements.amount.value,
    kind: form.elements.kind.value,
    category: form.elements.category.value,
    date: form.elements.date.value,
    note: form.elements.note.value,
  };
  const save = $('#save-transaction');
  save.disabled = true;
  try {
    const url = state.editingId ? `/api/transactions/${state.editingId}` : '/api/transactions';
    const data = await request(url, { method: state.editingId ? 'PATCH' : 'POST', body: JSON.stringify(payload), mutate: true });
    if (state.editingId) state.transactions = state.transactions.map(item => item.id === state.editingId ? data.transaction : item);
    else state.transactions.unshift(data.transaction);
    $('#transaction-dialog').close();
    renderPage();
    showToast(state.editingId ? 'Transaction updated.' : 'Transaction saved.');
  } catch (error) {
    $('#transaction-error').textContent = error.message;
    $('#transaction-error').hidden = false;
  } finally { save.disabled = false; }
});

async function start() {
  $('#today-label').textContent = new Intl.DateTimeFormat('en-US', { weekday: 'short', month: 'short', day: 'numeric' }).format(new Date());
  setAuthMode(false);
  updateCategories();
  try {
    const session = await request('/api/session');
    if (session.user) {
      state.user = session.user;
      state.csrf = session.csrf_token;
      await loadApp();
    } else showAuth();
  } catch { showAuth(); }
}

start();