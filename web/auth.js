(() => {
  let modalEl = null;
  let formEl = null;
  let errorEl = null;
  let userEl = null;
  let passEl = null;
  let loginWaiter = null;
  let isSubmitting = false;

  function ensureModal() {
    if (modalEl) return;

    const wrapper = document.createElement('div');
    wrapper.innerHTML = [
      '<div id="auth-login-overlay" class="auth-overlay" hidden>',
      '  <div class="auth-card" role="dialog" aria-modal="true" aria-labelledby="auth-login-title">',
      '    <div class="auth-title" id="auth-login-title">Authenticate to Continue</div>',
      '    <div class="auth-subtitle">Your session expired. Sign in to continue managing rSwitch.</div>',
      '    <form id="auth-login-form" class="auth-form">',
      '      <div class="form-group">',
      '        <label for="auth-username">Username</label>',
      '        <input id="auth-username" name="username" type="text" autocomplete="username" required>',
      '      </div>',
      '      <div class="form-group">',
      '        <label for="auth-password">Password</label>',
      '        <input id="auth-password" name="password" type="password" autocomplete="current-password" required>',
      '      </div>',
      '      <div id="auth-login-error" class="auth-error" hidden>Invalid username or password</div>',
      '      <div class="auth-actions">',
      '        <button type="submit" class="btn btn-primary auth-submit">Sign In</button>',
      '      </div>',
      '    </form>',
      '  </div>',
      '</div>'
    ].join('');

    document.body.appendChild(wrapper.firstElementChild);
    modalEl = document.getElementById('auth-login-overlay');
    formEl = document.getElementById('auth-login-form');
    errorEl = document.getElementById('auth-login-error');
    userEl = document.getElementById('auth-username');
    passEl = document.getElementById('auth-password');

    formEl.addEventListener('submit', onLoginSubmit);
  }

  function showLoginError(message) {
    if (!errorEl) return;
    errorEl.textContent = message || 'Login failed';
    errorEl.hidden = false;
  }

  function hideLoginError() {
    if (errorEl) errorEl.hidden = true;
  }

  async function onLoginSubmit(event) {
    event.preventDefault();
    if (!loginWaiter || isSubmitting) return;

    isSubmitting = true;
    hideLoginError();

    try {
      const resp = await fetch('/api/auth/login', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: userEl.value,
          password: passEl.value
        })
      });

      if (resp.ok) {
        modalEl.hidden = true;
        loginWaiter.resolve(true);
        loginWaiter = null;
        passEl.value = '';
        return;
      }

      let msg = 'Invalid username or password';
      try {
        const body = await resp.json();
        if (body && body.error) msg = body.error;
      } catch (_) {}
      showLoginError(msg);
    } catch (_) {
      showLoginError('Unable to reach authentication endpoint');
    } finally {
      isSubmitting = false;
    }
  }

  function showLoginModal() {
    ensureModal();
    hideLoginError();
    modalEl.hidden = false;

    if (!loginWaiter) {
      loginWaiter = {};
      loginWaiter.promise = new Promise((resolve) => {
        loginWaiter.resolve = resolve;
      });
    }

    setTimeout(() => {
      if (userEl.value) passEl.focus();
      else userEl.focus();
    }, 0);

    return loginWaiter.promise;
  }

  async function apiFetch(url, opts = {}) {
    const reqOpts = Object.assign({}, opts, {
      credentials: opts.credentials || 'same-origin'
    });

    let resp = await fetch(url, reqOpts);
    if (resp.status !== 401) return resp;

    const loginOk = await showLoginModal();
    if (!loginOk) return resp;

    resp = await fetch(url, reqOpts);
    return resp;
  }

  async function authLogout() {
    try {
      await apiFetch('/api/auth/logout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}'
      });
    } finally {
      window.location.reload();
    }
  }

  function setupHtmxAuth() {
    if (typeof htmx === 'undefined') return;

    htmx.config.withCredentials = true;

    document.body.addEventListener('htmx:configRequest', (event) => {
      if (event.detail) event.detail.credentials = 'same-origin';
    });

    document.body.addEventListener('htmx:responseError', async (event) => {
      const xhr = event.detail && event.detail.xhr;
      if (!xhr || xhr.status !== 401) return;

      event.preventDefault();

      const ok = await showLoginModal();
      if (!ok) return;

      const triggerEl = event.detail.elt;
      if (triggerEl) htmx.trigger(triggerEl, 'click');
    });
  }

  window.apiFetch = apiFetch;
  window.showLoginModal = showLoginModal;
  window.authLogout = authLogout;

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      ensureModal();
      setupHtmxAuth();
    });
  } else {
    ensureModal();
    setupHtmxAuth();
  }
})();
