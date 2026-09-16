(() => {
  let identity = null;
  let timeoutMs = 15 * 60 * 1000;
  let lastActivity = Date.now();
  let signedOut = false;

  const activityEvents = ['pointerdown', 'pointermove', 'keydown', 'touchstart', 'scroll'];
  const markActivity = () => { lastActivity = Date.now(); };
  activityEvents.forEach(name => window.addEventListener(name, markActivity, { passive: true }));

  const redirectToLogin = () => {
    const returnUrl = encodeURIComponent(location.pathname + location.search + location.hash);
    location.replace('/login?returnUrl=' + returnUrl);
  };

  async function refreshIdentity() {
    const response = await fetch('/auth/me', { cache: 'no-store' });
    if (response.status === 401) {
      redirectToLogin();
      return null;
    }
    if (!response.ok) throw new Error('Unable to refresh authenticated session.');
    identity = await response.json();
    timeoutMs = Math.max(5, Number(identity.idleTimeoutMinutes || 15)) * 60 * 1000;
    const name = document.getElementById('userName');
    const title = document.getElementById('userTitle');
    const session = document.getElementById('sessionInfo');
    if (name) name.textContent = identity.displayName || identity.userName || 'Signed in';
    if (title) title.textContent = identity.title || 'User';
    if (session) session.textContent = `Automatic sign-out after ${identity.idleTimeoutMinutes || 15} minutes of inactivity`;
    return identity;
  }

  async function signOut(reason) {
    if (signedOut) return;
    signedOut = true;
    try { await fetch('/auth/logout', { method: 'POST', cache: 'no-store' }); } catch { }
    const suffix = reason ? `&reason=${encodeURIComponent(reason)}` : '';
    location.replace('/login?returnUrl=' + encodeURIComponent(location.pathname) + suffix);
  }

  window.aegisSession = {
    get identity() { return identity; },
    refresh: refreshIdentity,
    signOut: () => signOut('manual'),
    requirePermission(permission) {
      return !!identity?.permissions?.some(x => String(x).toLowerCase() === permission.toLowerCase());
    }
  };

  document.addEventListener('click', event => {
    const button = event.target.closest('[data-signout]');
    if (button) {
      event.preventDefault();
      signOut('manual');
    }
  });

  refreshIdentity().catch(redirectToLogin);

  setInterval(() => {
    if (signedOut) return;
    const idleFor = Date.now() - lastActivity;
    if (idleFor >= timeoutMs) {
      signOut('inactive');
      return;
    }
    // Keep the signed cookie alive only while the operator remains active.
    if (idleFor < Math.min(timeoutMs, 2 * 60 * 1000)) {
      refreshIdentity().catch(redirectToLogin);
    }
  }, 60 * 1000);
})();
