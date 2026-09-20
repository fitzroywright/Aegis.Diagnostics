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


function installAegisConsoleAudio(){
  const key='aegis.console.sound',enabled=()=>localStorage.getItem(key)!=='off';
  let ctx=null;
  function tone(freq,duration,volume=.045,delay=0){
    if(!enabled())return;
    try{
      ctx=ctx||new (window.AudioContext||window.webkitAudioContext)();
      if(ctx.state==='suspended')ctx.resume();
      const t=ctx.currentTime+delay,o=ctx.createOscillator(),g=ctx.createGain();
      o.type='sine';o.frequency.setValueAtTime(freq,t);
      g.gain.setValueAtTime(0,t);g.gain.linearRampToValueAtTime(volume,t+.004);g.gain.exponentialRampToValueAtTime(.0001,t+duration);
      o.connect(g);g.connect(ctx.destination);o.start(t);o.stop(t+duration+.02);
    }catch{}
  }
  const cues={
    navigation:()=>{tone(1046.5,.026,.035);tone(1318.5,.031,.03,.035)},
    success:()=>{tone(659.3,.035,.035);tone(987.8,.04,.038,.047);tone(1318.5,.043,.032,.097)},
    warning:()=>{tone(587.3,.06,.045);tone(493.9,.072,.045,.095)},
    critical:()=>{tone(392,.08,.055);tone(329.6,.085,.055,.11);tone(261.6,.115,.06,.225)},
    complete:()=>{tone(784,.045,.032);tone(932.3,.045,.032,.05);tone(1174.7,.035,.03,.105)}
  };
  window.aegisAudio={play:name=>cues[name]?.(),enabled};
  const arm=document.querySelector('.workspace-arm');
  if(arm&&!document.getElementById('soundToggle')){
    const b=document.createElement('button');b.id='soundToggle';b.type='button';b.className='sound-toggle';
    const paint=()=>{b.innerHTML=enabled()?'<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 9v6h4l5 4V5L8 9H4zm11.5 3a3.5 3.5 0 0 0-1.5-2.87v5.74A3.5 3.5 0 0 0 15.5 12zm0-7.1v2.06a7 7 0 0 1 0 10.08v2.06a9 9 0 0 0 0-14.2z"/></svg>':'<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 9v6h4l5 4V5L8 9H4zm11.2.8 1.4 1.4 1.4-1.4 1.4 1.4-1.4 1.4 1.4 1.4-1.4 1.4-1.4-1.4-1.4 1.4-1.4-1.4 1.4-1.4-1.4-1.4 1.4-1.4z"/></svg>';b.title=enabled()?'Sound on':'Sound off';b.setAttribute('aria-label',b.title);b.setAttribute('aria-pressed',String(enabled()))};paint();
    b.onclick=()=>{localStorage.setItem(key,enabled()?'off':'on');paint();if(enabled())cues.success()};
    arm.appendChild(b);
  }
  document.querySelectorAll('.top-buttons a,.workspace-nav a,.lcars-back').forEach(x=>x.addEventListener('pointerdown',()=>cues.navigation()));
}
installAegisConsoleAudio();
