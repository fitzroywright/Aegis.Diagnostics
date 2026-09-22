(() => {
  let identity = null;
  let timeoutMs = 30 * 60 * 1000;
  let lastActivity = Date.now();
  let signedOut = false;

  const activityEvents = ['pointerdown', 'pointermove', 'keydown', 'touchstart', 'scroll'];
  const markActivity = () => { lastActivity = Date.now(); };
  activityEvents.forEach(name => window.addEventListener(name, markActivity, { passive: true }));

  const redirectToLogin = () => {
    const returnUrl = encodeURIComponent(location.pathname + location.search + location.hash);
    location.replace('/auth/sso?returnUrl=' + returnUrl);
  };

  async function refreshIdentity() {
    const response = await fetch('/auth/me', { cache: 'no-store' });
    if (response.status === 401) {
      redirectToLogin();
      return null;
    }
    if (!response.ok) throw new Error('Unable to refresh authenticated session.');
    identity = await response.json();
    timeoutMs = Math.max(5, Number(identity.idleTimeoutMinutes || 30)) * 60 * 1000;
    const name = document.getElementById('userName');
    const title = document.getElementById('userTitle');
    const session = document.getElementById('sessionInfo');
    if (name) name.textContent = identity.displayName || identity.userName || 'Signed in';
    if (title) title.textContent = identity.title || 'User';
    if (session) session.textContent = `Automatic sign-out after ${identity.idleTimeoutMinutes || 30} minutes of inactivity`;
    const brandUser=document.getElementById('brandUser');
    if(brandUser)brandUser.textContent='User: '+(identity.displayName||identity.userName||'Signed in')+' · IP: '+(identity.clientIp||'unknown');
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
    navigation:()=>{tone(1174.7,.025,.032);tone(1568,.032,.028,.032)},
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

async function refreshControlPlaneHealthBanner(){
  const host=document.querySelector('.detail-scroll');if(!host)return;
  let banner=document.getElementById('systemHealth')||document.getElementById('controlPlaneHealthBanner');
  if(!banner){banner=document.createElement('section');banner.id='controlPlaneHealthBanner';banner.className='control-plane-health-banner';host.prepend(banner);}
  if(!banner.classList.contains('control-plane-health-banner'))banner.classList.add('control-plane-health-banner');
  try{
    const response=await fetch('/health',{cache:'no-store'});
    if(!response.ok)throw new Error('HTTP '+response.status);
    const health=await response.json(),state=String(health.health||health.status||'Unknown'),summary=String(health.summary||'Health check returned no summary.').trim(),lower=state.toLowerCase();
    if(lower==='healthy'){banner.style.display='none';banner.classList.remove('critical','health-unavailable');return;}
    banner.classList.toggle('critical',lower==='unhealthy');
    banner.classList.remove('health-unavailable');
    banner.innerHTML='<strong>'+state.toUpperCase()+'</strong><div>'+String(summary).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]))+'</div>';
    banner.style.display='block';
  }catch(error){
    banner.classList.remove('critical');banner.classList.add('health-unavailable');
    banner.innerHTML='<strong>HEALTH CHECK UNAVAILABLE</strong><div>'+String(error?.message||'Unable to read /health.')+'</div>';
    banner.style.display='block';
  }
}
refreshControlPlaneHealthBanner();setInterval(refreshControlPlaneHealthBanner,30000);

function normalizedRegisteredHealth(o){
  const raw=o?.health??o?.state??o?.status??'unknown';
  const value=String(raw).trim().toLowerCase();
  if(value==='1')return 'healthy';
  if(value==='2')return 'degraded';
  if(value==='3')return 'unhealthy';
  if(value==='0')return 'unknown';
  return value;
}
async function refreshRegisteredApplicationHealth(){
  const host=document.querySelector('.detail-scroll');if(!host)return;
  let banner=document.getElementById('registeredApplicationHealthBanner');
  if(!banner){banner=document.createElement('section');banner.id='registeredApplicationHealthBanner';banner.className='control-plane-health-banner';const own=document.getElementById('controlPlaneHealthBanner')||document.getElementById('systemHealth');own?.insertAdjacentElement('afterend',banner)??host.prepend(banner);}
  try{
    const response=await fetch('/api/engineering/diagnostics/status',{cache:'no-store'});
    if(!response.ok)throw new Error('HTTP '+response.status);
    const data=await response.json(),observations=data.observations||[];
    const issues=observations.filter(o=>!['healthy','passed'].includes(normalizedRegisteredHealth(o)));
    if(!issues.length){banner.style.display='none';return;}
    const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
    banner.classList.toggle('critical',issues.some(o=>['unhealthy','failed','critical','error'].includes(normalizedRegisteredHealth(o))));
    banner.innerHTML='<strong>REGISTERED APPLICATION HEALTH · '+issues.length+' ISSUE'+(issues.length===1?'':'S')+'</strong><div>'+issues.slice(0,8).map(o=>esc(o.applicationId||o.application||o.name||'Application')+' — '+esc(o.state||o.status||o.health||'Unknown')+(o.reason||o.summary||o.detail?' · '+esc(o.reason||o.summary||o.detail):'')).join('<br>')+(issues.length>8?'<br>+'+(issues.length-8)+' more':'')+'</div>';
    banner.style.display='block';
  }catch{banner.style.display='none';}
}
refreshRegisteredApplicationHealth();setInterval(refreshRegisteredApplicationHealth,30000);
