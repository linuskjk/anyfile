(function () {
  const input = document.getElementById('file-input');
  const info = document.getElementById('file-info');
  const uploadBtn = document.getElementById('upload-button');
  const clearBtn = document.getElementById('clear-button');
  const publishBtn = document.getElementById('publish-button');
  const list = document.getElementById('file-list');
  const totalEl = document.getElementById('total-size');
  const statusEl = document.getElementById('upload-status');
  const progressEl = document.getElementById('upload-progress');
  const progressBar = progressEl ? progressEl.querySelector('.bar') : null;
  const cancelBtn = document.getElementById('upload-cancel');
  let currentXHR = null;
  const offlinePanel = document.getElementById('api-offline');
  const apiBaseInput = document.getElementById('api-base-input');
  const apiBaseApply = document.getElementById('api-base-apply');
  const apiProbeStatus = document.getElementById('api-probe-status');
  const recentList = document.getElementById('recent-list');
  const recentStatus = document.getElementById('recent-status');
  const uploadLabel = document.querySelector('.custom-file-upload');
  const dropzone = document.getElementById('dropzone');
  const publishPBtn = document.getElementById('publish-p-button');
  const whitelistInput = document.getElementById('whitelist-password');
  const whitelistApply = document.getElementById('whitelist-apply');
  const whitelistStatus = document.getElementById('whitelist-status');
  const expireSelect = document.getElementById('expire-select');
  const expireHint = document.getElementById('expire-hint');
  const expireDownloadCheckbox = document.getElementById('expire-on-download');
  const quotaStatus = document.getElementById('quota-status');
  let overrideFiles = null; // used by drag-and-drop when DataTransfer assignment isn't supported
  const STANDARD_MAX_DAYS = 7;
  const STANDARD_DAILY_LIMIT = 1024 * 1024 * 1024; // 1 GB
  let whitelistPass = '';
  let lastTier = 'standard';
  let lastQuotaSnapshot = null;
  const pendingOneTimeRemovals = new Set();
  let pendingRemovalTimer = null;
  let pendingRemovalAttempts = 0;
  const PENDING_REMOVAL_POLL_INTERVAL = 5000;
  const PENDING_REMOVAL_MAX_ATTEMPTS = 60;
  let recentLoading = false;
  let recentReloadRequested = false;
  let latestRecentFiles = [];


  function getCookie(name) {
    const m = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/([.$?*|{}()\[\]\\\/\+^])/g,'\\$1') + '=([^;]*)'));
    return m ? decodeURIComponent(m[1]) : undefined;
  }

  function bytesToSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  function pollPendingRemovals() {
    pendingRemovalTimer = null;
    if (!pendingOneTimeRemovals.size) {
      pendingRemovalAttempts = 0;
      return;
    }
    pendingRemovalAttempts++;
    loadRecent();
    if (pendingOneTimeRemovals.size && pendingRemovalAttempts < PENDING_REMOVAL_MAX_ATTEMPTS) {
      pendingRemovalTimer = setTimeout(pollPendingRemovals, PENDING_REMOVAL_POLL_INTERVAL);
    } else if (!pendingOneTimeRemovals.size) {
      pendingRemovalAttempts = 0;
    }
  }

  function schedulePendingRemovalPoll(resetAttempts = false) {
    if (!pendingOneTimeRemovals.size) return;
    if (resetAttempts) pendingRemovalAttempts = 0;
    if (pendingRemovalTimer) return;
    pendingRemovalTimer = setTimeout(pollPendingRemovals, PENDING_REMOVAL_POLL_INTERVAL);
  }

  function trackPendingOneTimeRemoval(storedName) {
    if (!storedName) return;
    pendingOneTimeRemovals.add(storedName);
    schedulePendingRemovalPoll(true);
  }

  function handleRecentListUpdate(files) {
    if (!Array.isArray(files)) {
      return;
    }
    latestRecentFiles = files;
    if (!pendingOneTimeRemovals.size) return;
    const present = new Set(latestRecentFiles.map(f => f && f.storedName).filter(Boolean));
    let removedAny = false;
    for (const id of Array.from(pendingOneTimeRemovals)) {
      if (!present.has(id)) {
        pendingOneTimeRemovals.delete(id);
        removedAny = true;
      }
    }
    if (!pendingOneTimeRemovals.size && pendingRemovalTimer) {
      clearTimeout(pendingRemovalTimer);
      pendingRemovalTimer = null;
      pendingRemovalAttempts = 0;
    } else if (removedAny) {
      pendingRemovalAttempts = 0;
    }
  }

  window.addEventListener('focus', () => {
    if (pendingOneTimeRemovals.size) {
      loadRecent();
    }
  });

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && pendingOneTimeRemovals.size) {
      loadRecent();
    }
  });

  function resolveShareUrl(path, preferFilesSubdomain = false) {
    if (!path) return '';
    if (/^https?:\/\//i.test(path)) return path;
    if (!path.startsWith('/')) return path;
    let base = '';
    if (preferFilesSubdomain) {
      const host = location.hostname;
      const parts = host.split('.');
      if (!/^files\./i.test(host) && parts.length >= 2) {
        base = `${location.protocol}//files.${parts.slice(-2).join('.')}`;
      } else {
        base = location.origin;
      }
    } else {
      if (API_BASE) {
        try {
          const url = new URL(API_BASE);
          base = `${url.protocol}//${url.host}`;
        } catch (_) {
          base = API_BASE;
        }
      }
      if (!base) {
        base = location.origin;
      }
    }
    return base.replace(/\/$/, '') + path;
  }

  function pickShareUrl(payload) {
    if (!payload) return '';
    if (payload.deleteAfterDownload) {
      const landing = payload.landingAbsoluteUrl || payload.landingUrl;
      if (landing) {
        return resolveShareUrl(landing, true);
      }
    }
  const candidate = payload.absoluteUrl || payload.downloadAbsoluteUrl || payload.shortUrl || payload.shareUrl || payload.downloadUrl || payload.url || '';
    if (!candidate) return '';
    return resolveShareUrl(candidate, !!payload.deleteAfterDownload);
  }

  function updateWhitelistStatus(message, isError) {
    if (!whitelistStatus) return;
    whitelistStatus.textContent = message || '';
    if (isError) whitelistStatus.classList.add('error');
    else whitelistStatus.classList.remove('error');
  }

  function updateExpireHint(tier) {
    if (!expireHint) return;
    if (tier === 'premium') {
      expireHint.textContent = 'Premium: choose any expiry or keep files forever.';
    } else {
      expireHint.textContent = `Standard users: files delete after ${STANDARD_MAX_DAYS} days and have 1 GB/day limit.`;
    }
  }

  function applyTierConstraints(tier) {
    lastTier = tier || 'standard';
    updateExpireHint(lastTier);
    if (!expireSelect) return;
    const options = Array.from(expireSelect.options || []);
    options.forEach(opt => {
      const val = Number(opt.value);
      if (Number.isNaN(val)) return;
      if (lastTier === 'standard' && (val > STANDARD_MAX_DAYS || val === 0)) {
        opt.disabled = true;
      } else {
        opt.disabled = false;
      }
    });
    if (lastTier === 'standard') {
      const currentVal = Number(expireSelect.value);
      if (Number.isNaN(currentVal) || currentVal > STANDARD_MAX_DAYS || currentVal === 0) {
        expireSelect.value = String(STANDARD_MAX_DAYS);
      }
    }
  }

  function handleTierUpdateFromServer(tier) {
    if (!tier) return;
    applyTierConstraints(tier);
    if (whitelistStatus) {
      if (tier === 'premium') {
        updateWhitelistStatus(whitelistPass ? 'Premium password accepted.' : 'Premium tier active.');
      } else {
        if (whitelistPass) {
          updateWhitelistStatus('Password not accepted; using standard tier.', true);
        } else {
          updateWhitelistStatus('Using standard tier.');
        }
      }
    }
    updateQuotaStatus();
  }

  function authHeaders(extra = {}) {
    const headers = { ...extra };
    if (whitelistPass) {
      headers['X-AnySend-Pass'] = whitelistPass;
    }
    return headers;
  }

  function getUploadOptions() {
    const opts = {};
    if (expireSelect) {
      opts.expireDays = expireSelect.value;
    }
    if (expireDownloadCheckbox && expireDownloadCheckbox.checked) {
      opts.deleteAfterDownload = true;
    }
    return opts;
  }

  function updateQuotaStatus(quota) {
    if (!quotaStatus) return;
    if (arguments.length) {
      lastQuotaSnapshot = quota || null;
    }
    const currentTier = lastTier === 'premium' ? 'premium' : 'standard';
    if (currentTier === 'premium') {
      quotaStatus.textContent = 'Tier: Premium — Unlimited uploads (no daily cap).';
      return;
    }
    const snapshot = lastQuotaSnapshot;
    if (snapshot && snapshot.limit != null) {
      const usedBytes = Number(snapshot.used) || 0;
      const limitBytes = Number(snapshot.limit) || 0;
      const remainingBytes = Number(snapshot.remaining);
      const used = bytesToSize(Math.max(0, usedBytes));
      const limit = limitBytes ? bytesToSize(Math.max(0, limitBytes)) : '—';
      const remaining = Number.isFinite(remainingBytes) ? bytesToSize(Math.max(0, remainingBytes)) : '—';
      let text = 'Tier: Standard — Daily quota ';
      if (snapshot.identifierType === 'ip') {
        text += '(per IP address)';
      } else {
        text += '(per user)';
      }
      text += `: ${used}`;
      if (limit !== '—') {
        text += ` used of ${limit}`;
      }
      if (remaining !== '—') {
        text += ` (remaining ${remaining})`;
      }
      if (snapshot.identifierType === 'ip' && snapshot.identifier) {
        text += ` — Tracking IP: ${snapshot.identifier}`;
      }
      if (snapshot.day) {
        text += ` — Tracking date: ${snapshot.day}`;
      }
      quotaStatus.textContent = text;
      return;
    }
    quotaStatus.textContent = `Tier: Standard — Daily quota tracked by IP address (${bytesToSize(STANDARD_DAILY_LIMIT)}/day).`;
  }

  try {
    const storedPass = localStorage.getItem('anyfile_pass');
    if (storedPass) {
      whitelistPass = storedPass;
      updateWhitelistStatus('Password loaded from storage. Tier will verify on next request.');
    }
  } catch (_) {
    updateWhitelistStatus('Could not read saved password.', true);
  }

  applyTierConstraints(lastTier);
  updateQuotaStatus(null);

  if (whitelistApply) {
    whitelistApply.addEventListener('click', () => {
      const val = (whitelistInput && whitelistInput.value ? whitelistInput.value : '').trim();
      whitelistPass = val;
      try {
        if (val) {
          localStorage.setItem('anyfile_pass', val);
          updateWhitelistStatus('Password saved. Tier will update after next request.');
        } else {
          localStorage.removeItem('anyfile_pass');
          updateWhitelistStatus('Password cleared.');
          applyTierConstraints('standard');
        }
      } catch (e) {
        updateWhitelistStatus('Failed to store password locally.', true);
      }
    });
  }

  if (whitelistInput) {
    whitelistInput.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter') {
        ev.preventDefault();
        whitelistApply && whitelistApply.click();
      }
    });
  }

  function render() {
    const files = overrideFiles ? Array.from(overrideFiles) : (input.files ? Array.from(input.files) : []);
    // Toggle label state based on selection
    const label = input && input.parentElement && input.parentElement.classList
      ? input.parentElement
      : null;
    if (label && label.classList) {
      if (files.length > 0) label.classList.add('has-files');
      else label.classList.remove('has-files');
    }

  // Allow all file types - no client-side restrictions
  const allowedExt = []; // Empty array = allow everything
  let invalidCount = 0;
  let total = 0;

    // Build list early so we can mark invalid entries
    list.innerHTML = '';
    files.forEach(f => {
      const li = document.createElement('li');
      let reason = '';
      const name = f.name || 'file';
      const extMatch = name.toLowerCase().match(/\.([a-z0-9]+)$/);
      const ext = extMatch ? extMatch[1] : '';
      total += f.size;
      // No file type restrictions - allow everything
      // if (!allowedExt.includes(ext)) {
      //   reason = 'type not allowed';
      // }
      if (reason) {
        invalidCount++;
        li.classList.add('invalid');
      }
  // Row content with name + size
  const title = document.createElement('div');
  title.textContent = name + ' — ' + bytesToSize(f.size);
  li.appendChild(title);
  // Per-file progress container (hidden until upload starts)
  const pf = document.createElement('div');
  pf.className = 'file_progress';
  const pbar = document.createElement('div');
  pbar.className = 'bar';
  pf.appendChild(pbar);
  pf.style.display = 'none';
  li.appendChild(pf);
      if (reason) {
        const span = document.createElement('span');
        span.className = 'reason';
        span.textContent = ' (' + reason + ')';
        li.appendChild(span);
      }
      list.appendChild(li);
    });

    if (files.length === 0) {
      info.textContent = 'No file selected';
  uploadBtn.disabled = true;
  clearBtn.disabled = true;
  if (publishBtn) publishBtn.disabled = true;
    } else if (files.length === 1) {
      info.textContent = '1 file selected';
  uploadBtn.disabled = invalidCount > 0;
  clearBtn.disabled = false;
  if (publishBtn) publishBtn.disabled = invalidCount > 0;
    } else {
      info.textContent = files.length + ' files selected';
  uploadBtn.disabled = invalidCount > 0;
  clearBtn.disabled = false;
  if (publishBtn) publishBtn.disabled = invalidCount > 0;
    }

    totalEl.textContent = 'Total: ' + bytesToSize(total);
    if (invalidCount > 0) {
      setStatus(invalidCount + ' invalid file(s) blocked.', 'error');
    } else if (files.length > 0) {
      setStatus('', '');
    }
  }

  input.addEventListener('change', () => { overrideFiles = null; render(); });

  clearBtn.addEventListener('click', function () {
    // Clearing file inputs requires resetting the value
    input.value = '';
    overrideFiles = null;
    render();
  });

  function setStatus(message, type) {
    statusEl.textContent = message || '';
    statusEl.className = 'upload_status' + (type ? ' ' + type : '');
  }

  // Determine API base: allow override via window.ANYSEND_API_BASE
  let API_BASE = window.ANYSEND_API_BASE || '';
  let apiBaseResolved = false;
  const pathPrefix = (location.pathname.startsWith('/anyfile/') || location.pathname === '/anyfile') ? '/anyfile' : '';

  async function probe(base) {
    try {
      console.log(`Probing API health at: ${base}/api/health`);
  const r = await fetch(base + '/api/health', { cache: 'no-store', credentials: 'include' });
      console.log(`Health probe response: status=${r.status}, content-type=${r.headers.get('Content-Type')}`);
      
      if (!r.ok) {
        console.warn(`Health probe failed with status ${r.status}`);
        return false;
      }
      
      const text = await r.text();
      let js;
      try {
        js = JSON.parse(text);
        console.log('Health probe JSON response:', js);
        return !!(js && js.ok);
      } catch (e) {
        console.error('Failed to parse health probe response as JSON:', text.substring(0, 200));
        return false;
      }
    } catch (err) {
      console.error('Health probe fetch error:', err);
      return false;
    }
  }

  async function ensureApiBase() {
    console.log('Ensuring API base, current state:', { 
      apiBaseResolved, 
      API_BASE, 
      pathPrefix,
      origin: location.origin,
      pathname: location.pathname,
      hostname: location.hostname
    });
    
    if (apiBaseResolved) return API_BASE;
    
    // Check for Synology direct URL in localStorage
    try {
      const synologyDirect = localStorage.getItem('synology_direct');
      if (synologyDirect && !API_BASE) {
        console.log('Using Synology direct URL from localStorage:', synologyDirect);
        // Try direct URL first
        if (await probe(synologyDirect)) {
          API_BASE = synologyDirect;
          apiBaseResolved = true;
          console.log('Synology direct URL probe successful');
          return API_BASE;
        }
      }
    } catch(_) { /* Ignore localStorage errors */ }
    
    // Special handling for anyfile.uk with Cloudflare
    if (location.hostname === 'anyfile.uk' && !API_BASE) {
      // Try upload subdomain (which should bypass Cloudflare)
      const uploadSubdomain = 'https://upload.anyfile.uk';
      console.log('Detected anyfile.uk, trying upload subdomain:', uploadSubdomain);
      if (await probe(uploadSubdomain)) {
        API_BASE = uploadSubdomain;
        apiBaseResolved = true;
        console.log('Upload subdomain probe successful');
        return API_BASE;
      }
      
      // Try api subdomain
      const apiSubdomain = 'https://api.anyfile.uk';
      console.log('Trying API subdomain:', apiSubdomain);
      if (await probe(apiSubdomain)) {
        API_BASE = apiSubdomain;
        apiBaseResolved = true;
        console.log('API subdomain probe successful');
        return API_BASE;
      }
    }
    
    // user pre-set (global) -> probe to be sure
    if (API_BASE) {
      console.log('Testing preset API_BASE:', API_BASE);
      if (await probe(API_BASE)) { apiBaseResolved = true; return API_BASE; }
      // fall through to discovery if preset fails
      console.log('Preset API_BASE failed probe, trying alternatives');
      API_BASE = '';
    }
    const origin = location.origin;
    // If hosted under /anyfile try prefixed path (no base override needed)
    if (pathPrefix) {
      try {
  const r = await fetch(origin + pathPrefix + '/api/health', { cache: 'no-store', credentials: 'include' });
        if (r.ok) { apiBaseResolved = true; return API_BASE; }
      } catch(_){ }
    }
    if (await probe(origin)) { API_BASE = ''; apiBaseResolved = true; return API_BASE; }
    // Try upload.<host> first (bypasses Cloudflare proxy limits)
    const host = location.hostname;
    if (!/^upload\./i.test(host)) {
      const uploadHost = location.protocol + '//' + 'upload.' + host;
      if (await probe(uploadHost)) { API_BASE = uploadHost; apiBaseResolved = true; return API_BASE; }
      // If host is like sub.domain.tld, also attempt upload.<domain.tld>
      const parts1 = host.split('.');
      if (parts1.length > 2) {
        const rootDomain = parts1.slice(parts1.length - 2).join('.');
        const uploadRoot = location.protocol + '//' + 'upload.' + rootDomain;
        if (uploadRoot !== uploadHost && await probe(uploadRoot)) { API_BASE = uploadRoot; apiBaseResolved = true; return API_BASE; }
      }
    }
    // Try https://api.<host> if not already on it
    if (!/^api\./i.test(host)) {
      const apiHost = location.protocol + '//' + 'api.' + host;
      if (await probe(apiHost)) { API_BASE = apiHost; apiBaseResolved = true; return API_BASE; }
      const parts2 = host.split('.');
      if (parts2.length > 2) {
        const rootDomain2 = parts2.slice(parts2.length - 2).join('.');
        const apiRoot = location.protocol + '//' + 'api.' + rootDomain2;
        if (apiRoot !== apiHost && await probe(apiRoot)) { API_BASE = apiRoot; apiBaseResolved = true; return API_BASE; }
      }
    }
    // fallback ports
    const ports = [3000, 5173];
    for (const p of ports) {
      const cand = location.protocol + '//' + location.hostname + ':' + p;
      if (await probe(cand)) { API_BASE = cand; apiBaseResolved = true; return API_BASE; }
    }
    // Show offline panel for manual entry
    if (offlinePanel) offlinePanel.classList.remove('hidden');
    throw { code: 'BACKEND_OFFLINE' };
  }

  apiBaseApply && apiBaseApply.addEventListener('click', async () => {
    const valRaw = (apiBaseInput.value || '').trim();
    if (!valRaw) { apiProbeStatus.textContent = 'Enter a URL first.'; return; }
    // Normalize: remove trailing slash
    let base = valRaw.replace(/\/$/, '');
    apiProbeStatus.textContent = 'Probing…';
    if (!/^https?:\/\//i.test(base)) {
      apiProbeStatus.textContent = 'Must start with http:// or https://';
      return;
    }
    const ok = await probe(base);
    if (ok) {
      API_BASE = base;
      apiBaseResolved = true;
      apiProbeStatus.textContent = 'Connected.';
      setStatus('Connected to ' + base, 'success');
      setTimeout(() => { offlinePanel.classList.add('hidden'); }, 800);
    } else {
      apiProbeStatus.textContent = 'Health check failed (no /api/health).';
    }
  });

  function apiUrl(path) { return (API_BASE ? API_BASE : (pathPrefix || '')) + path; }

  function extractIdFromUrl(u) {
    try {
      const a = document.createElement('a');
      a.href = u;
      const parts = a.pathname.split('/').filter(Boolean);
      return parts[parts.length - 1] || '';
    } catch(_) { return ''; }
  }

  function apiUrl(path) { return (API_BASE ? API_BASE : (pathPrefix || '')) + path; }

  function extractIdFromUrl(u) {
    try {
      const a = document.createElement('a');
      a.href = u;
      const parts = a.pathname.split('/').filter(Boolean);
      // expecting /api/download/<id>
      return parts[parts.length - 1] || '';
    } catch(_) { return ''; }
  }

  async function loadRecent() {
    if (!recentList) return;
    if (recentLoading) {
      recentReloadRequested = true;
      return;
    }
    recentLoading = true;
    recentStatus.textContent = 'Loading recent…';
    try {
    await ensureApiBase();
    const r = await fetch(apiUrl('/api/files?limit=50'), { cache: 'no-store', credentials: 'include', headers: authHeaders() });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const js = await r.json();
      if (!js.ok) throw new Error(js.error || 'LIST_FAILED');
      if (js.tier) {
        handleTierUpdateFromServer(js.tier);
      }
      if (Object.prototype.hasOwnProperty.call(js, 'quota')) {
        updateQuotaStatus(js.quota);
      }
      recentList.innerHTML = '';
      js.files.forEach(f => {
        const li = document.createElement('li');
        li.className = 'recent_item';

        // REPLACE anchor with plain text span (no download on name)
        const nameEl = document.createElement('span');
        nameEl.className = 'file-name';
        nameEl.textContent = f.originalName + ' (' + bytesToSize(f.size) + ')';
        if (f.deleteAfterDownload) {
          const oneTime = document.createElement('span');
          oneTime.className = 'tag-once';
          oneTime.textContent = 'one-time';
          oneTime.title = 'Deletes after first download';
          nameEl.appendChild(oneTime);
        }
        li.appendChild(nameEl);

        // Share button (icon-only)
        const shareBtn = document.createElement('button');
        shareBtn.className = 'icon-btn share-btn';
        shareBtn.setAttribute('aria-label','Share link');
        shareBtn.style.marginLeft = '6px';
        shareBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="none" viewBox="0 0 16 16"><path stroke="#444" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" d="M10.5 4.5l-5 2.5m5 2.5l-5-2.5"/><circle cx="12.5" cy="4.5" r="2" stroke="#444" stroke-width="1.5"/><circle cx="12.5" cy="11.5" r="2" stroke="#444" stroke-width="1.5"/><circle cx="3.5" cy="8" r="2" stroke="#444" stroke-width="1.5"/></svg>';
        shareBtn.addEventListener('click', async () => {
          shareBtn.disabled = true;
          shareBtn.classList.add('busy');
          let sharePayload = null;
          try {
            await ensureApiBase();
            const resp = await fetch(apiUrl('/api/share/' + encodeURIComponent(f.storedName)), { method: 'POST', headers: authHeaders({ 'Content-Type':'application/json' }), body: '{}', credentials: 'include' });
            const jsn = await resp.json().catch(()=>({}));
            if (resp.ok && jsn.ok) {
              sharePayload = jsn;
              if (jsn.deleteAfterDownload) {
                trackPendingOneTimeRemoval(jsn.storedName || f.storedName);
              }
              const full = pickShareUrl(jsn);
              if (full) {
                const res = await shareLink(full, f.originalName);
                if (res.ok) {
                  shareBtn.classList.add('ok');
                  shareBtn.classList.remove('err');
                  setTimeout(() => { shareBtn.classList.remove('ok'); }, 1600);
                } else if (!res.cancelled) {
                  shareBtn.classList.add('err');
                  shareBtn.classList.remove('ok');
                  setTimeout(() => { shareBtn.classList.remove('err'); }, 1500);
                }
              } else {
                shareBtn.classList.add('err');
                shareBtn.classList.remove('ok');
                setTimeout(() => { shareBtn.classList.remove('err'); }, 1500);
              }
            } else {
              shareBtn.classList.add('err');
              setTimeout(()=> shareBtn.classList.remove('err'), 1500);
              setTimeout(() => loadRecent(), 600);
            }
          } catch(e) {
            shareBtn.classList.add('err');
            setTimeout(()=> shareBtn.classList.remove('err'), 1500);
            setTimeout(() => loadRecent(), 600);
          } finally {
            shareBtn.disabled = false;
            shareBtn.classList.remove('busy');
            if (sharePayload && sharePayload.deleteAfterDownload) {
              setTimeout(() => loadRecent(), 600);
            }
          }
        });
        li.appendChild(shareBtn);

        // Delete button
        const delBtn = document.createElement('button');
        delBtn.textContent = 'Delete';
        delBtn.className = 'button-clear'; // match Clear button styling
        delBtn.style.marginLeft = '6px';
        delBtn.addEventListener('click', async () => {
          if (!confirm('Delete this file? This cannot be undone.')) return;
          delBtn.disabled = true;
          try {
            await ensureApiBase();
            const resp = await fetch(apiUrl('/api/files/delete/' + encodeURIComponent(f.storedName)), { method:'POST', headers: authHeaders({'Content-Type':'application/json'}), body:'{}', credentials: 'include' });
            const jsn = await resp.json().catch(()=>({}));
            if (resp.ok && jsn.ok) {
              delBtn.textContent = 'Deleted';
              li.style.opacity = '0.5';
              setTimeout(()=> { loadRecent(); }, 600);
            } else { delBtn.textContent='Error'; setTimeout(()=> delBtn.textContent='Delete', 1500); }
          } catch(e){ delBtn.textContent='Error'; setTimeout(()=> delBtn.textContent='Delete', 1500);} finally { delBtn.disabled=false; }
        });
        li.appendChild(delBtn);

        const meta = document.createElement('span');
        meta.className = 'meta';
        const when = new Date(f.time);
        meta.textContent = ' — ' + when.toLocaleString();
        li.appendChild(meta);
        recentList.appendChild(li);
      });
      recentStatus.textContent = js.files.length ? '' : 'No uploads yet.';
      handleRecentListUpdate(js.files);
    } catch (e) {
      recentStatus.textContent = 'Failed loading recent.';
    } finally {
      recentLoading = false;
      if (recentReloadRequested) {
        recentReloadRequested = false;
        loadRecent();
      }
    }
  }

  // Progress helpers
  function showProgress(pct) {
    if (!progressEl || !progressBar) return;
    progressEl.classList.remove('hidden');
    const clamped = Math.max(0, Math.min(100, Math.round(pct)));
    progressBar.style.width = clamped + '%';
    progressEl.setAttribute('aria-valuenow', String(clamped));
    progressEl.classList.remove('indeterminate');
    if (cancelBtn) cancelBtn.classList.remove('hidden');
  }

  function hideProgress() {
    if (!progressEl || !progressBar) return;
    progressEl.classList.add('hidden');
    progressBar.style.width = '0%';
    progressEl.setAttribute('aria-valuenow', '0');
    progressEl.classList.remove('indeterminate');
    if (cancelBtn) cancelBtn.classList.add('hidden');
  }

  function uploadFiles(files) {
    if (!files.length) return;

    // Compute total bytes for aggregate progress
    const totalBytes = files.reduce((s, f) => s + (f.size || 0), 0) || 0;

    function uploadOne(file, index, loadedBefore) {
      return new Promise((resolve, reject) => {
        const row = list.children[index];
        const pf = row ? row.querySelector('.file_progress') : null;
        const pbar = pf ? pf.querySelector('.bar') : null;
        if (pf) pf.style.display = '';
        if (row) {
          row.classList.add('uploading');
          try { row.style.setProperty('--pf-width', '0%'); } catch(_) {}
        }

        const fd = new FormData();
        fd.append('files', file);
        try {
          fd.append('upload-options', JSON.stringify(getUploadOptions()));
        } catch (_) {
          fd.append('upload-options', '{}');
        }

        const xhr = new XMLHttpRequest();
        currentXHR = xhr;
        xhr.open('POST', apiUrl('/api/upload'));
  xhr.withCredentials = true;
        if (whitelistPass) {
          try { xhr.setRequestHeader('X-AnySend-Pass', whitelistPass); } catch (_) {}
        }

        let lastProgressTs = Date.now();
        let lastPct = 0;
        const heartbeat = setInterval(() => {
          if (xhr.readyState === 4) { clearInterval(heartbeat); return; }
          const idleMs = Date.now() - lastProgressTs;
          if (idleMs > 2000) {
            setStatus('Uploading…', '');
            showProgress(((loadedBefore + (file.size * lastPct / 100)) / Math.max(1, totalBytes)) * 100);
            if (pbar) pbar.style.width = lastPct + '%';
            if (row) try { row.style.setProperty('--pf-width', lastPct + '%'); } catch(_) {}
          }
        }, 1000);

        xhr.upload.addEventListener('progress', (e) => {
          if (e.lengthComputable) {
            const pct = Math.round((e.loaded / e.total) * 100);
            lastPct = pct;
            lastProgressTs = Date.now();
            setStatus('Uploading…', '');
            const aggPct = ((loadedBefore + e.loaded) / Math.max(1, totalBytes)) * 100;
            showProgress(aggPct);
            if (pbar) pbar.style.width = pct + '%';
            if (row) try { row.style.setProperty('--pf-width', pct + '%'); } catch(_) {}
          } else {
            lastProgressTs = Date.now();
            setStatus('Uploading…', '');
            if (progressEl) progressEl.classList.add('indeterminate');
          }
        });

        xhr.onreadystatechange = function () {
          if (xhr.readyState === 4) {
            clearInterval(heartbeat);
            const raw = xhr.responseText || '';
            const ct = (xhr.getResponseHeader('Content-Type') || '').toLowerCase();
            if (!ct.includes('application/json')) {
              return reject({ code: 'BAD_RESPONSE', status: xhr.status, snippet: raw.slice(0, 200) });
            }
            try {
              const json = JSON.parse(raw || '{}');
              if (xhr.status >= 200 && xhr.status < 300 && json.ok) {
                if (row) {
                  try { row.style.setProperty('--pf-width', '100%'); } catch(_) {}
                  row.classList.remove('uploading');
                }
                resolve(json);
              } else {
                if (row) row.classList.remove('uploading');
                reject(json.error ? { code: json.error, status: xhr.status, quota: json.quota, remaining: json.remaining, limit: json.limit, used: json.used } : { code: 'UPLOAD_FAILED', status: xhr.status });
              }
            } catch (err) {
              if (row) row.classList.remove('uploading');
              reject({ code: 'BAD_RESPONSE', status: xhr.status, snippet: raw.slice(0, 200) });
            }
          }
        };

        xhr.onerror = function () { clearInterval(heartbeat); if (row) row.classList.remove('uploading'); reject('NETWORK'); };
        xhr.onabort = function () { clearInterval(heartbeat); if (row) row.classList.remove('uploading'); reject({ code: 'CANCELLED' }); };
        xhr.send(fd);
      });
    }

    return (async () => {
      let uploadedCount = 0;
      let loadedBefore = 0;
      const uploadedFiles = [];
      showProgress(0);
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        try {
          const res = await uploadOne(file, i, loadedBefore);
          uploadedCount += (res.count || 1);
          if (Array.isArray(res.files)) { uploadedFiles.push(...res.files); }
          loadedBefore += file.size || 0;
        } catch (e) {
          if (e && e.code === 'CANCELLED') {
            hideProgress();
            // Throw with partial results so UI can still present completed uploads
            throw { code: 'CANCELLED', partial: { ok: true, count: uploadedCount, files: uploadedFiles } };
          }
          setStatus('Some files failed to upload.', 'error');
          loadedBefore += file.size || 0; // advance to keep aggregate bar sensible
        }
      }
      hideProgress();
      return { ok: true, count: uploadedCount, files: uploadedFiles };
    })();
  }

  uploadBtn.addEventListener('click', function () {
    if (uploadBtn.disabled) return;
    const files = overrideFiles ? Array.from(overrideFiles) : (input.files ? Array.from(input.files) : []);
    if (!files.length) return;
    setStatus('Starting upload…', '');
    showProgress(0);
    uploadBtn.disabled = true;
    clearBtn.disabled = true;

    ensureApiBase()
      .then(() => uploadFiles(files))
      .then(result => {
        setStatus('Uploaded ' + result.count + ' file(s).', 'success');
        hideProgress();
        if (result.tier) {
          handleTierUpdateFromServer(result.tier);
        }
        if (result.quota) {
          updateQuotaStatus(result.quota);
        } else if ((result.tier || lastTier) === 'premium') {
          updateQuotaStatus(null);
        }
        // Show links
        if (Array.isArray(result.files)) {
          const frag = document.createDocumentFragment();
          result.files.forEach(f => {
            const li = document.createElement('li');
            const a = document.createElement('a');
            const dl = f.downloadUrl || f.url;
            a.href = dl;
            a.textContent = f.originalName + ' (' + bytesToSize(f.size) + ')';
            if (f.originalName) a.setAttribute('download', f.originalName);
            a.target = '_blank';
            li.appendChild(a);
            if (f.deleteAfterDownload) {
              const oneTime = document.createElement('span');
              oneTime.className = 'tag-once';
              oneTime.textContent = 'one-time';
              oneTime.title = 'Deletes after first download';
              li.appendChild(oneTime);
            }
            const shareBtn = document.createElement('button');
            shareBtn.className = 'icon-btn share-btn';
            shareBtn.setAttribute('aria-label','Share link');
            shareBtn.style.marginLeft = '6px';
            shareBtn.innerHTML = '<img src="./share.svg" alt="" width="16" height="16" />';
            shareBtn.addEventListener('click', async () => {
              shareBtn.disabled = true;
              shareBtn.classList.add('busy');
              let sharePayload = null;
              try {
                await ensureApiBase();
                const resp = await fetch(apiUrl('/api/share/' + encodeURIComponent(f.storedName)), { method:'POST', headers: authHeaders({'Content-Type':'application/json'}), body:'{}', credentials: 'include' });
                const jsn = await resp.json().catch(()=>({}));
                if (resp.ok && jsn.ok) {
                  sharePayload = jsn;
                  if (jsn.deleteAfterDownload) {
                    trackPendingOneTimeRemoval(jsn.storedName || f.storedName);
                  }
                  const full = pickShareUrl(jsn);
                  if (full) {
                    const res = await shareLink(full, f.originalName);
                    if (res.ok) {
                      shareBtn.classList.add('ok');
                      shareBtn.classList.remove('err');
                      setTimeout(() => shareBtn.classList.remove('ok'), 1600);
                    } else if (!res.cancelled) {
                      shareBtn.classList.add('err');
                      shareBtn.classList.remove('ok');
                      setTimeout(() => shareBtn.classList.remove('err'), 1500);
                    }
                  } else {
                    shareBtn.classList.add('err');
                    shareBtn.classList.remove('ok');
                    setTimeout(() => shareBtn.classList.remove('err'), 1500);
                  }
                } else {
                  shareBtn.classList.add('err');
                  setTimeout(() => shareBtn.classList.remove('err'), 1500);
                  setTimeout(() => loadRecent(), 600);
                }
              } catch(e) {
                shareBtn.classList.add('err');
                setTimeout(() => shareBtn.classList.remove('err'), 1500);
                setTimeout(() => loadRecent(), 600);
              } finally {
                shareBtn.disabled = false;
                shareBtn.classList.remove('busy');
                if (sharePayload && sharePayload.deleteAfterDownload) {
                  setTimeout(() => loadRecent(), 600);
                }
              }
            });
            li.appendChild(shareBtn);
            const delBtn = document.createElement('button');
            delBtn.textContent = 'Delete';
            delBtn.className = 'button-clear'; // match Clear button styling
            delBtn.style.marginLeft = '6px';
            delBtn.addEventListener('click', async () => {
              if (!confirm('Delete this file? This cannot be undone.')) return;
              delBtn.disabled = true;
              try {
                await ensureApiBase();
                const resp = await fetch(apiUrl('/api/files/delete/' + encodeURIComponent(f.storedName)), { method:'POST', headers: authHeaders({'Content-Type':'application/json'}), body:'{}', credentials: 'include' });
                const jsn = await resp.json().catch(()=>({}));
                if (resp.ok && jsn.ok) {
                  delBtn.textContent = 'Deleted';
                  li.style.opacity = '0.5';
                  setTimeout(()=> { loadRecent(); }, 600);
                } else { delBtn.textContent='Error'; setTimeout(()=> delBtn.textContent='Delete', 1500); }
              } catch(e){ delBtn.textContent='Error'; setTimeout(()=> delBtn.textContent='Delete', 1500);} finally { delBtn.disabled=false; }
            });
            li.appendChild(delBtn);
            frag.appendChild(li);
          });
          // Append a separator header
          const header = document.createElement('li');
          header.textContent = 'Uploaded:';
          header.style.fontWeight = 'bold';
          list.appendChild(header);
          list.appendChild(frag);
        }
        // Reset selection after success
        input.value = '';
        overrideFiles = null;
        render();
        loadRecent();
      })
      .catch(err => {
        let msg;
        const errCode = (err && err.code) || err;
        if (err && err.tier) {
          handleTierUpdateFromServer(err.tier);
        }
        if (err && (err.quota || err.limit != null || err.used != null)) {
          const source = err.quota || {};
          const limit = source.limit != null ? source.limit : err.limit;
          const used = source.used != null ? source.used : err.used;
          let remaining = source.remaining != null ? source.remaining : err.remaining;
          if (remaining == null && limit != null && used != null) {
            remaining = Math.max(0, Number(limit) - Number(used));
          }
          const identifier = source.identifier;
          const identifierType = source.identifierType || (identifier ? 'ip' : undefined);
          updateQuotaStatus({ limit, used, remaining, identifier, identifierType, day: source.day });
        }
        switch (errCode) {
          case 'NO_FILES': msg = 'No files received by server.'; break;
          case 'FILE_TOO_LARGE': msg = 'File rejected by server (size).'; break;
          case 'DAILY_LIMIT_EXCEEDED':
            msg = 'Daily quota reached. Try again tomorrow or use a premium password.';
            break;
          case 'UPLOAD_FAILED': msg = 'Upload failed.'; break;
          case 'NETWORK': msg = 'Network error.'; break;
          case 'CANCELLED': msg = 'Upload cancelled.'; break;
          case 'BAD_RESPONSE': {
            const snippet = err && err.snippet ? (' Response snippet: ' + err.snippet.replace(/\s+/g, ' ').trim()) : '';
            msg = 'Server returned invalid JSON (status ' + (err.status || '?') + ').' + snippet;
            break;
          }
          default: msg = 'Error: ' + errCode; break;
        }
        setStatus(msg, 'error');
        hideProgress();
        // If we have partial results (cancelled mid-sequence), show the links we did complete
        if (err && err.partial && Array.isArray(err.partial.files) && err.partial.files.length) {
          const header = document.createElement('li');
          header.textContent = 'Uploaded (before cancel):';
          header.style.fontWeight = 'bold';
          list.appendChild(header);
          const frag = document.createDocumentFragment();
          err.partial.files.forEach(f => {
            const li = document.createElement('li');
            const a = document.createElement('a');
            const dl = f.downloadUrl || f.url;
            a.href = dl;
            a.textContent = f.originalName + ' (' + bytesToSize(f.size) + ')';
            if (f.originalName) a.setAttribute('download', f.originalName);
            a.target = '_blank';
            li.appendChild(a);
            frag.appendChild(li);
          });
          list.appendChild(frag);
        }
      })
      .finally(() => {
        render();
      });
  });
  // Cancel current upload if possible
  cancelBtn && cancelBtn.addEventListener('click', function(){
    try { currentXHR && currentXHR.abort(); } catch(_) {}
  });

  // --- Simplified publish to /p directory ---
  async function handlePublishPClick() {
    const name = (siteNameInput && siteNameInput.value || '').trim().toLowerCase();
    const files = overrideFiles ? Array.from(overrideFiles) : (input.files ? Array.from(input.files) : []);
    if (!files.length) { setStatus('Select your site files (index.html and assets) first.', 'error'); return; }
    // Basic check for index.html
    const hasIndex = files.some(f => /(^|\/)index\.html$/i.test(f.name || ''));
    // Allow a single HTML file without checking the name (server will promote it)
    const htmlFiles = files.filter(f => /\.html?$/i.test(f.name || ''));
    if (!hasIndex && htmlFiles.length !== 1) { 
      setStatus('Need either index.html or exactly one HTML file in selection.', 'error'); 
      return; 
    }
    
    try {
      await ensureApiBase();
      setStatus('Publishing to /p directory...', '');
      showProgress(0);
      const fd = new FormData();
      files.forEach(f => fd.append('files', f, f.webkitRelativePath || f.name));
      
      // Only add Synology session ID if available
      const synoId = getCookie('id');
      if (synoId) {
        fd.append('_sid', synoId); // Synology session ID if available
      }
      
      // Prepare endpoints for publishing to /p directory
      const endpoints = [
        '/api/p/publish',          // New dedicated endpoint for /p directory
        '/anyfile/api/p/publish',  // With anyfile prefix
        '/api/site/publish?name=p' // Fallback to old endpoint with name=p
      ];
      
      // Cloudflare specific - try direct upload subdomain bypassing Cloudflare proxy
      const host = location.hostname;
      if (host === 'anyfile.uk') {
        console.log('Detected anyfile.uk with Cloudflare - adding direct subdomain endpoints');
        
        // Create direct upload subdomain URLs (bypassing Cloudflare proxy)
        const uploadSubdomain = 'https://upload.anyfile.uk';
        const filesSubdomain = 'https://files.anyfile.uk';
        
        // Add these as complete URLs (not using apiUrl helper)
        endpoints.push(uploadSubdomain + '/api/p/publish');
        endpoints.push(filesSubdomain + '/api/p/publish');
        
        // Try Synology direct URL if configured
        try {
          const synologyDirectUrl = localStorage.getItem('synology_direct');
          if (synologyDirectUrl) {
            const directUrl = synologyDirectUrl.replace(/\/+$/, ''); // Remove trailing slashes
            console.log('Adding Synology direct URL:', directUrl);
            endpoints.push(directUrl + '/api/p/publish');
          }
        } catch(_) { /* Ignore localStorage errors */ }
      }

      let resp = null;
      let text = '';
      let parsedResponse = null;
      let successUrl = null;
      console.log('API_BASE:', API_BASE, 'pathPrefix:', pathPrefix, 'Origin:', location.origin);

      // Function to detect Cloudflare challenges or interstitials
      function isCloudflareInterstitial(responseText) {
        const cfSignatures = [
          'DDoS protection by Cloudflare',
          'Checking your browser',
          'Please turn JavaScript on and reload the page',
          'Ray ID:',
          '<title>Just a moment...</title>',
          'performance.mark(\"cf_check_start\")'
        ];
        if (!responseText) return false;
        return cfSignatures.some(sig => responseText.includes(sig));
      }

      // Try each endpoint until we find one that works
      for (const endpoint of endpoints) {
        // Handle complete URLs (for direct subdomains) vs relative endpoints
        let url;
        if (endpoint.startsWith('http')) {
          // Full URL specified (for direct subdomains)
          url = endpoint + '?name=' + encodeURIComponent(name);
        } else {
          // Relative endpoint - use apiUrl helper
          const queryParam = '?name=' + encodeURIComponent(name);
          const pathSuffix = endpoint + queryParam;
          url = apiUrl(pathSuffix);
        }

        console.log(`Attempting to publish to: ${url}`);

        try {
          // For Synology, we may need specific headers
          const headers = authHeaders();
          if (url.includes('webapi') || url.includes('webman')) {
            headers['X-SYNO-TOKEN'] = getCookie('synotoken') || '';
            headers['X-Requested-With'] = 'XMLHttpRequest';
          }

          resp = await fetch(url, { 
            method: 'POST', 
            body: fd,
            headers,
            credentials: 'include',
            timeout: 30000
          });

          text = await resp.text();
          console.log(`Response from ${url}: Status ${resp.status}, Content-Type: ${resp.headers.get('Content-Type')}`);

          // Detect Cloudflare challenges
          if (isCloudflareInterstitial(text)) {
            console.warn(`Cloudflare challenge detected for ${url}, trying next endpoint`);
            continue;
          }

          // Check for successful upload even without proper JSON
          if (resp.ok && text.includes('"ok":true')) {
            try {
              parsedResponse = JSON.parse(text);
              if (parsedResponse.ok) {
                successUrl = url;
                console.log('Successful publish endpoint found:', url);
                break; // Exit the loop on success
              }
            } catch(e) {
              // If we can't parse the JSON but it contains "ok":true, consider it a success
              if (text.includes('"ok":true')) {
                parsedResponse = {ok: true};
                successUrl = url;
                console.log('Successful response detected despite JSON parse error:', url);
                break;
              }
              console.error(`Failed to parse response from ${url} as JSON:`, text.substring(0, 200));
              parsedResponse = {ok: false, error: 'INVALID_JSON_RESPONSE'};
            }
          } else if (url.includes('synology') || url.includes('webapi') || url.includes('webman')) {
            // Special handling for Synology responses
            try {
              const synoResponse = JSON.parse(text);
              // Synology uses "success": true instead of "ok": true
              if (synoResponse.success === true) {
                parsedResponse = {ok: true};
                successUrl = url;
                console.log('Successful Synology-style response:', url);
                break;
              }
            } catch(e) {
              // Continue to next endpoint
            }
          }
          // If we get here, the attempt was unsuccessful - continue to next endpoint
        } catch (fetchError) {
          console.error(`Fetch error for ${url}:`, fetchError);
          // Continue to next endpoint
        }
      }
      let js;
      try {
        js = JSON.parse(text);
      } catch(e) {
        console.error('Failed to parse response as JSON:', text.substring(0, 200));
        js = {ok: false, error: 'INVALID_JSON_RESPONSE'};
      }

      // After trying all endpoints, check if we had success
      if (successUrl) {
        hideProgress();

        // Use the URL from the server response if available, otherwise construct it
        let publishUrl = '';
        if (parsedResponse && parsedResponse.url) {
          publishUrl = parsedResponse.url;
        } else {
          // Fallback to constructing our own URL
          const hostParts = location.hostname.split('.');
          if (hostParts.length >= 2) {
            // Try to use p.domain.com format if main domain
            const rootDomain = hostParts.slice(-2).join('.');
            publishUrl = `${location.protocol}//p.${rootDomain}/`;
          } else {
            // Fallback to /p path
            publishUrl = `${location.origin}/p/`;
          }
        }

        // Add first filename if available
        if (parsedResponse && parsedResponse.files && parsedResponse.files.length > 0) {
          const firstFile = parsedResponse.files[0].name;
          if (firstFile) {
            publishUrl += firstFile;
          }
        }

        console.log('Published files will be available at:', publishUrl);
        setStatus('Published at ' + publishUrl, 'success');
        try { await copyToClipboard(publishUrl); } catch(_){ }
      } else {
        hideProgress();
        const detail = (parsedResponse && (parsedResponse.error || parsedResponse.message)) || '';
        const contentType = resp ? (resp.headers.get('Content-Type') || 'unknown') : 'no response';
        const status = resp ? resp.status : 'no response';

        console.error('Publishing to /p failed. Response details:', {
          status,
          contentType,
          apiBase: API_BASE,
          pathPrefix,
          textPreview: text ? text.substring(0, 200) : 'No response text'
        });

        if (text && (text.includes('<!DOCTYPE html>') || text.includes('<html'))) {
          // Check for Cloudflare interstitial/challenge
          if (isCloudflareInterstitial(text)) {
            const errorMsg = `Cloudflare protection is blocking the API request. Try using direct subdomains.`;
            setStatus('Publish failed: ' + errorMsg, 'error');
            // Removed popup code
          } else {
            // Standard HTML error without Cloudflare interference
            const errorMsg = `Server returned HTML instead of JSON (status: ${status}, content-type: ${contentType})`;
            setStatus('Publish failed: ' + errorMsg, 'error');
            // Show detailed troubleshooting advice for Synology
            console.info('Synology DS920 Troubleshooting:', [
              '1. Check Synology Web Station is properly set up',
              '2. Verify the virtual host configuration for anyfile.uk',
              '3. Check permissions for web folder (/web/anyfile)',
              '4. Make sure API endpoints are correctly mapped in your web server config',
              '5. Try accessing your Synology\'s direct IP:port instead of the Cloudflare domain'
            ].join('\n'));
          }
        } else {
          const errorMsg = detail || `HTTP ${status} (content-type: ${contentType})`;
          setStatus('Publish failed: ' + errorMsg, 'error');
        }
      }
    } catch(e) {
      hideProgress();
      setStatus('Publish failed: ' + (e.message || String(e)), 'error');
      console.error('Site publish error:', e);
    }
  }

  publishPBtn && publishPBtn.addEventListener('click', () => {
    handlePublishPClick().catch(err => console.error('Unhandled publish /p error:', err));
  });

  // Drag & Drop support on the label/container
  if (uploadLabel) {
    ;['dragenter','dragover'].forEach(ev => uploadLabel.addEventListener(ev, (e) => {
      e.preventDefault(); e.stopPropagation();
      uploadLabel.classList.add('dragover');
    }));
    ;['dragleave','dragend','drop'].forEach(ev => uploadLabel.addEventListener(ev, (e) => {
      uploadLabel.classList.remove('dragover');
    }));
    uploadLabel.addEventListener('drop', (e) => {
      e.preventDefault(); e.stopPropagation();
      const files = e.dataTransfer && e.dataTransfer.files ? Array.from(e.dataTransfer.files) : [];
      if (!files.length) return;
      try {
        // Try to assign via DataTransfer (not supported everywhere)
        const dt = new DataTransfer();
        files.forEach(f => dt.items.add(f));
        input.files = dt.files;
        overrideFiles = null;
      } catch(_) {
        // Fallback: store override for render/upload
        overrideFiles = files;
      }
      render();
    });
  }

  // Drag & Drop support on the dedicated dropzone section
  if (dropzone) {
    ['dragenter','dragover'].forEach(ev => dropzone.addEventListener(ev, (e) => {
      e.preventDefault(); e.stopPropagation();
      dropzone.classList.add('dragover');
    }));
    ['dragleave','dragend','drop'].forEach(ev => dropzone.addEventListener(ev, (e) => {
      dropzone.classList.remove('dragover');
    }));
    dropzone.addEventListener('drop', (e) => {
      e.preventDefault(); e.stopPropagation();
      const files = e.dataTransfer && e.dataTransfer.files ? Array.from(e.dataTransfer.files) : [];
      if (!files.length) return;
      try {
        const dt = new DataTransfer();
        files.forEach(f => dt.items.add(f));
        input.files = dt.files;
        overrideFiles = null;
      } catch(_) {
        overrideFiles = files;
      }
      render();
    });
  }

  // Cancel current upload if possible
  cancelBtn && cancelBtn.addEventListener('click', function(){
    try { currentXHR && currentXHR.abort(); } catch(_) {}
  });

  // Add configuration info panel for Synology + Cloudflare setup
  function addConfigPanel() {
    const configPanel = document.createElement('div');
    configPanel.className = 'config-panel';
    configPanel.style.cssText = 'margin-top: 30px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; background: #f9f9f9;';
    configPanel.innerHTML = `
      <h3 style="margin-top: 0; font-size: 16px;">Anyfile Configuration</h3>
      <div id="api-config-info"></div>
      <div style="margin-top: 15px;">
        <label for="synology-direct-url">Synology Direct URL:</label>
        <div style="display: flex; margin-top: 5px;">
          <input type="text" id="synology-direct-url" placeholder="http://192.168.1.x:5000" style="flex: 1; padding: 8px;">
          <button id="save-synology-url" style="margin-left: 10px; padding: 8px 15px; background: #007bff; color: white; border: none; cursor: pointer;">Save</button>
        </div>
        <p style="margin-top: 5px; font-size: 0.9em;">Use your Synology's direct IP or DDNS URL to bypass Cloudflare</p>
      </div>
      <div style="margin-top: 15px;">
        <h4 style="font-size: 14px; margin-bottom: 5px;">Cloudflare Setup Tips:</h4>
        <ul style="margin-top: 5px; padding-left: 20px; font-size: 0.9em;">
          <li>Set DNS records for <strong>upload.anyfile.uk</strong> to bypass proxy (gray cloud)</li>
          <li>Set DNS records for <strong>files.anyfile.uk</strong> to bypass proxy (gray cloud)</li>
          <li>Make sure port forwarding is properly configured on your router</li>
        </ul>
      </div>
    `;
    
    // Find a good place to add the panel
    const container = document.querySelector('.container') || document.body;
    container.appendChild(configPanel);
    
    // Load saved direct URL
    try {
      const savedUrl = localStorage.getItem('synology_direct');
      if (savedUrl) {
        document.getElementById('synology-direct-url').value = savedUrl;
      }
    } catch(_) { /* Ignore localStorage errors */ }
    
    // Save button handler
    document.getElementById('save-synology-url').addEventListener('click', function() {
      const directUrl = document.getElementById('synology-direct-url').value.trim();
      if (directUrl) {
        try {
          localStorage.setItem('synology_direct', directUrl);
          alert('Direct URL saved! Please reload the page to apply the setting.');
          window.location.reload();
        } catch(e) {
          alert('Could not save: ' + e.message);
        }
      } else {
        alert('Please enter a valid direct URL');
      }
    });
    
    // Show current API configuration
    const apiInfo = document.getElementById('api-config-info');
    if (apiInfo) {
      apiInfo.innerHTML = `
        <div style="font-family: monospace; font-size: 12px; background: #f0f0f0; padding: 10px; overflow-wrap: break-word;">
          <div>API Base: <span id="current-api-base">${API_BASE || 'Not resolved yet'}</span></div>
          <div>Origin: ${location.origin}</div>
          <div>Path Prefix: ${pathPrefix || 'None'}</div>
          <div>Hostname: ${location.hostname}</div>
        </div>
      `;
      
      // Update when API base is resolved
      const updateApiBase = setInterval(() => {
        if (apiBaseResolved) {
          document.getElementById('current-api-base').textContent = API_BASE || 'Not detected';
          clearInterval(updateApiBase);
        }
      }, 1000);
    }
  }
  
  // initial
  render();
  loadRecent();
  
  // Configuration panel disabled per request
  // setTimeout(addConfigPanel, 500);

  // --- Clipboard Debug Flag Setup ---
  const DEBUG_CLIPBOARD = (() => {
    if (location.search.includes('debug=clip') || location.hash.includes('debug=clip')) return true;
    try { return localStorage.getItem('debug_clip') === '1'; } catch(_) { return false; }
  })();

  let clipDebugDiv = null;
  function ensureClipDebugDiv() {
    if (!DEBUG_CLIPBOARD) return null;
    if (clipDebugDiv) return clipDebugDiv;
    clipDebugDiv = document.createElement('div');
    clipDebugDiv.id = 'clip-debug';
    clipDebugDiv.style.cssText = 'position:fixed;bottom:8px;right:8px;max-width:320px;max-height:40vh;overflow:auto;font:11px monospace;background:#111;color:#0f0;padding:6px 8px;z-index:9999;border:1px solid #0f0;opacity:0.9;white-space:pre-wrap;line-height:1.3;';
    clipDebugDiv.textContent = '[clip debug enabled]\n';
    document.body.appendChild(clipDebugDiv);
    return clipDebugDiv;
  }

  function clipLog(msg, data) {
    if (!DEBUG_CLIPBOARD) return;
    const ts = new Date().toISOString().split('T')[1].replace('Z','');
    const line = `[${ts}] ${msg}` + (data ? ' ' + (() => { try { return JSON.stringify(data); } catch { return String(data); } })() : '');
    console.log('%c[CLIP]', 'color:#0f0', line);
    const d = ensureClipDebugDiv();
    if (d) {
      d.textContent += line + '\n';
      d.scrollTop = d.scrollHeight;
    }
  }

  // --- Manual fallback overlay (lazy created) ---
  let clipFallback = null;
  function showClipboardFallback(url) {
    if (!clipFallback) {
      clipFallback = document.createElement('div');
      clipFallback.style.cssText = 'position:fixed;inset:0;z-index:99999;background:rgba(0,0,0,0.55);display:flex;align-items:center;justify-content:center;padding:20px;';
      clipFallback.innerHTML = '<div style="background:#111;color:#eee;max-width:480px;width:100%;padding:18px 20px;font:14px system-ui,Arial;border:1px solid #444;border-radius:6px;box-shadow:0 4px 16px rgba(0,0,0,0.4);">'
        +'<h3 style="margin:0 0 10px;font-size:16px;color:#6cf;">Manual Copy Required</h3>'
        +'<p style="margin:0 0 10px;line-height:1.4;">Your browser blocked automatic copying. Tap and hold the field below, choose Copy, then share it.</p>'
        +'<input id="clip-fallback-input" type="text" readonly style="width:100%;padding:8px 10px;font:13px monospace;border:1px solid #555;background:#222;color:#0f0;border-radius:4px;" />'
        +'<div style="display:flex;justify-content:space-between;margin-top:12px;gap:8px;">'
        +'<button id="clip-fallback-close" style="flex:1;padding:8px 10px;background:#333;color:#eee;border:1px solid #555;border-radius:4px;cursor:pointer;">Close</button>'
        +'<button id="clip-fallback-select" style="flex:1;padding:8px 10px;background:#264d26;color:#cfe;border:1px solid #3a7a3a;border-radius:4px;cursor:pointer;">Select All</button>'
        +'</div>'
        +'<div id="clip-fallback-status" style="margin-top:10px;font-size:12px;color:#888;"></div>'
        +'</div>';
      document.body.appendChild(clipFallback);
      clipFallback.addEventListener('click', (e) => { if (e.target === clipFallback) hideClipboardFallback(); });
      clipFallback.querySelector('#clip-fallback-close').addEventListener('click', hideClipboardFallback);
      clipFallback.querySelector('#clip-fallback-select').addEventListener('click', () => {
        const inp = clipFallback.querySelector('#clip-fallback-input');
        inp.focus();
        inp.select();
        clipLog('fallback select all');
      });
    }
    const inp = clipFallback.querySelector('#clip-fallback-input');
    inp.value = url;
    inp.focus();
    inp.select();
    clipFallback.style.display = 'flex';
    clipLog('showClipboardFallback', { urlLength: url.length });
  }
  function hideClipboardFallback() { if (clipFallback) clipFallback.style.display = 'none'; }

  // --- iOS pre-focus session helper ---
  // On iOS sometimes selection must be established within the same task of the user gesture.
  let iosSession = null;
  function beginIOSClipboardSession() {
    if (iosSession && iosSession.active) return iosSession; // reuse if still active
    const ios = /ipad|iphone|ipod/i.test(navigator.userAgent);
    if (!ios) return null;
    const ta = document.createElement('textarea');
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    ta.style.top = '-9999px';
    ta.style.opacity = '0';
    ta.value = '⏳';
    document.body.appendChild(ta);
    try { ta.focus(); ta.select(); ta.setSelectionRange(0, 9999); } catch(_) {}
    iosSession = {
      active: true,
      ta,
      apply(text) {
        if (!this.active) return { ok:false, reason:'session_not_active' };
        try {
          ta.value = text;
          ta.focus();
          ta.select();
          ta.setSelectionRange(0, 999999);
          const ok = document.execCommand('copy');
          clipLog('iosSession exec copy', { ok });
          return { ok, method:'iosSession' };
        } catch(e) {
          clipLog('iosSession copy error', { error: String(e) });
          return { ok:false, error:String(e) };
        } finally {
          try { document.body.removeChild(ta); } catch(_) {}
          this.active = false;
        }
      }
    };
    clipLog('iosSession started');
    return iosSession;
  }




  // Cross-browser copy function using iOS-compatible pattern (instrumented)
  window.Clipboard = (function(window, document, navigator) {
  var textArea,
    copy;

  function isOS() {
    const ios = !!navigator.userAgent.match(/ipad|iphone/i);
    clipLog('isOS', { ios });
    return ios;
  }

  function createTextArea(text) {
    textArea = document.createElement('textArea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.left = '-999999px';
    textArea.style.top = '-999999px';
    textArea.style.opacity = '0';
    document.body.appendChild(textArea);
    clipLog('createTextArea', { length: text.length });
  }

  function selectText() {
    var range,
      selection;
    if (!textArea) { clipLog('selectText no textarea'); return; }
    if (isOS()) {
      try {
        range = document.createRange();
        range.selectNodeContents(textArea);
        selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
        textArea.setSelectionRange(0, 999999);
        clipLog('selectText ios', { sample: textArea.value.slice(0,60) });
      } catch(e) {
        clipLog('selectText ios error', { error: String(e) });
      }
    } else {
      try {
        textArea.select();
        clipLog('selectText standard');
      } catch(e) {
        clipLog('selectText standard error', { error: String(e) });
      }
    }
  }

  function copyToClipboard() {
    let successful = false;
    try {
      successful = document.execCommand('copy');
      clipLog('execCommand copy', { successful });
    } catch(e) {
      clipLog('execCommand error', { error: String(e) });
    }
    try { document.body.removeChild(textArea); } catch(_) {}
    textArea = null;
    return successful;
  }

  copy = function(text) {
    clipLog('copy start');
    createTextArea(text);
    selectText();
    const ok = copyToClipboard();
    clipLog('copy done', { ok });
    return ok;
  };

  return { copy };
  })(window, document, navigator);

  async function copyToClipboard(text) {
    const ios = !!navigator.userAgent.match(/ipad|iphone/i);
    clipLog('copyToClipboard wrapper', { ios, length: text.length });
    if (!ios && navigator.clipboard && navigator.clipboard.writeText) {
      try {
        await navigator.clipboard.writeText(text);
        clipLog('navigator.clipboard success');
        return { ok: true, method: 'navigator.clipboard' };
      } catch (err) {
        clipLog('navigator.clipboard failed', { error: String(err) });
      }
    }
    const ok = window.Clipboard.copy(text);
    return { ok, method: 'execCommand', ios };
  }

  // NEW: Share helper – prefers OS share sheet, falls back to clipboard/modal
  async function shareLink(url, name = 'Anyfile share') {
    url = String(url || '');
    const shareData = {
      title: name || 'Anyfile share',
      text: 'Here is the Anyfile link I just generated:',
      url
    };

    if (navigator.share) {
      let payload = shareData;
      if (navigator.canShare && !navigator.canShare(payload)) {
        payload = { url };
        if (navigator.canShare && !navigator.canShare(payload)) {
          // Even if canShare reports false, some Safari versions still handle plain URL
          payload = { url };
        }
      }
      try {
        // Minimal delay helps Safari preserve the user gesture after async work
        await new Promise(resolve => setTimeout(resolve, 0));
        await navigator.share(payload);
        clipLog && clipLog('navigator.share success', { url });
        return { ok: true, method: 'navigator.share' };
      } catch (e) {
        const nameErr = (e && e.name) || '';
        const cancelled = nameErr === 'AbortError' || /cancel/i.test(String(e));
        clipLog && clipLog('navigator.share error', { error: String(e), name: nameErr, cancelled, payload });
        if (nameErr === 'TypeError' && payload !== shareData) {
          // If minimal payload still fails, fall through to clipboard
        }
        if (cancelled) return { ok: false, method: 'navigator.share', cancelled: true };
        const res = await copyToClipboard(url);
        if (res && (res.ok || res === true)) return { ok: true, method: 'clipboard' };
        showClipboardFallback(url);
        return { ok: false, method: 'fallback' };
      }
    }
    const res = await copyToClipboard(url);
    if (res && (res.ok || res === true)) return { ok: true, method: 'clipboard' };
    showClipboardFallback(url);
    return { ok: false, method: 'fallback' };
  }

})();

