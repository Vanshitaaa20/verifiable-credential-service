const STEP_DEFS = [
  { title: 'Generate issuer DID', desc: 'POST /api/dids' },
  { title: 'Generate holder DID', desc: 'POST /api/dids' },
  { title: 'Issue credential', desc: 'POST /api/credentials' },
  { title: 'Verify credential', desc: 'POST /api/credentials/verify — before revocation' },
  { title: 'Revoke credential', desc: 'POST /api/credentials/:id/revoke' },
  { title: 'Verify again', desc: 'POST /api/credentials/verify — after revocation' },
];

const stepsEl = document.getElementById('steps');
const runBtn = document.getElementById('run-demo');
const resetBtn = document.getElementById('reset-demo');

function renderSteps() {
  stepsEl.innerHTML = '';
  STEP_DEFS.forEach((def, i) => {
    const el = document.createElement('div');
    el.className = 'step';
    el.id = `step-${i}`;
    el.innerHTML = `
      <div class="step-head">
        <div class="step-num">${i + 1}</div>
        <div>
          <div class="step-title">${def.title}</div>
          <div class="step-desc">${def.desc}</div>
        </div>
        <div class="step-status" id="step-${i}-status">pending</div>
      </div>
      <div class="step-body"><pre id="step-${i}-body"></pre></div>
    `;
    stepsEl.appendChild(el);
  });
}

function setStep(i, state, data) {
  const el = document.getElementById(`step-${i}`);
  const status = document.getElementById(`step-${i}-status`);
  const body = document.getElementById(`step-${i}-body`);
  el.classList.remove('running', 'done', 'error');
  el.classList.add(state);
  status.textContent = state;
  if (data !== undefined) {
    body.textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
  }
}

async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await res.json().catch(() => null);
  if (!res.ok) {
    const err = new Error(json?.error ?? `request failed (${res.status})`);
    err.details = json;
    throw err;
  }
  return json;
}

async function runDemo() {
  runBtn.disabled = true;
  renderSteps();
  try {
    setStep(0, 'running');
    const issuer = await api('POST', '/api/dids');
    setStep(0, 'done', issuer);

    setStep(1, 'running');
    const holder = await api('POST', '/api/dids');
    setStep(1, 'done', holder);

    setStep(2, 'running');
    const issued = await api('POST', '/api/credentials', {
      issuerDid: issuer.did,
      holderDid: holder.did,
    });
    setStep(2, 'done', issued);

    setStep(3, 'running');
    const firstVerify = await api('POST', '/api/credentials/verify', issued.credential);
    setStep(3, 'done', firstVerify);

    setStep(4, 'running');
    const revoke = await api('POST', `/api/credentials/${issued.id}/revoke`);
    setStep(4, 'done', revoke);

    setStep(5, 'running');
    const secondVerify = await api('POST', '/api/credentials/verify', issued.credential);
    setStep(5, 'done', secondVerify);

    document.getElementById('verify-input').value = JSON.stringify(issued.credential, null, 2);
    refreshStats();
  } catch (err) {
    const runningStep = STEP_DEFS.findIndex((_, i) => {
      const el = document.getElementById(`step-${i}`);
      return el.classList.contains('running');
    });
    if (runningStep !== -1) {
      setStep(runningStep, 'error', err.details ?? err.message);
    }
  } finally {
    runBtn.disabled = false;
  }
}

runBtn.addEventListener('click', runDemo);
resetBtn.addEventListener('click', renderSteps);
renderSteps();

// --- Verify panel ---
const verifyInput = document.getElementById('verify-input');
const verifyBtn = document.getElementById('verify-btn');
const verifyResult = document.getElementById('verify-result');

function renderVerifyResult(result) {
  const checks = result.checks ?? {};
  const pills = Object.entries(checks)
    .map(([k, v]) => `<span class="check-pill ${v ? 'pass' : 'fail'}">${k}: ${v ? 'pass' : 'fail'}</span>`)
    .join('');
  const errors = (result.errors ?? []).length
    ? `<p class="verify-errors">${result.errors.join('<br />')}</p>`
    : '';
  verifyResult.innerHTML = `
    <span class="verify-banner ${result.valid ? 'valid' : 'invalid'}">${result.valid ? '✓ valid' : '✗ invalid'}</span>
    <div class="check-row">${pills}</div>
    ${errors}
  `;
}

verifyBtn.addEventListener('click', async () => {
  verifyResult.innerHTML = '';
  let credential;
  try {
    credential = JSON.parse(verifyInput.value);
  } catch {
    verifyResult.innerHTML = '<p class="verify-errors">That\'s not valid JSON.</p>';
    return;
  }
  verifyBtn.disabled = true;
  try {
    const result = await api('POST', '/api/credentials/verify', credential);
    renderVerifyResult(result);
  } catch (err) {
    verifyResult.innerHTML = `<p class="verify-errors">${err.message}</p>`;
  } finally {
    verifyBtn.disabled = false;
  }
});

// --- Dashboard ---
async function refreshStats() {
  const statusEl = document.getElementById('stat-status');
  try {
    const health = await fetch('/health').then((r) => r.json());
    statusEl.innerHTML = health.status === 'ok'
      ? '<span class="dot online"></span>Online'
      : '<span class="dot offline"></span>Degraded';
  } catch {
    statusEl.innerHTML = '<span class="dot offline"></span>Offline';
  }

  try {
    const res = await fetch('/api/stats');
    if (!res.ok) throw new Error('stats unavailable');
    const stats = await res.json();
    document.getElementById('stat-issued').textContent = stats.credentialsIssued;
    document.getElementById('stat-revoked').textContent = stats.credentialsRevoked;
    document.getElementById('stat-verifications').textContent = stats.verificationRequests;
    document.getElementById('stat-dids').textContent = stats.didsRegistered;
    document.getElementById('badge-issued').textContent = `${stats.credentialsIssued}+`;
    document.getElementById('badge-dids').textContent = `${stats.didsRegistered}+`;
  } catch {
    // Leave placeholders — dashboard just won't update this cycle.
  }
}

document.getElementById('refresh-stats').addEventListener('click', refreshStats);
refreshStats();
