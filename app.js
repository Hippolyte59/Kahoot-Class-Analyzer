/* ============================================================
  KAHOOT ANALYZER - app.js
  Frontend OAuth 2.0 PKCE + Kahoot API dashboard logic
  ============================================================

   HOW TO USE:
   1. Register your app at https://devportal.kahoot.com
   2. Fill in CONFIG below (CLIENT_ID, REDIRECT_URI)
   3. Serve this folder over HTTPS or localhost (e.g. Live Server)
   4. Click "Connect with Kahoot" — OAuth flow opens, tokens saved
      automatically.

   API Docs: https://devportal.kahoot.com/documentation
   ============================================================ */

'use strict';

/* ============================================================
  CONFIGURATION - fill these values
  ============================================================ */
const CONFIG = {
  CLIENT_ID:    'YOUR_CLIENT_ID',          // From Kahoot Developer Portal
  REDIRECT_URI: 'http://localhost:5500/',  // Must match what you registered
  SCOPE:        'openid profile email reports:read kahoots:read',

  // Kahoot API base
  API_BASE:     'https://api.kahoot.com/v2',

  // OAuth endpoints
  AUTH_URL:     'https://create.kahoot.it/oauth/authorize',
  TOKEN_URL:    'https://create.kahoot.it/oauth/token',
};

const TOKEN_STORAGE = sessionStorage;
const MAX_REPORTS = 100;

/* ============================================================
   STATE
   ============================================================ */
const state = {
  accessToken:  null,
  refreshToken: null,
  tokenExpiry:  null,
  user:         null,
  sessions:     [],       // all fetched reports
  charts:       {},       // chart instances keyed by id
  activeSession: null,
};

/* ============================================================
   DOM HELPERS
   ============================================================ */
const $  = (id) => document.getElementById(id);
const el = (tag, cls, html) => {
  const e = document.createElement(tag);
  if (cls)  e.className = cls;
  if (html) e.innerHTML = html;
  return e;
};
const show = (id) => { const e = $(id); if (e) { e.classList.remove('hidden'); e.classList.add('active'); } };
const hide = (id) => { const e = $(id); if (e) { e.classList.remove('active'); e.classList.add('hidden'); } };
const toFiniteNumber = (value, fallback = 0) => {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
};
const sanitizeText = (value, fallback = '') => {
  if (typeof value !== 'string') return fallback;
  return value.replace(/[\u0000-\u001F\u007F]/g, '').trim().slice(0, 120);
};
const isSafeAvatarUrl = (value) => {
  if (typeof value !== 'string' || !value.trim()) return false;
  try {
    const parsed = new URL(value, window.location.origin);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:';
  } catch {
    return false;
  }
};
const screen = (id) => {
  ['authScreen','loadingScreen','dashboard'].forEach(s => {
    const el = $(s);
    if (el) { el.classList.remove('active'); }
  });
  const target = $(id);
  if (target) target.classList.add('active');
};

let toastTimer = null;
function toast(msg, type = 'info') {
  const t = $('toast');
  t.textContent = msg;
  t.className = `toast show ${type}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 3500);
}

/* ============================================================
   BACKGROUND PARTICLES
   ============================================================ */
function spawnParticles() {
  const container = $('bgParticles');
  const colors = ['#7c3aed','#00f5c8','#f0037f','#3b82f6','#ffb340'];
  for (let i = 0; i < 22; i++) {
    const p = el('div', 'particle');
    const size = 6 + Math.random() * 20;
    p.style.cssText = `
      width:${size}px; height:${size}px;
      left:${Math.random()*100}%;
      bottom:${-size}px;
      background:${colors[Math.floor(Math.random()*colors.length)]};
      animation-duration:${10+Math.random()*20}s;
      animation-delay:${Math.random()*10}s;
    `;
    container.appendChild(p);
  }
}

/* ============================================================
   PKCE HELPERS (required by Kahoot OAuth 2.0 PKCE flow)
   ============================================================ */
function base64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}
async function generatePKCE() {
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const digest   = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  const challenge = base64url(digest);
  return { verifier, challenge };
}

/* ============================================================
  OAUTH - LOGIN
  ============================================================ */
async function login() {
  const { verifier, challenge } = await generatePKCE();
  const stateParam = base64url(crypto.getRandomValues(new Uint8Array(12)));

  sessionStorage.setItem('pkce_verifier', verifier);
  sessionStorage.setItem('oauth_state',   stateParam);

  const params = new URLSearchParams({
    response_type:         'code',
    client_id:             CONFIG.CLIENT_ID,
    redirect_uri:          CONFIG.REDIRECT_URI,
    scope:                 CONFIG.SCOPE,
    state:                 stateParam,
    code_challenge:        challenge,
    code_challenge_method: 'S256',
  });

  window.location.href = `${CONFIG.AUTH_URL}?${params}`;
}

/* ============================================================
  OAUTH - HANDLE CALLBACK (code in URL)
  ============================================================ */
async function handleCallback(code, returnedState) {
  const savedState  = sessionStorage.getItem('oauth_state');
  const verifier    = sessionStorage.getItem('pkce_verifier');
  const codeIsValid = typeof code === 'string' && /^[A-Za-z0-9._~-]{8,2048}$/.test(code);

  if (returnedState !== savedState || !verifier || !codeIsValid) {
    toast('OAuth state mismatch - possible CSRF attack.', 'error');
    screen('authScreen');
    return;
  }

  $('loadingText').textContent = 'Exchanging token...';
  screen('loadingScreen');

  try {
    const res = await fetch(CONFIG.TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type:    'authorization_code',
        client_id:     CONFIG.CLIENT_ID,
        redirect_uri:  CONFIG.REDIRECT_URI,
        code,
        code_verifier: verifier,
      }),
    });

    if (!res.ok) throw new Error(`Token exchange failed: ${res.status}`);
    const data = await res.json();

    saveTokens(data);
    clearCallback();
    await initDashboard();
  } catch (err) {
    toast('Authentication failed. Please try again.', 'error');
    console.error(err);
    screen('authScreen');
  }
}

/* ============================================================
   TOKEN MANAGEMENT (sessionStorage)
   ============================================================ */
function saveTokens(data) {
  state.accessToken  = typeof data.access_token === 'string' ? data.access_token : null;
  state.refreshToken = typeof data.refresh_token === 'string' ? data.refresh_token : null;
  state.tokenExpiry  = Date.now() + (toFiniteNumber(data.expires_in, 3600) * 1000);
  if (!state.accessToken) throw new Error('Missing access token');
  TOKEN_STORAGE.setItem('ka_token',   state.accessToken);
  TOKEN_STORAGE.setItem('ka_refresh', state.refreshToken || '');
  TOKEN_STORAGE.setItem('ka_expiry',  String(state.tokenExpiry));
}

function loadTokens() {
  state.accessToken  = TOKEN_STORAGE.getItem('ka_token')   || null;
  state.refreshToken = TOKEN_STORAGE.getItem('ka_refresh') || null;
  state.tokenExpiry  = parseInt(TOKEN_STORAGE.getItem('ka_expiry') || '0', 10);
  return !!state.accessToken;
}

function clearTokens() {
  state.accessToken = state.refreshToken = state.tokenExpiry = null;
  ['ka_token','ka_refresh','ka_expiry'].forEach(k => TOKEN_STORAGE.removeItem(k));
}

function isTokenExpired() {
  return state.tokenExpiry && Date.now() > state.tokenExpiry - 60000;
}

async function refreshAccessToken() {
  if (!state.refreshToken) { logout(); return false; }
  try {
    const res = await fetch(CONFIG.TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type:    'refresh_token',
        client_id:     CONFIG.CLIENT_ID,
        refresh_token: state.refreshToken,
      }),
    });
    if (!res.ok) throw new Error('Refresh failed');
    saveTokens(await res.json());
    return true;
  } catch {
    logout();
    return false;
  }
}

function clearCallback() {
  const url = new URL(window.location.href);
  url.searchParams.delete('code');
  url.searchParams.delete('state');
  url.hash = '';
  window.history.replaceState({}, '', url.toString());
  sessionStorage.removeItem('pkce_verifier');
  sessionStorage.removeItem('oauth_state');
}

/* ============================================================
   API WRAPPER
   ============================================================ */
async function apiGet(path) {
  if (isTokenExpired()) {
    const ok = await refreshAccessToken();
    if (!ok) return null;
  }
  const res = await fetch(`${CONFIG.API_BASE}${path}`, {
    headers: { Authorization: `Bearer ${state.accessToken}` },
  });
  if (res.status === 401) { logout(); return null; }
  if (!res.ok) throw new Error(`API ${path} → ${res.status}`);
  return res.json();
}

/* ============================================================
  DEMO / MOCK DATA
  Used when CLIENT_ID is not configured so the dashboard can
  run without live API access.
  ============================================================ */
function generateMockData() {
  const names = ['Alice','Bob','Charlie','Diana','Ethan','Fiona','George','Hannah','Ivan','Julia'];
  const quizzes = [
    'History Chapter 3','Science Quiz #4','Math Midterm','Geography Basics',
    'Literature Review','Physics Final','Chemistry #2','Biology Test'
  ];

  const sessions = [];
  for (let s = 0; s < 8; s++) {
    const date = new Date(Date.now() - (8-s)*5*24*3600*1000);
    const quiz = quizzes[s % quizzes.length];
    const numQ = 5 + Math.floor(Math.random()*6);
    const players = names.slice(0, 6 + Math.floor(Math.random()*4)).map(name => {
      const correctAnswers = Math.floor(Math.random() * (numQ + 1));
      const totalScore = correctAnswers * (1000 + Math.floor(Math.random()*200));
      return { name, totalScore, correctAnswers, totalQuestions: numQ };
    });

    const questionStats = Array.from({length: numQ}, (_, i) => ({
      questionIndex: i,
      text: `Question ${i+1}`,
      correctRatio: 0.3 + Math.random() * 0.65,
    }));

    sessions.push({
      id: `mock-${s}`,
      quizTitle: quiz,
      startedAt: date.toISOString(),
      players,
      questionStats,
    });
  }
  return sessions;
}

/* ============================================================
   FETCH DATA FROM KAHOOT API
   ============================================================ */
async function fetchUser() {
  try {
    return await apiGet('/users/me');
  } catch { return null; }
}

async function fetchSessions() {
  // Reports endpoint: returns completed sessions
  try {
    const data = await apiGet('/reports?limit=50&orderBy=startedAt:desc');
    if (!data) return [];
    // Normalize possible API response shapes
    const reports = Array.isArray(data.reports || data.data || data.entities)
      ? (data.reports || data.data || data.entities)
      : [];
    return reports.slice(0, MAX_REPORTS).map(r => normalizeSessions(r));
  } catch (err) {
    console.warn('Using mock data:', err.message);
    return generateMockData();
  }
}

function normalizeSessions(r) {
  // Normalize one report into the internal session shape
  const sourcePlayers = Array.isArray(r.players || r.participants) ? (r.players || r.participants) : [];
  const players = sourcePlayers.map(p => ({
    name: sanitizeText(p.name || p.nickname, 'Unknown') || 'Unknown',
    totalScore: Math.max(0, toFiniteNumber(p.totalScore || p.score, 0)),
    correctAnswers: Math.max(0, toFiniteNumber(p.correctAnswers, 0)),
    totalQuestions: Math.max(0, toFiniteNumber(p.totalQuestions || r.quizQuestionCount, 0)),
  }));

  const sourceQuestions = Array.isArray(r.questionSummaries || r.questions) ? (r.questionSummaries || r.questions) : [];
  const questionStats = sourceQuestions.map((q, i) => ({
    questionIndex: i,
    text: sanitizeText(q.question || q.title, `Question ${i+1}`),
    correctRatio: q.correctAnswersPercent != null
      ? clampPct(toFiniteNumber(q.correctAnswersPercent, 50)) / 100
      : (toFiniteNumber(q.totalCount, 0) > 0
          ? clampPct((toFiniteNumber(q.correctCount, 0) / toFiniteNumber(q.totalCount, 1)) * 100) / 100
          : 0.5),
  }));

  return {
    id: sanitizeText(String(r.id || r.reportId || crypto.randomUUID())),
    quizTitle: sanitizeText(r.quizTitle || r.quiz?.title, 'Untitled Quiz') || 'Untitled Quiz',
    startedAt: sanitizeText(r.startedAt || r.createdAt, new Date().toISOString()) || new Date().toISOString(),
    players,
    questionStats,
  };
}

/* ============================================================
   COMPUTED METRICS
   ============================================================ */
function avgScore(session) {
  if (!session.players.length) return 0;
  return session.players.reduce((s,p) => s + p.totalScore, 0) / session.players.length;
}

function sessionAccuracy(session) {
  if (!session.players.length) return 0;
  const totals = session.players.reduce((acc, p) => ({
    correct: acc.correct + p.correctAnswers,
    total:   acc.total   + p.totalQuestions,
  }), {correct:0, total:0});
  return totals.total ? (totals.correct / totals.total) * 100 : 0;
}

function aggregatePlayers(sessions) {
  const map = {};
  for (const ses of sessions) {
    for (const p of ses.players) {
      if (!map[p.name]) map[p.name] = { name: p.name, totalScore: 0, sessions: 0 };
      map[p.name].totalScore += p.totalScore;
      map[p.name].sessions++;
    }
  }
  return Object.values(map).sort((a,b) => b.totalScore - a.totalScore);
}

function movingAverage(values, windowSize = 3) {
  if (!values.length) return [];
  return values.map((_, idx) => {
    const start = Math.max(0, idx - windowSize + 1);
    const chunk = values.slice(start, idx + 1);
    return chunk.reduce((a, b) => a + b, 0) / chunk.length;
  });
}

function clampPct(value) {
  return Math.max(0, Math.min(100, value));
}

function sessionConsistency(session) {
  if (!session.players.length) return 0;
  const scores = session.players.map((p) => p.totalScore);
  const mean = scores.reduce((a, b) => a + b, 0) / scores.length;
  const variance = scores.reduce((acc, s) => acc + ((s - mean) ** 2), 0) / scores.length;
  const stdDev = Math.sqrt(variance);
  const normalized = mean ? 100 - ((stdDev / mean) * 100) : 0;
  return clampPct(normalized);
}

function avgQuestionsPerPlayer(session) {
  if (!session.players.length) return 0;
  const totalQuestions = session.players.reduce((sum, p) => sum + (p.totalQuestions || 0), 0);
  return totalQuestions / session.players.length;
}

function calcSessionQualityMetrics(session) {
  const participation = clampPct((session.players.length / 30) * 100);
  const avgScoreValue = avgScore(session);
  const scoreQuality = clampPct((avgScoreValue / 12000) * 100);
  const accuracy = clampPct(sessionAccuracy(session));
  const consistency = sessionConsistency(session);
  const depth = clampPct((avgQuestionsPerPlayer(session) / 20) * 100);

  return {
    labels: ['Participation', 'Score Quality', 'Accuracy', 'Consistency', 'Depth'],
    values: [participation, scoreQuality, accuracy, consistency, depth],
  };
}

/* ============================================================
   CHART HELPERS
   ============================================================ */
const CHART_COLORS = {
  cyan:    'rgba(0,245,200,.9)',
  violet:  'rgba(124,58,237,.9)',
  fuchsia: 'rgba(240,3,127,.9)',
  amber:   'rgba(255,179,64,.9)',
  emerald: 'rgba(0,230,118,.9)',
  coral:   'rgba(255,77,109,.9)',
  blue:    'rgba(59,130,246,.9)',
};

const GRID_STYLE = {
  color: 'rgba(124,58,237,.1)',
  drawBorder: false,
};

const LEGEND_CONFIG = {
  display: false,
};

const CHART_ANIMATION = {
  duration: 1000,
  easing: 'easeOutQuart',
};

function destroyChart(id) {
  if (state.charts[id]) {
    state.charts[id].destroy();
    delete state.charts[id];
  }
}

Chart.defaults.color = '#7878a8';
Chart.defaults.font.family = "'Segoe UI', system-ui, sans-serif";
Chart.register(ChartDataLabels);

/* ============================================================
   RENDER CHARTS
   ============================================================ */

// 1. Score trend (line chart across sessions)
function renderTrendChart(sessions) {
  destroyChart('trend');
  const labels = sessions.map(s => new Date(s.startedAt).toLocaleDateString('en-GB',{month:'short',day:'numeric'}));
  const scores = sessions.map(s => Math.round(avgScore(s)));
  const accs   = sessions.map(s => Math.round(sessionAccuracy(s)));

  const ctx = $('chartTrend').getContext('2d');

  // Gradient for fill
  const grad = ctx.createLinearGradient(0, 0, 0, 220);
  grad.addColorStop(0, 'rgba(0,245,200,.28)');
  grad.addColorStop(1, 'rgba(124,58,237,0)');

  state.charts.trend = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label: 'Avg Score',
          data: scores,
          borderColor: '#00f5c8',
          backgroundColor: grad,
          fill: true,
          tension: .4,
          pointBackgroundColor: '#00f5c8',
          pointBorderColor: '#0d0d1f',
          pointBorderWidth: 2,
          pointRadius: 5,
          yAxisID: 'y',
        },
        {
          label: 'Accuracy %',
          data: accs,
          borderColor: '#f0037f',
          backgroundColor: 'transparent',
          tension: .4,
          pointBackgroundColor: '#f0037f',
          pointBorderColor: '#0d0d1f',
          pointBorderWidth: 2,
          pointRadius: 5,
          yAxisID: 'y1',
          borderDash: [6,3],
        },
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      animation: CHART_ANIMATION,
      plugins: { legend: LEGEND_CONFIG, datalabels: { display: false } },
      scales: {
        x: { grid: GRID_STYLE },
        y:  { grid: GRID_STYLE, position: 'left',  title: { display: true, text: 'Score' } },
        y1: { grid: { display:false }, position: 'right', title: { display: true, text: 'Accuracy %' }, min:0, max:100 },
      },
      interaction: { mode: 'index', intersect: false },
    },
  });

  // Legend
  $('trendLegend').innerHTML = `
    <div class="legend-item"><div class="legend-dot" style="background:#00f5c8"></div> Avg Score</div>
    <div class="legend-item"><div class="legend-dot" style="background:#f0037f"></div> Accuracy %</div>
  `;
}

// 2. Accuracy per question (bar chart for a session)
function renderAccuracyChart(session) {
  destroyChart('accuracy');
  if (!session.questionStats.length) return;

  const labels = session.questionStats.map(q => q.text.length > 20 ? q.text.slice(0,20)+'...' : q.text);
  const data   = session.questionStats.map(q => Math.round(q.correctRatio * 100));
  const colors = data.map(v => v >= 70 ? '#00e676' : v >= 40 ? '#ffb340' : '#ff4d6d');

  state.charts.accuracy = new Chart($('chartAccuracy').getContext('2d'), {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Correct %',
        data,
        backgroundColor: colors,
        borderRadius: 6,
        borderSkipped: false,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      animation: CHART_ANIMATION,
      plugins: {
        legend: LEGEND_CONFIG,
        datalabels: {
          color: '#fff', anchor: 'end', align: 'start',
          formatter: v => v + '%',
          font: { weight: 'bold', size: 11 },
        },
      },
      scales: {
        x: { grid: GRID_STYLE },
        y: { grid: GRID_STYLE, min: 0, max: 100, ticks: { callback: v => v+'%' } },
      },
    },
  });
  $('accuracySession').textContent = session.quizTitle;
}

// 3. Score distribution (doughnut)
function renderDistChart(sessions) {
  destroyChart('dist');
  // Bucket all player scores into ranges
  const allScores = sessions.flatMap(s => s.players.map(p => p.totalScore));
  const max = Math.max(...allScores, 1);
  const buckets = [0,0,0,0,0];
  for (const sc of allScores) {
    const i = Math.min(4, Math.floor((sc / max) * 5));
    buckets[i]++;
  }

  state.charts.dist = new Chart($('chartDist').getContext('2d'), {
    type: 'doughnut',
    data: {
      labels: ['0–20%','20–40%','40–60%','60–80%','80–100%'],
      datasets: [{
        data: buckets,
        backgroundColor: ['#ff4d6d','#ffb340','#3b82f6','#7c3aed','#00e676'],
        borderWidth: 0,
        hoverOffset: 8,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false, cutout: '65%',
      animation: CHART_ANIMATION,
      plugins: {
        legend: { display: true, position:'bottom', labels: { boxWidth:12, padding:14 } },
        datalabels: {
          color: '#fff', font: { weight:'bold', size:12 },
          formatter: (v, ctx) => v + '\n(' + Math.round(v/ctx.dataset.data.reduce((a,b)=>a+b,0)*100) + '%)',
          display: v => v > 0,
        },
      },
    },
  });
}

// 4. Participation (bar)
function renderParticipationChart(sessions) {
  destroyChart('participation');
  const labels = sessions.map(s => new Date(s.startedAt).toLocaleDateString('en-GB',{month:'short',day:'numeric'}));
  const counts  = sessions.map(s => s.players.length);

  state.charts.participation = new Chart($('chartParticipation').getContext('2d'), {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Players',
        data: counts,
        backgroundColor: 'rgba(0,245,200,.7)',
        borderRadius: 6,
        borderSkipped: false,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      animation: CHART_ANIMATION,
      plugins: {
        legend: LEGEND_CONFIG,
        datalabels: {
          color: '#fff', anchor: 'end', align: 'top',
          font: { weight:'bold' },
        },
      },
      scales: {
        x: { grid: GRID_STYLE },
        y: { grid: GRID_STYLE, beginAtZero: true, ticks: { precision: 0 } },
      },
    },
  });
}

// 5. Momentum (rolling average area line)
function renderMomentumChart(sessions) {
  destroyChart('momentum');
  const labels = sessions.map((s) => new Date(s.startedAt).toLocaleDateString('en-GB', { month: 'short', day: 'numeric' }));
  const baseScores = sessions.map((s) => avgScore(s));
  const smoothed = movingAverage(baseScores, 3).map((v) => Math.round(v));

  const ctx = $('chartMomentum').getContext('2d');
  const gradient = ctx.createLinearGradient(0, 0, 0, 220);
  gradient.addColorStop(0, 'rgba(240,3,127,.3)');
  gradient.addColorStop(1, 'rgba(240,3,127,0)');

  state.charts.momentum = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'Rolling Avg',
        data: smoothed,
        borderColor: '#f0037f',
        backgroundColor: gradient,
        fill: true,
        tension: 0.45,
        pointRadius: 4,
        pointBackgroundColor: '#f0037f',
        pointBorderWidth: 0,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: CHART_ANIMATION,
      plugins: {
        legend: LEGEND_CONFIG,
        datalabels: { display: false },
      },
      scales: {
        x: { grid: GRID_STYLE },
        y: { grid: GRID_STYLE, beginAtZero: true },
      },
    },
  });
}

// 6. Session rhythm by weekday (polar area)
function renderWeekdaysChart(sessions) {
  destroyChart('weekdays');
  const weekdayLabels = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const counts = [0, 0, 0, 0, 0, 0, 0];

  sessions.forEach((session) => {
    const day = new Date(session.startedAt).getDay();
    const index = day === 0 ? 6 : day - 1;
    counts[index] += 1;
  });

  state.charts.weekdays = new Chart($('chartWeekdays').getContext('2d'), {
    type: 'polarArea',
    data: {
      labels: weekdayLabels,
      datasets: [{
        data: counts,
        backgroundColor: [
          'rgba(0,245,200,.55)',
          'rgba(59,130,246,.55)',
          'rgba(124,58,237,.55)',
          'rgba(240,3,127,.55)',
          'rgba(255,179,64,.55)',
          'rgba(0,230,118,.55)',
          'rgba(255,77,109,.55)',
        ],
        borderColor: [
          '#00f5c8', '#3b82f6', '#7c3aed', '#f0037f', '#ffb340', '#00e676', '#ff4d6d',
        ],
        borderWidth: 1.5,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: CHART_ANIMATION,
      plugins: {
        legend: { position: 'bottom', labels: { boxWidth: 10, color: '#9a9ab8' } },
        datalabels: {
          color: '#fff',
          font: { weight: 'bold', size: 10 },
          formatter: (v) => (v > 0 ? v : ''),
        },
      },
      scales: {
        r: {
          grid: { color: 'rgba(124,58,237,.16)' },
          angleLines: { color: 'rgba(124,58,237,.14)' },
          pointLabels: { color: '#a9a9c6', font: { size: 11 } },
          ticks: { display: false, stepSize: 1 },
          beginAtZero: true,
        },
      },
    },
  });
}

// 7. Session quality radar
function renderSessionRadar(session) {
  destroyChart('radar');
  if (!session) {
    $('radarSession').textContent = '- select a session';
    return;
  }

  const { labels, values } = calcSessionQualityMetrics(session);

  state.charts.radar = new Chart($('chartRadar').getContext('2d'), {
    type: 'radar',
    data: {
      labels,
      datasets: [{
        label: 'Quality',
        data: values,
        borderColor: '#00f5c8',
        backgroundColor: 'rgba(0,245,200,.18)',
        pointBackgroundColor: '#f0037f',
        pointBorderColor: '#0d0d1f',
        pointBorderWidth: 1,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: CHART_ANIMATION,
      plugins: {
        legend: LEGEND_CONFIG,
        datalabels: { display: false },
      },
      scales: {
        r: {
          suggestedMin: 0,
          suggestedMax: 100,
          ticks: { display: false },
          pointLabels: { color: '#b8b8d2', font: { size: 11 } },
          grid: { color: 'rgba(124,58,237,.16)' },
          angleLines: { color: 'rgba(124,58,237,.14)' },
        },
      },
    },
  });

  $('radarSession').textContent = session.quizTitle;
}

// 8. Performance map (bubble: x accuracy, y score, radius players)
function renderPerformanceMap(sessions) {
  destroyChart('perfmap');

  const points = sessions.map((session, index) => ({
    x: Number(sessionAccuracy(session).toFixed(1)),
    y: Number(avgScore(session).toFixed(0)),
    r: Math.max(6, Math.min(20, session.players.length + 4)),
    label: `S${index + 1}`,
  }));

  state.charts.perfmap = new Chart($('chartPerfMap').getContext('2d'), {
    type: 'bubble',
    data: {
      datasets: [{
        label: 'Sessions',
        data: points,
        backgroundColor: 'rgba(124,58,237,.35)',
        borderColor: '#00f5c8',
        borderWidth: 1.5,
        hoverBackgroundColor: 'rgba(240,3,127,.45)',
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: CHART_ANIMATION,
      plugins: {
        legend: LEGEND_CONFIG,
        tooltip: {
          callbacks: {
            label: (ctx) => {
              const p = ctx.raw;
              return `Accuracy ${p.x}% | Score ${p.y.toLocaleString()} | Players ${p.r - 4}`;
            },
          },
        },
        datalabels: {
          color: '#d9d9ef',
          formatter: (_, ctx) => ctx.raw.label,
          font: { size: 10, weight: 'bold' },
          align: 'center',
        },
      },
      scales: {
        x: {
          min: 0,
          max: 100,
          title: { display: true, text: 'Accuracy %' },
          grid: GRID_STYLE,
        },
        y: {
          beginAtZero: true,
          title: { display: true, text: 'Average Score' },
          grid: GRID_STYLE,
        },
      },
    },
  });
}

/* ============================================================
   RENDER SESSIONS LIST
   ============================================================ */
function renderSessions(sessions) {
  const list = $('sessionList');
  list.innerHTML = '';
  $('sessionCount').textContent = sessions.length;

  if (!sessions.length) {
    list.appendChild(el('div', 'empty-state', '<span>No Data</span>No sessions found'));
    return;
  }

  sessions.forEach((ses, i) => {
    const avg  = Math.round(avgScore(ses));
    const date = new Date(ses.startedAt).toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'});
    const item = el('div', 'session-item');
    item.style.animationDelay = `${i*0.04}s`;
    item.innerHTML = `
      <div class="session-dot"></div>
      <div class="session-info">
        <div class="session-title">${esc(ses.quizTitle)}</div>
        <div class="session-meta">${date} · ${ses.players.length} players</div>
      </div>
      <div class="session-score">${avg.toLocaleString()}</div>
    `;
    item.addEventListener('click', () => selectSession(ses, item));
    list.appendChild(item);
  });
}

function selectSession(ses, itemEl) {
  document.querySelectorAll('.session-item').forEach(e => e.classList.remove('active'));
  itemEl.classList.add('active');
  state.activeSession = ses;
  renderAccuracyChart(ses);
  $('distSession').textContent = ses.quizTitle;
  renderDistChart([ses]);
  renderSessionRadar(ses);
}

/* ============================================================
   RENDER KPIs
   ============================================================ */
function renderKPIs(sessions) {
  const kpiRow = $('kpiRow');
  kpiRow.innerHTML = '';

  const totalSessions = sessions.length;
  const totalPlayers  = new Set(sessions.flatMap(s => s.players.map(p => p.name))).size;
  const allAvgs       = sessions.map(s => avgScore(s));
  const overallAvg    = allAvgs.length ? Math.round(allAvgs.reduce((a,b)=>a+b,0) / allAvgs.length) : 0;
  const overallAcc    = sessions.length
    ? Math.round(sessions.reduce((a,s) => a + sessionAccuracy(s), 0) / sessions.length)
    : 0;

  // Trend vs previous half
  const half = Math.floor(sessions.length / 2);
  const recent = allAvgs.slice(-half);
  const older  = allAvgs.slice(0, half);
  const avgRecent = recent.length ? recent.reduce((a,b)=>a+b,0)/recent.length : overallAvg;
  const avgOlder  = older.length  ? older.reduce((a,b)=>a+b,0)/older.length  : overallAvg;
  const delta = avgOlder ? Math.round((avgRecent - avgOlder) / avgOlder * 100) : 0;

  const kpis = [
    { label:'Total Sessions', value: totalSessions, delta: null, delay:'0s' },
    { label:'Unique Players',  value: totalPlayers,  delta: null, delay:'.05s' },
    { label:'Avg Score',       value: overallAvg.toLocaleString(), delta, delay:'.1s' },
    { label:'Avg Accuracy',    value: overallAcc + '%', delta: null, delay:'.15s' },
  ];

  for (const k of kpis) {
    const card = el('div', 'kpi-card');
    card.style.setProperty('--delay', k.delay);
    card.innerHTML = `
      <div class="kpi-label">${k.label}</div>
      <div class="kpi-value">${k.value}</div>
      ${k.delta !== null ? `<div class="kpi-delta ${k.delta < 0 ? 'negative' : ''}">
        ${k.delta >= 0 ? 'UP' : 'DOWN'} ${Math.abs(k.delta)}% vs prior period
      </div>` : ''}
    `;
    kpiRow.appendChild(card);
  }
}

/* ============================================================
   RENDER TOP PLAYERS
   ============================================================ */
function renderPlayers(sessions) {
  const players = aggregatePlayers(sessions).slice(0, 10);
  const list    = $('playerList');
  list.innerHTML = '';
  if (!players.length) {
    list.appendChild(el('div','empty-state','<span>Ranking</span>No data yet'));
    return;
  }
  const maxScore = players[0].totalScore || 1;
  players.forEach((p, i) => {
    const rankCls = i===0 ? 'gold' : i===1 ? 'silver' : i===2 ? 'bronze' : '';
    const item = el('div', 'player-item');
    item.innerHTML = `
      <div class="player-rank ${rankCls}">${i+1}</div>
      <div style="flex:1;min-width:0">
        <div class="player-name">${esc(p.name)}</div>
        <div class="player-bar-wrap">
          <div class="player-bar" style="width:${Math.round(p.totalScore/maxScore*100)}%"></div>
        </div>
      </div>
      <div class="player-score">${p.totalScore.toLocaleString()}</div>
    `;
    list.appendChild(item);
  });
}

/* ============================================================
   SEARCH / FILTER
   ============================================================ */
function setupSearch() {
  $('sessionSearch').addEventListener('input', (e) => {
    const q = sanitizeText(String(e.target.value || ''), '').toLowerCase().slice(0, 80);
    const filtered = state.sessions.filter(s =>
      s.quizTitle.toLowerCase().includes(q)
    );
    renderSessions(filtered);
  });
}

/* ============================================================
   ESCAPE HTML
   ============================================================ */
function esc(str) {
  return String(str)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}

/* ============================================================
   UPDATE HEADER WITH USER INFO
   ============================================================ */
function updateUserUI() {
  if (state.user) {
    $('userName').textContent = sanitizeText(state.user.name || state.user.email, 'Kahoot User') || 'Kahoot User';
    if (isSafeAvatarUrl(state.user.avatar)) {
      $('userAvatar').src = state.user.avatar;
    } else {
      $('userAvatar').removeAttribute('src');
    }
    $('userBadge').classList.remove('hidden');
  }
  $('btnLogin').classList.add('hidden');
  $('btnLogout').classList.remove('hidden');
}

/* ============================================================
   INIT DASHBOARD
   ============================================================ */
async function initDashboard() {
  $('loadingText').textContent = 'Loading your sessions...';
  screen('loadingScreen');

  try {
    // Fetch user profile & sessions in parallel
    const [user, sessions] = await Promise.all([fetchUser(), fetchSessions()]);
    state.user     = user;
    state.sessions = sessions;

    updateUserUI();
    renderKPIs(sessions);
    renderSessions(sessions);
    renderTrendChart(sessions);
    renderDistChart(sessions);
    renderParticipationChart(sessions);
    renderMomentumChart(sessions);
    renderWeekdaysChart(sessions);
    renderSessionRadar(null);
    renderPerformanceMap(sessions);
    renderPlayers(sessions);

    // Auto-select first session for detail charts
    if (sessions.length) {
      const firstItem = document.querySelector('.session-item');
      if (firstItem) selectSession(sessions[0], firstItem);
    }

    setupSearch();
    screen('dashboard');
    toast('Dashboard loaded!', 'success');
  } catch (err) {
    console.error(err);
    toast('Failed to load data: ' + err.message, 'error');
    screen('authScreen');
  }
}

/* ============================================================
   LOGOUT
   ============================================================ */
function logout() {
  clearTokens();
  state.user = null;
  state.sessions = [];
  Object.keys(state.charts).forEach(k => { state.charts[k].destroy(); delete state.charts[k]; });
  $('userBadge').classList.add('hidden');
  $('btnLogout').classList.add('hidden');
  $('btnLogin').classList.remove('hidden');
  screen('authScreen');
  toast('Logged out');
}

/* ============================================================
   REFRESH BUTTON
   ============================================================ */
async function refreshData() {
  if (!state.accessToken) return;
  $('btnRefresh').disabled = true;
  toast('Refreshing...');
  try {
    const sessions = await fetchSessions();
    state.sessions  = sessions;
    renderKPIs(sessions);
    renderSessions(sessions);
    renderTrendChart(sessions);
    renderDistChart(sessions);
    renderParticipationChart(sessions);
    renderMomentumChart(sessions);
    renderWeekdaysChart(sessions);
    renderSessionRadar(state.activeSession || null);
    renderPerformanceMap(sessions);
    renderPlayers(sessions);
    toast('Data refreshed!', 'success');
  } catch (err) {
    toast('Refresh failed: ' + err.message, 'error');
  }
  $('btnRefresh').disabled = false;
}

/* ============================================================
   BOOTSTRAP
   ============================================================ */
document.addEventListener('DOMContentLoaded', () => {
  spawnParticles();

  // Wire up buttons
  $('btnLogin').addEventListener('click', login);
  $('btnLoginHero').addEventListener('click', login);
  $('btnLogout').addEventListener('click', logout);
  $('btnRefresh').addEventListener('click', refreshData);

  const params = new URLSearchParams(window.location.search);
  const code   = params.get('code');
  const retState = params.get('state');
  const paramsAreValid =
    (!code || /^[A-Za-z0-9._~-]{8,2048}$/.test(code)) &&
    (!retState || /^[A-Za-z0-9_-]{8,256}$/.test(retState));

  if (!paramsAreValid) {
    clearCallback();
    toast('Invalid callback parameters detected.', 'error');
    screen('authScreen');
    return;
  }

  if (code && retState) {
    // Returning from OAuth redirect
    handleCallback(code, retState);
    return;
  }

  // Check for saved token
  if (loadTokens() && !isTokenExpired()) {
    initDashboard();
    return;
  }

  // If demo mode (no CLIENT_ID configured), load mock data directly
  if (CONFIG.CLIENT_ID === 'YOUR_CLIENT_ID') {
    console.info('[Kahoot Analyser] Running in demo mode with mock data.');
    state.accessToken = 'demo';
    state.sessions = generateMockData();
    renderKPIs(state.sessions);
    renderSessions(state.sessions);
    renderTrendChart(state.sessions);
    renderDistChart(state.sessions);
    renderParticipationChart(state.sessions);
    renderMomentumChart(state.sessions);
    renderWeekdaysChart(state.sessions);
    renderSessionRadar(null);
    renderPerformanceMap(state.sessions);
    renderPlayers(state.sessions);
    setupSearch();
    if (state.sessions.length) {
      const firstItem = document.querySelector('.session-item');
      if (firstItem) selectSession(state.sessions[0], firstItem);
    }
    state.user = { name: 'Demo User' };
    updateUserUI();
    screen('dashboard');
    toast('Running in demo mode - configure CLIENT_ID to use real data', 'info');
    return;
  }

  screen('authScreen');
});
