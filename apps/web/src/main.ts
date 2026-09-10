interface User { email: string; organizationId: string; role: string }
interface Summary { protectedDevices: number; detections: number; blockedEvents: number; redactions: number; recentEvents: { occurredAt: string; service: string; secretType: string; severity: string; action: string }[] }

const api = "http://localhost:3000";
const app = document.querySelector<HTMLDivElement>("#app")!;

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`${api}${path}`, { ...options, credentials: "include", headers: { "Content-Type": "application/json", ...(options.headers ?? {}) } });
  if (!response.ok) throw new Error(response.status === 401 ? "unauthorized" : "request_failed");
  return response.status === 204 ? ({} as T) : response.json() as Promise<T>;
}

function loginView(message = ""): void {
  app.innerHTML = `<main class="login"><form class="login-card" id="login-form"><div class="brand">DLP <span>SECURITY</span></div><p class="eyebrow">Developer protection console</p><h1 class="title">Sign in</h1><p class="muted">Review risk metadata without exposing prompts or secret values.</p><label>Email<input name="email" type="email" autocomplete="email" required placeholder="you@company.com"></label><label>Password<input name="password" type="password" autocomplete="current-password" required minlength="12"></label>${message ? `<p class="error">${message}</p>` : ""}<button class="primary" type="submit">Sign in</button><p class="muted">New local account? Register through the API first.</p></form></main>`;
  document.querySelector<HTMLFormElement>("#login-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget as HTMLFormElement);
    try { await request("/v1/auth/login", { method: "POST", body: JSON.stringify({ email: form.get("email"), password: form.get("password") }) }); await dashboardView(); } catch { loginView("Invalid credentials or API unavailable."); }
  });
}

async function dashboardView(): Promise<void> {
  try {
    const [{ user }, summary] = await Promise.all([request<{ user: User }>("/v1/auth/me"), request<Summary>("/v1/dashboard/summary")]);
    app.innerHTML = `<div class="shell"><aside class="sidebar"><div class="brand">DLP <span>SECURITY</span></div><nav class="nav"><button class="active">Overview</button><button>Detections</button><button>Devices</button><button>Policies</button><button>Team</button><button>Billing</button></nav></aside><main class="content"><div class="topline"><div><div class="eyebrow">${user.email}</div><h1 class="title">Security overview</h1><p class="muted">Organization protection status and recent metadata.</p></div><span class="pill">Protection active</span></div><section class="metrics"><article class="metric"><div class="metric-label">Protected devices</div><div class="metric-value">${summary.protectedDevices}</div></article><article class="metric"><div class="metric-label">Detections</div><div class="metric-value">${summary.detections}</div></article><article class="metric"><div class="metric-label">Blocked events</div><div class="metric-value">${summary.blockedEvents}</div></article><article class="metric"><div class="metric-label">Redactions</div><div class="metric-value">${summary.redactions}</div></article></section><section class="grid"><article class="panel"><h2>Recent detections</h2>${summary.recentEvents.length ? summary.recentEvents.map((event) => `<div class="event"><span>${new Date(event.occurredAt).toLocaleTimeString()}</span><span>${event.service} · ${event.secretType}</span><span class="severity">${event.severity}</span></div>`).join("") : `<div class="empty">No security events yet. Local extension scans stay private.</div>`}</article><article class="panel"><h2>Organization</h2><p class="muted">Role</p><strong>${user.role.replaceAll("_", " ")}</strong><p class="muted">Organization ID</p><code>${user.organizationId}</code><hr><button id="logout">Sign out</button></article></section></main></div>`;
    document.querySelector("#logout")?.addEventListener("click", async () => { await request("/v1/auth/logout", { method: "POST" }); loginView(); });
  } catch { loginView("Sign in to view the security console."); }
}

loginView();
