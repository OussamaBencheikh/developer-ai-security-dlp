interface User { email: string; organizationId: string; role: string }
interface Summary { protectedDevices: number; detections: number; blockedEvents: number; redactions: number; recentEvents: { occurredAt: string; service: string; secretType: string; severity: string; action: string }[] }
interface Member { userId: string; email: string; role: string }

const api = "http://localhost:3000";
const app = document.querySelector<HTMLDivElement>("#app")!;

class ApiError extends Error {
  constructor(readonly status: number, message: string) { super(message); }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${api}${path}`, { ...options, credentials: "include", headers: { "Content-Type": "application/json", ...(options.headers ?? {}) } });
  } catch {
    throw new ApiError(0, "api_unavailable");
  }
  if (!response.ok) throw new ApiError(response.status, response.status === 401 ? "unauthorized" : "request_failed");
  return response.status === 204 ? ({} as T) : response.json() as Promise<T>;
}

function loginView(message = "", mode: "login" | "register" = "login"): void {
  const isRegister = mode === "register";
  app.innerHTML = `<main class="login"><form class="login-card" id="login-form"><div class="brand">DLP <span>SECURITY</span></div><p class="eyebrow">Developer protection console</p><h1 class="title">${isRegister ? "Create account" : "Sign in"}</h1><p class="muted">Review risk metadata without exposing prompts or secret values.</p><label>Email<input name="email" type="email" autocomplete="email" required placeholder="you@company.com"></label><label>Password<input name="password" type="password" autocomplete="${isRegister ? "new-password" : "current-password"}" required minlength="12"></label>${message ? `<p class="error">${message}</p>` : ""}<button class="primary" type="submit">${isRegister ? "Create account" : "Sign in"}</button><p class="muted">${isRegister ? "Already have an account?" : "Need an account?"} <a href="#" id="toggle-auth">${isRegister ? "Sign in" : "Register"}</a></p></form></main>`;
  document.querySelector<HTMLAnchorElement>("#toggle-auth")?.addEventListener("click", (event) => { event.preventDefault(); loginView("", isRegister ? "login" : "register"); });
  document.querySelector<HTMLFormElement>("#login-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget as HTMLFormElement);
    try { await request(isRegister ? "/v1/auth/register" : "/v1/auth/login", { method: "POST", body: JSON.stringify({ email: form.get("email"), password: form.get("password") }) }); await dashboardView(); } catch (error) {
      const message = isRegister
        ? error instanceof ApiError && error.status === 409 ? "This email is already registered. Sign in instead." : "Could not create account. Use a unique email and a password of at least 12 characters."
        : error instanceof ApiError && error.status === 0 ? "API unavailable. Start the API on http://localhost:3000." : "Account not found or password is incorrect. Use Register if this is your first login.";
      loginView(message, mode);
    }
  });
}

async function dashboardView(): Promise<void> {
  try {
    const [{ user }, summary] = await Promise.all([request<{ user: User }>("/v1/auth/me"), request<Summary>("/v1/dashboard/summary")]);
    app.innerHTML = `<div class="shell"><aside class="sidebar"><div class="brand">DLP <span>SECURITY</span></div><nav class="nav"><button data-view="overview" class="active">Overview</button><button data-view="detections">Detections</button><button data-view="devices">Devices</button><button data-view="policies">Policies</button><button data-view="team">Team</button><button data-view="billing">Billing</button><button data-view="admin">Admin</button></nav></aside><main class="content"><div class="topline"><div><div class="eyebrow">${user.email}</div><h1 class="title">Security overview</h1><p class="muted">Organization protection status and recent metadata.</p></div><span class="pill">Protection active</span></div><section class="metrics"><article class="metric"><div class="metric-label">Protected devices</div><div class="metric-value">${summary.protectedDevices}</div></article><article class="metric"><div class="metric-label">Detections</div><div class="metric-value">${summary.detections}</div></article><article class="metric"><div class="metric-label">Blocked events</div><div class="metric-value">${summary.blockedEvents}</div></article><article class="metric"><div class="metric-label">Redactions</div><div class="metric-value">${summary.redactions}</div></article></section><section class="grid"><article class="panel"><h2>Recent detections</h2>${summary.recentEvents.length ? summary.recentEvents.map((event) => `<div class="event"><span>${new Date(event.occurredAt).toLocaleTimeString()}</span><span>${event.service} · ${event.secretType}</span><span class="severity">${event.severity}</span></div>`).join("") : `<div class="empty">No security events yet. Local extension scans stay private.</div>`}</article><article class="panel"><h2>Organization</h2><p class="muted">Role</p><strong>${user.role.replaceAll("_", " ")}</strong><p class="muted">Organization ID</p><code>${user.organizationId}</code><hr><button id="logout">Sign out</button></article></section><section id="workspace-panel"></section></main></div>`;
    document.querySelector("#logout")?.addEventListener("click", async () => { await request("/v1/auth/logout", { method: "POST" }); loginView(); });
    document.querySelectorAll<HTMLButtonElement>("[data-view]").forEach((button) => button.addEventListener("click", () => {
      document.querySelectorAll("[data-view]").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      void renderWorkspacePanel(button.dataset.view ?? "overview");
    }));
  } catch { loginView("Sign in to view the security console."); }
}

async function renderWorkspacePanel(view: string): Promise<void> {
  const panel = document.querySelector<HTMLElement>("#workspace-panel");
  if (!panel || view === "overview") { if (panel) panel.innerHTML = ""; return; }
  if (view === "team") {
    const data = await request<{ members: Member[] }>("/v1/team");
    panel.innerHTML = `<article class="panel workspace"><h2>Team members</h2>${data.members.map((member) => `<div class="event"><span>${member.email}</span><span>${member.role.replaceAll("_", " ")}</span><span>${member.userId.startsWith("pending_") ? "Pending" : "Active"}</span></div>`).join("")}<form id="member-form"><label>Email<input name="email" type="email" required placeholder="member@company.com"></label><label>Role<select name="role"><option value="member">Member</option><option value="viewer">Viewer</option><option value="security_admin">Security admin</option><option value="admin">Admin</option></select></label><button class="primary" type="submit">Add member</button></form></article>`;
    panel.querySelector("form")?.addEventListener("submit", async (event) => { event.preventDefault(); const form = new FormData(event.currentTarget as HTMLFormElement); await request("/v1/team/members", { method: "POST", body: JSON.stringify({ email: form.get("email"), role: form.get("role") }) }); await renderWorkspacePanel("team"); });
    return;
  }
  if (view === "billing") {
    const billing = await request<{ plan: string; provider: string; entitlements: string[] }>("/v1/billing");
    panel.innerHTML = `<article class="panel workspace"><h2>Billing and entitlements</h2><p class="muted">Current plan</p><strong>${billing.plan}</strong><p class="muted">Provider</p><strong>${billing.provider}</strong><p class="muted">Features</p><div>${billing.entitlements.join(" · ")}</div><p class="empty">Payment provider integration is not configured in local development.</p></article>`;
    return;
  }
  if (view === "admin") {
    const health = await request<{ api: string; database: string; version: string }>("/v1/admin/health");
    panel.innerHTML = `<article class="panel workspace"><h2>Admin system health</h2><div class="event"><span>API</span><strong>${health.api}</strong></div><div class="event"><span>Database</span><strong>${health.database}</strong></div><div class="event"><span>Version</span><strong>${health.version}</strong></div></article>`;
    return;
  }
  panel.innerHTML = `<article class="panel workspace"><h2>${view[0]?.toUpperCase()}${view.slice(1)}</h2><p class="empty">This view is connected to the product navigation and is ready for its persisted data endpoint.</p></article>`;
}

loginView();
