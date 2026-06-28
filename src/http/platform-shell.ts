export function renderLandingPage(): string {
  return htmlDocument({
    title: "Swooshz Platform",
    body: `
      <main class="landing">
        <section class="panel">
          <p class="eyebrow">Internal platform shell</p>
          <h1>Swooshz Platform</h1>
          <p class="lede">
            Sign in to review your platform session, workspace access, and app
            launch options.
          </p>
          <a class="primary-action" href="/api/platform/auth/start">Sign in</a>
        </section>
      </main>
    `,
  });
}

export function renderAppShellPage(): string {
  return htmlDocument({
    title: "Swooshz Platform App",
    body: `
      <main class="shell">
        <header class="topbar">
          <div>
            <p class="eyebrow">Swooshz Platform</p>
            <h1>App Access</h1>
          </div>
          <button id="logoutButton" class="secondary-action" type="button" hidden>Log out</button>
        </header>

        <section id="status" class="status" role="status">Loading platform session...</section>
        <section id="identity" class="identity" hidden></section>
        <section id="workspaces" class="workspace-list" aria-live="polite"></section>
        <section id="launchResult" class="handoff" hidden></section>
      </main>
      <script>
        (() => {
          const endpoints = {
            context: "/api/platform/session/context",
            csrf: "/api/platform/session/csrf",
            launch: "/api/platform/apps/launch",
            logout: "/api/platform/logout"
          };

          const state = {
            csrfToken: null
          };

          const status = document.getElementById("status");
          const identity = document.getElementById("identity");
          const workspaces = document.getElementById("workspaces");
          const launchResult = document.getElementById("launchResult");
          const logoutButton = document.getElementById("logoutButton");

          logoutButton.addEventListener("click", () => {
            void logout();
          });

          void loadContext();

          async function loadContext() {
            setStatus("Loading platform session...");

            try {
              const response = await fetch(endpoints.context, {
                credentials: "same-origin",
                cache: "no-store"
              });
              const context = await readJson(response);

              if (!response.ok || context.outcome !== "authenticated") {
                renderUnauthenticated();
                return;
              }

              renderAuthenticated(context);
            } catch {
              setStatus("Platform session could not be loaded.");
            }
          }

          function renderUnauthenticated() {
            logoutButton.hidden = true;
            identity.hidden = true;
            workspaces.replaceChildren();
            launchResult.hidden = true;
            status.innerHTML =
              '<span>No active platform session.</span> ' +
              '<a href="/api/platform/auth/start">Sign in</a>';
          }

          function renderAuthenticated(context) {
            logoutButton.hidden = false;
            setStatus("Platform session active.");

            identity.hidden = false;
            identity.replaceChildren(
              textBlock("Signed in as", context.user.displayName || context.user.email),
              textBlock("Email", context.user.email),
              textBlock("User status", context.user.status)
            );

            workspaces.replaceChildren();

            if (!Array.isArray(context.workspaces) || context.workspaces.length === 0) {
              workspaces.append(emptyMessage("No active workspaces are available."));
              return;
            }

            for (const workspace of context.workspaces) {
              workspaces.append(renderWorkspace(workspace));
            }
          }

          function renderWorkspace(workspace) {
            const section = document.createElement("section");
            section.className = "workspace";

            const header = document.createElement("div");
            header.className = "workspace-header";
            header.append(
              textBlock("Workspace", workspace.workspaceName || workspace.workspaceId),
              textBlock("Role", workspace.membershipRole || "member")
            );
            section.append(header);

            const apps = document.createElement("div");
            apps.className = "apps";
            const appList = Array.isArray(workspace.apps) ? workspace.apps : [];

            if (appList.length === 0) {
              apps.append(emptyMessage("No apps are registered for this workspace."));
            }

            for (const app of appList) {
              apps.append(renderApp(workspace, app));
            }

            section.append(apps);
            return section;
          }

          function renderApp(workspace, app) {
            const row = document.createElement("article");
            row.className = "app-row";

            const detail = document.createElement("div");
            detail.append(
              textBlock("App", app.appName || app.appKey),
              textBlock("Access", app.access?.message || app.access?.result || "Unavailable")
            );
            row.append(detail);

            if (app.access?.allowed === true) {
              const button = document.createElement("button");
              button.type = "button";
              button.className = "primary-action compact";
              button.textContent = "Launch";
              button.addEventListener("click", () => {
                void launchApp(workspace.workspaceId, app.appKey);
              });
              row.append(button);
            }

            return row;
          }

          async function launchApp(workspaceId, appKey) {
            setStatus("Creating app launch intent...");
            launchResult.hidden = true;

            try {
              const csrfToken = await getCsrfToken();
              const response = await fetch(
                endpoints.launch +
                  "?workspaceId=" + encodeURIComponent(workspaceId) +
                  "&appKey=" + encodeURIComponent(appKey),
                {
                  method: "POST",
                  credentials: "same-origin",
                  cache: "no-store",
                  headers: {
                    "x-csrf-token": csrfToken
                  }
                }
              );
              const payload = await readJson(response);

              if (!response.ok || payload.outcome !== "launch_intent_created") {
                setStatus("App launch intent could not be created.");
                return;
              }

              renderLaunchPayload(payload);
              setStatus("App launch intent created.");
            } catch {
              setStatus("App launch intent could not be created.");
            }
          }

          async function getCsrfToken() {
            if (state.csrfToken) {
              return state.csrfToken;
            }

            const response = await fetch(endpoints.csrf, {
              credentials: "same-origin",
              cache: "no-store"
            });
            const payload = await readJson(response);

            if (!response.ok || payload.outcome !== "issued" || !payload.csrfToken) {
              throw new Error("CSRF token unavailable.");
            }

            state.csrfToken = payload.csrfToken;
            return state.csrfToken;
          }

          function renderLaunchPayload(payload) {
            launchResult.replaceChildren();

            const title = document.createElement("h2");
            title.textContent = "Temporary internal handoff";
            launchResult.append(title);

            if (payload.launchUrl) {
              launchResult.append(textBlock("Launch URL", payload.launchUrl));
            }

            launchResult.append(
              textBlock("App key", payload.appKey),
              textBlock("Workspace", payload.workspaceId),
              textBlock("Expires", payload.launchTokenExpiresAt)
            );

            const tokenBox = document.createElement("pre");
            tokenBox.className = "token-box";
            tokenBox.textContent = payload.launchToken || "";
            launchResult.append(tokenBox);

            if (payload.launchToken && navigator.clipboard?.writeText) {
              const copy = document.createElement("button");
              copy.type = "button";
              copy.className = "secondary-action";
              copy.textContent = "Copy token";
              copy.addEventListener("click", async () => {
                await navigator.clipboard.writeText(payload.launchToken);
                setStatus("Launch token copied.");
              });
              launchResult.append(copy);
            }

            launchResult.hidden = false;
          }

          async function logout() {
            setStatus("Signing out...");

            try {
              const csrfToken = await getCsrfToken();
              await fetch(endpoints.logout, {
                method: "POST",
                credentials: "same-origin",
                cache: "no-store",
                headers: {
                  "x-csrf-token": csrfToken
                }
              });
            } finally {
              window.location.assign("/");
            }
          }

          async function readJson(response) {
            try {
              return await response.json();
            } catch {
              return {};
            }
          }

          function setStatus(message) {
            status.textContent = message;
          }

          function textBlock(label, value) {
            const block = document.createElement("p");
            const strong = document.createElement("strong");
            strong.textContent = label;
            const span = document.createElement("span");
            span.textContent = value ?? "";
            block.append(strong, span);
            return block;
          }

          function emptyMessage(message) {
            const node = document.createElement("p");
            node.className = "empty";
            node.textContent = message;
            return node;
          }
        })();
      </script>
    `,
  });
}

function htmlDocument({
  title,
  body,
}: {
  title: string;
  body: string;
}): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title}</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f4f6f8;
      --surface: #ffffff;
      --ink: #18212b;
      --muted: #5d6b78;
      --line: #d7dde3;
      --accent: #0f766e;
      --accent-strong: #115e59;
      --danger-soft: #fef3c7;
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      min-height: 100vh;
      background: var(--bg);
      color: var(--ink);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.5;
    }

    a,
    button {
      font: inherit;
    }

    .landing,
    .shell {
      width: min(1120px, calc(100% - 32px));
      margin: 0 auto;
    }

    .landing {
      min-height: 100vh;
      display: grid;
      place-items: center;
    }

    .panel,
    .workspace,
    .handoff {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
    }

    .panel {
      width: min(520px, 100%);
      padding: 40px;
    }

    .shell {
      padding: 32px 0 48px;
    }

    .topbar,
    .workspace-header,
    .app-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
    }

    .topbar {
      margin-bottom: 20px;
    }

    .eyebrow {
      margin: 0 0 8px;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    h1,
    h2,
    p {
      margin-top: 0;
    }

    h1 {
      margin-bottom: 12px;
      font-size: 42px;
      line-height: 1;
      letter-spacing: 0;
    }

    h2 {
      font-size: 18px;
    }

    .lede,
    .status,
    .empty {
      color: var(--muted);
    }

    .status,
    .identity {
      margin-bottom: 16px;
    }

    .identity {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 10px;
    }

    .identity p,
    .workspace p,
    .handoff p {
      margin: 0;
    }

    strong,
    span {
      display: block;
    }

    strong {
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .workspace-list {
      display: grid;
      gap: 16px;
    }

    .workspace,
    .handoff {
      padding: 20px;
    }

    .workspace-header {
      align-items: flex-start;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--line);
    }

    .apps {
      display: grid;
      gap: 10px;
      padding-top: 16px;
    }

    .app-row {
      min-height: 76px;
      padding: 14px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fbfaf7;
    }

    .primary-action,
    .secondary-action {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 44px;
      padding: 0 18px;
      border-radius: 6px;
      border: 1px solid transparent;
      cursor: pointer;
      text-decoration: none;
      white-space: nowrap;
    }

    .primary-action {
      background: var(--accent);
      color: #ffffff;
    }

    .primary-action:hover {
      background: var(--accent-strong);
    }

    .secondary-action {
      background: var(--surface);
      border-color: var(--line);
      color: var(--ink);
    }

    .compact {
      min-width: 104px;
    }

    .handoff {
      margin-top: 18px;
      background: var(--danger-soft);
    }

    .token-box {
      max-width: 100%;
      overflow-x: auto;
      padding: 12px;
      border-radius: 6px;
      background: var(--surface);
      border: 1px solid var(--line);
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }

    [hidden] {
      display: none !important;
    }

    @media (max-width: 640px) {
      .topbar,
      .workspace-header,
      .app-row {
        align-items: stretch;
        flex-direction: column;
      }

      .panel {
        padding: 28px;
      }

      h1 {
        font-size: 34px;
      }

      .primary-action,
      .secondary-action {
        width: 100%;
      }
    }
  </style>
</head>
<body>
${body}
</body>
</html>`;
}
