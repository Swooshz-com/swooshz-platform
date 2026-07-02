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
          <div class="topbar-actions">
            <a id="adminLink" class="secondary-action" href="/app/admin" hidden>Admin</a>
            <button id="logoutButton" class="secondary-action" type="button" hidden>Log out</button>
          </div>
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
            launch: "/api/platform/apps/launch/open",
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
          const adminLink = document.getElementById("adminLink");

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
            adminLink.hidden = true;
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
              adminLink.hidden = true;
              workspaces.append(emptyMessage("No active workspaces are available."));
              return;
            }

            const adminWorkspace = context.workspaces.find((workspace) =>
              workspace.membershipRole === "owner" || workspace.membershipRole === "admin"
            );
            if (adminWorkspace) {
              adminLink.href =
                "/app/admin?workspaceId=" + encodeURIComponent(adminWorkspace.workspaceId);
              adminLink.hidden = false;
            } else {
              adminLink.hidden = true;
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
            setStatus("Opening app...");
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

              if (!response.ok || payload.outcome !== "launch_opened" || !payload.launchUrl) {
                setStatus("App could not be opened.");
                return;
              }

              setStatus("Opening app...");
              window.location.assign(payload.launchUrl);
            } catch {
              setStatus("App could not be opened.");
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

export function renderAdminShellPage(): string {
  return htmlDocument({
    title: "Swooshz Platform Admin",
    body: `
      <main class="shell">
        <header class="topbar">
          <div>
            <p class="eyebrow">Swooshz Platform</p>
            <h1>Workspace Admin</h1>
          </div>
          <div class="topbar-actions">
            <a class="secondary-action" href="/app">App Access</a>
            <button id="logoutButton" class="secondary-action" type="button" hidden>Log out</button>
          </div>
        </header>

        <section id="status" class="status" role="status">Loading platform session...</section>
        <section id="identity" class="identity" hidden></section>
        <section id="workspaceSummary" class="workspace" hidden></section>
        <section id="addMember" class="workspace" hidden>
          <h2>Add Existing User</h2>
          <form id="addMemberForm" class="inline-form">
            <label>
              <strong>Email</strong>
              <input name="email" type="email" autocomplete="email" required>
            </label>
            <label>
              <strong>Role</strong>
              <select name="role" required>
                <option value="member">member</option>
                <option value="admin">admin</option>
                <option value="viewer">viewer</option>
              </select>
            </label>
            <button class="primary-action compact" type="submit">Add</button>
          </form>
        </section>
        <section id="members" class="workspace" hidden></section>
        <section id="entitlements" class="workspace" hidden></section>
      </main>
      <script>
        (() => {
          const endpoints = {
            context: "/api/platform/session/context",
            csrf: "/api/platform/session/csrf",
            logout: "/api/platform/logout"
          };

          const state = {
            context: null,
            csrfToken: null,
            workspace: null
          };

          const status = document.getElementById("status");
          const identity = document.getElementById("identity");
          const workspaceSummary = document.getElementById("workspaceSummary");
          const addMember = document.getElementById("addMember");
          const addMemberForm = document.getElementById("addMemberForm");
          const members = document.getElementById("members");
          const entitlements = document.getElementById("entitlements");
          const logoutButton = document.getElementById("logoutButton");

          logoutButton.addEventListener("click", () => {
            void logout();
          });
          addMemberForm.addEventListener("submit", (event) => {
            void addExistingMember(event);
          });

          void loadContext();

          async function loadContext() {
            setStatus("Loading platform session...");
            hideAdminSections();

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

              state.context = context;
              logoutButton.hidden = false;
              renderIdentity(context);

              const workspace = chooseWorkspace(context);
              if (!workspace) {
                renderForbidden();
                return;
              }

              state.workspace = workspace;
              await loadAdminData();
            } catch {
              setStatus("Workspace admin could not be loaded.");
            }
          }

          async function loadAdminData() {
            setStatus("Loading workspace admin...");
            const workspaceId = state.workspace.workspaceId;

            try {
              const [membersResponse, entitlementsResponse] = await Promise.all([
                fetch(adminMembersUrl(workspaceId), {
                  credentials: "same-origin",
                  cache: "no-store"
                }),
                fetch(adminEntitlementsUrl(workspaceId), {
                  credentials: "same-origin",
                  cache: "no-store"
                })
              ]);
              const membersPayload = await readJson(membersResponse);
              const entitlementsPayload = await readJson(entitlementsResponse);

              if (
                !membersResponse.ok ||
                !entitlementsResponse.ok ||
                membersPayload.outcome !== "listed" ||
                entitlementsPayload.outcome !== "listed"
              ) {
                renderForbidden();
                return;
              }

              renderWorkspaceSummary(state.workspace);
              addMember.hidden = false;
              renderMembers(membersPayload.members);
              renderEntitlements(entitlementsPayload.entitlements);
              setStatus("Workspace admin ready.");
            } catch {
              setStatus("Workspace admin could not be loaded.");
              hideAdminSections();
            }
          }

          function chooseWorkspace(context) {
            const params = new URLSearchParams(window.location.search);
            const requested = params.get("workspaceId");
            const adminWorkspaces = Array.isArray(context.workspaces)
              ? context.workspaces.filter((workspace) =>
                  workspace.membershipRole === "owner" || workspace.membershipRole === "admin"
                )
              : [];

            if (requested) {
              return adminWorkspaces.find((workspace) => workspace.workspaceId === requested) ?? null;
            }

            return adminWorkspaces[0] ?? null;
          }

          function renderUnauthenticated() {
            logoutButton.hidden = true;
            hideAdminSections();
            status.innerHTML =
              '<span>No active platform session.</span> ' +
              '<a href="/api/platform/auth/start">Sign in</a>';
          }

          function renderForbidden() {
            hideAdminSections();
            setStatus("Workspace admin is available to workspace owners and admins only.");
          }

          function renderIdentity(context) {
            identity.hidden = false;
            identity.replaceChildren(
              textBlock("Signed in as", context.user.displayName || context.user.email),
              textBlock("Email", context.user.email),
              textBlock("User status", context.user.status)
            );
          }

          function renderWorkspaceSummary(workspace) {
            workspaceSummary.hidden = false;
            workspaceSummary.replaceChildren(
              sectionHeading("Workspace"),
              textBlock("Name", workspace.workspaceName),
              textBlock("Workspace ID", workspace.workspaceId),
              textBlock("Role", workspace.membershipRole)
            );
          }

          function renderMembers(memberList) {
            members.hidden = false;
            members.replaceChildren(sectionHeading("Team Members"));

            if (!Array.isArray(memberList) || memberList.length === 0) {
              members.append(emptyMessage("No workspace members are available."));
              return;
            }

            const table = document.createElement("table");
            table.append(tableHead(["Name", "Email", "Role", "Status", "Last login", "Actions"]));
            const body = document.createElement("tbody");

            for (const member of memberList) {
              const row = document.createElement("tr");
              row.append(
                tableCell(member.user?.displayName || ""),
                tableCell(member.user?.email || ""),
                roleCell(member),
                tableCell(member.status || ""),
                tableCell(formatDate(member.user?.lastLoginAt)),
                memberActionsCell(member)
              );
              body.append(row);
            }

            table.append(body);
            members.append(table);
          }

          function renderEntitlements(entitlementList) {
            entitlements.hidden = false;
            entitlements.replaceChildren(sectionHeading("App Access"));

            if (!Array.isArray(entitlementList) || entitlementList.length === 0) {
              entitlements.append(emptyMessage("No app entitlements are configured."));
              return;
            }

            const list = document.createElement("div");
            list.className = "apps";

            for (const entitlement of entitlementList) {
              const row = document.createElement("article");
              row.className = "app-row";
              const detail = document.createElement("div");
              detail.append(
                textBlock("App", entitlement.appName || entitlement.appKey),
                textBlock("App key", entitlement.appKey),
                textBlock("App status", entitlement.appStatus),
                textBlock("Entitlement", entitlement.status),
                textBlock("Granted by", entitlement.grantedByUserId || "Not available"),
                textBlock("Updated", formatDate(entitlement.updatedAt))
              );
              row.append(detail);

              if (entitlement.appKey === "kqag") {
                const button = document.createElement("button");
                button.type = "button";
                button.className = "secondary-action compact";
                const nextStatus = entitlement.status === "enabled" ? "disabled" : "enabled";
                button.textContent = nextStatus === "enabled" ? "Enable" : "Disable";
                button.addEventListener("click", () => {
                  void updateEntitlement(nextStatus);
                });
                row.append(button);
              }

              list.append(row);
            }

            entitlements.append(list);
          }

          function roleCell(member) {
            const cell = document.createElement("td");
            const select = document.createElement("select");
            const roles = ["owner", "admin", "member", "viewer"];
            const isSelf = member.user?.id === state.context?.user?.userId;

            for (const role of roles) {
              const option = document.createElement("option");
              option.value = role;
              option.textContent = role;
              option.selected = member.role === role;
              select.append(option);
            }

            select.disabled = isSelf || member.status !== "active";
            select.addEventListener("change", () => {
              void changeMemberRole(member.membershipId, select.value);
            });
            cell.append(select);
            return cell;
          }

          function memberActionsCell(member) {
            const cell = document.createElement("td");
            const button = document.createElement("button");
            const isSelf = member.user?.id === state.context?.user?.userId;
            button.type = "button";
            button.className = "secondary-action compact";
            button.textContent = "Disable";
            button.disabled = isSelf || member.status !== "active";
            button.addEventListener("click", () => {
              void disableMember(member.membershipId);
            });
            cell.append(button);
            return cell;
          }

          async function changeMemberRole(membershipId, role) {
            await postAdminAction(
              adminMemberUrl(state.workspace.workspaceId, membershipId) +
                "/role?role=" + encodeURIComponent(role)
            );
          }

          async function disableMember(membershipId) {
            await postAdminAction(
              adminMemberUrl(state.workspace.workspaceId, membershipId) + "/disable"
            );
          }

          async function updateEntitlement(nextStatus) {
            await postAdminAction(
              adminEntitlementsUrl(state.workspace.workspaceId) +
                "/kqag/status?status=" + encodeURIComponent(nextStatus)
            );
          }

          async function addExistingMember(event) {
            event.preventDefault();
            const formData = new FormData(addMemberForm);
            const email = String(formData.get("email") || "");
            const role = String(formData.get("role") || "member");

            if (!email.trim()) {
              setStatus("Workspace admin action could not be completed.");
              return;
            }

            await postAdminAction(addMemberUrl(state.workspace.workspaceId, email, role));
            addMemberForm.reset();
          }

          async function postAdminAction(url) {
            setStatus("Saving workspace admin change...");

            try {
              const csrfToken = await getCsrfToken();
              const response = await fetch(url, {
                method: "POST",
                credentials: "same-origin",
                cache: "no-store",
                headers: {
                  "x-csrf-token": csrfToken
                }
              });

              if (!response.ok) {
                setStatus("Workspace admin action could not be completed.");
                await loadAdminData();
                return;
              }

              await loadAdminData();
            } catch {
              setStatus("Workspace admin action could not be completed.");
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

          function adminMembersUrl(workspaceId) {
            return "/api/platform/workspaces/" + encodeURIComponent(workspaceId) + "/members";
          }

          function addMemberUrl(workspaceId, email, role) {
            return adminMembersUrl(workspaceId) +
              "/add?email=" + encodeURIComponent(email) +
              "&role=" + encodeURIComponent(role);
          }

          function adminMemberUrl(workspaceId, membershipId) {
            return adminMembersUrl(workspaceId) + "/" + encodeURIComponent(membershipId);
          }

          function adminEntitlementsUrl(workspaceId) {
            return "/api/platform/workspaces/" +
              encodeURIComponent(workspaceId) +
              "/app-entitlements";
          }

          function hideAdminSections() {
            identity.hidden = true;
            workspaceSummary.hidden = true;
            addMember.hidden = true;
            members.hidden = true;
            entitlements.hidden = true;
            workspaceSummary.replaceChildren();
            addMemberForm.reset();
            members.replaceChildren();
            entitlements.replaceChildren();
          }

          function setStatus(message) {
            status.textContent = message;
          }

          function sectionHeading(value) {
            const heading = document.createElement("h2");
            heading.textContent = value;
            return heading;
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

          function tableHead(labels) {
            const head = document.createElement("thead");
            const row = document.createElement("tr");
            for (const label of labels) {
              const cell = document.createElement("th");
              cell.scope = "col";
              cell.textContent = label;
              row.append(cell);
            }
            head.append(row);
            return head;
          }

          function tableCell(value) {
            const cell = document.createElement("td");
            cell.textContent = value ?? "";
            return cell;
          }

          function formatDate(value) {
            if (!value) {
              return "Not available";
            }

            return String(value);
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

    .topbar-actions {
      display: flex;
      align-items: center;
      gap: 10px;
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

    .workspace + .workspace {
      margin-top: 16px;
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

    table {
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
    }

    th,
    td {
      padding: 12px 10px;
      border-top: 1px solid var(--line);
      text-align: left;
      vertical-align: middle;
      overflow-wrap: anywhere;
    }

    th {
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    select {
      width: 100%;
      min-height: 40px;
      padding: 0 10px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--surface);
      color: var(--ink);
      font: inherit;
    }

    input {
      width: 100%;
      min-height: 40px;
      padding: 0 10px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--surface);
      color: var(--ink);
      font: inherit;
    }

    .inline-form {
      display: grid;
      grid-template-columns: minmax(220px, 1fr) minmax(140px, 180px) auto;
      gap: 12px;
      align-items: end;
    }

    button:disabled,
    select:disabled {
      cursor: not-allowed;
      opacity: 0.55;
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

    .landing .primary-action {
      display: flex;
      width: max-content;
      margin-left: auto;
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

    [hidden] {
      display: none !important;
    }

    @media (max-width: 640px) {
      .topbar,
      .topbar-actions,
      .workspace-header,
      .app-row {
        align-items: stretch;
        flex-direction: column;
      }

      table,
      thead,
      tbody,
      tr,
      th,
      td,
      .inline-form {
        display: block;
        width: 100%;
      }

      th {
        display: none;
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
