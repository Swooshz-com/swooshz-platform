export function renderLandingPage(): string {
  return htmlDocument({
    title: "Swooshz Platform",
    body: `
      ${publicNav("home")}
      <main class="public-page">
        <section class="public-hero">
          <div class="hero-copy">
            <h1>The workspace platform for launching trusted business apps</h1>
            <p class="lede">
              Coordinate approved workspace access, app entitlements, and
              separate product launches from one controlled Platform shell.
            </p>
            <div class="button-row">
              <a class="primary-action" href="/login">Access entry</a>
              <a class="secondary-action" href="/solutions">View solutions</a>
            </div>
          </div>
          <div class="architecture-card" aria-label="Platform launch architecture preview">
            <div class="architecture-bar">
              <span>Swooshz Platform</span>
              <span>Access control</span>
            </div>
            <div class="architecture-grid">
              <span>Provider identity</span>
              <span>Workspace membership</span>
              <span>App entitlement</span>
              <span>Launch token</span>
              <span>Separate app handoff</span>
              <span>Audit event</span>
            </div>
          </div>
        </section>
        <section class="public-band">
          <div class="section-heading">
            <h2>Core Modules</h2>
            <p>Purpose-built access surfaces for specialized operational requirements.</p>
          </div>
          <div class="module-grid">
            <article class="module-card module-card-wide">
              <div class="card-title-row">
                <h3>Swooshz Quote Auto Generator</h3>
                <span class="icon-mark" aria-hidden="true">doc</span>
              </div>
              <p>
                Swooshz Quote Auto Generator is a separate app launched from
                Platform after workspace access and entitlement checks pass.
              </p>
              <div class="mini-workflow" aria-label="Launch boundary">
                <span>Platform access</span>
                <span>Entitlement check</span>
                <span>Separate app launch</span>
              </div>
            </article>
            <div class="module-stack">
              <article class="module-card muted-card">
                <div class="card-title-row">
                  <h3>SEO / GEO / Seozilla</h3>
                  <span class="status-pill">Coming soon</span>
                </div>
                <p>Vendor workflow pending. Unavailable until confirmed.</p>
              </article>
              <article class="module-card muted-card">
                <div class="card-title-row">
                  <h3>Platform workspace controls</h3>
                  <span class="status-pill">Available</span>
                </div>
                <p>Memberships, roles, entitlements, launch checks, and audit activity.</p>
              </article>
            </div>
          </div>
        </section>
        <section class="process-section">
          <div class="section-heading centered">
            <h2>Standardized Execution</h2>
            <p>A controlled three-step path for launching approved workspace apps.</p>
          </div>
          <div class="process-grid">
            <article>
              <span>01</span>
              <h3>Workspace approval</h3>
              <p>Provider-backed users must belong to an approved workspace.</p>
            </article>
            <article>
              <span>02</span>
              <h3>Entitlement check</h3>
              <p>Platform verifies the selected app is available for that workspace.</p>
            </article>
            <article>
              <span>03</span>
              <h3>Separate app launch</h3>
              <p>Launch opens the product app without embedding product workflow data.</p>
            </article>
          </div>
        </section>
      </main>
      ${publicFooter()}
    `,
  });
}

export function renderSolutionsPage(): string {
  return htmlDocument({
    title: "Swooshz Platform Solutions",
    body: `
      ${publicNav("solutions")}
      <main class="public-page">
        <section class="solutions-hero">
          <div class="hero-copy">
            <p class="utility-label">Institutional utility</p>
            <h1>Swooshz Quote Auto Generator</h1>
            <p class="lede">
              A separate product app launched from Platform for approved
              workspaces with active access and entitlement checks.
            </p>
            <div class="button-row">
              <a class="primary-action" href="/login">Access entry</a>
            </div>
          </div>
          <div class="product-preview" aria-label="Swooshz Quote Auto Generator launch preview">
            <div class="preview-window-bar">
              <span>Quote generator preview</span>
              <span aria-hidden="true">...</span>
            </div>
            <div class="preview-empty">
              <span class="icon-mark large" aria-hidden="true">doc</span>
              <p>Swooshz Quote Auto Generator opens as a separate app after Platform launch checks.</p>
            </div>
          </div>
        </section>
        <section class="public-band">
          <div class="section-heading">
            <h2>Core Platform Capabilities</h2>
            <p>Engineered for controlled access, clear ownership boundaries, and auditability.</p>
          </div>
          <div class="capability-grid">
            <article class="module-card module-card-wide">
              <span class="icon-mark" aria-hidden="true">shield</span>
              <h3>Access Management</h3>
              <p>
                Platform owns provider identities, sessions, workspace
                memberships, roles, and app launch eligibility.
              </p>
              <div class="role-rail" aria-label="Visible workspace roles">
                <span>Owner</span>
                <span>Admin</span>
                <span>Member</span>
                <span>Pending</span>
              </div>
            </article>
            <article class="module-card">
              <span class="icon-mark" aria-hidden="true">nodes</span>
              <h3>Workspace Entitlements</h3>
              <p>
                App availability is controlled at the workspace boundary and
                fails closed when access is unavailable.
              </p>
            </article>
            <article class="module-card unavailable-card">
              <span class="icon-mark large" aria-hidden="true">geo</span>
              <h3>SEO / GEO / Seozilla</h3>
              <p>Vendor workflow pending. Unavailable until confirmed.</p>
              <span class="status-pill">Coming soon</span>
            </article>
          </div>
        </section>
      </main>
      ${publicFooter()}
    `,
  });
}

export function renderLoginPage(): string {
  return htmlDocument({
    title: "Swooshz Platform Access",
    body: `
      <main class="login-canvas">
        <section class="access-panel">
          <div class="access-heading">
            <h1>Swooshz</h1>
            <p>Secure Access Portal</p>
          </div>
          <p id="signedOutNotice" class="signed-out" hidden>
            You are signed out of Swooshz Platform. Your Google account may
            still be signed in.
          </p>
          <p class="lede">
            Access requires an approved provider-backed account for your
            workspace. No public signup is available.
          </p>
          <p class="helper">Use the approved Google account for your workspace.</p>
          <div class="login-actions">
            <a class="primary-action" href="/api/platform/auth/start">Continue with Google</a>
            <a class="secondary-action" href="/app">Already signed in? Continue to app</a>
          </div>
        </section>
        <div class="login-lines" aria-hidden="true"></div>
      </main>
      ${publicFooter()}
      <script>
        (() => {
          const params = new URLSearchParams(window.location.search);
          const notice = document.getElementById("signedOutNotice");
          if (params.get("signedOut") === "1" && notice) {
            notice.hidden = false;
          }
        })();
      </script>
    `,
  });
}

export function renderAppShellPage(): string {
  return htmlDocument({
    title: "Swooshz Platform App",
    body: `
      <div class="portal-layout">
        <aside class="portal-sidebar">
          <div class="portal-brand">
            <span class="brand-mark" aria-hidden="true">apps</span>
            <div>
              <h1>Swooshz Platform</h1>
              <p>Enterprise Workspace</p>
            </div>
          </div>
          <button class="primary-action sidebar-launch" type="button" disabled>Launch Apps</button>
          <nav class="portal-nav" aria-label="Workspace navigation">
            <a class="portal-nav-active" href="/app">Home</a>
            <a href="/app">Apps</a>
            <a id="adminLink" href="/app/admin" hidden>Admin</a>
            <span aria-disabled="true">Members</span>
            <span aria-disabled="true">Activity</span>
          </nav>
          <button id="logoutButton" class="sidebar-logout" type="button" hidden>Sign out of Swooshz Platform</button>
        </aside>
        <main class="portal-main">
          <header class="portal-topbar">
            <p>Platform</p>
            <div class="portal-topbar-actions" aria-hidden="true">
              <span>bell</span>
              <span>history</span>
              <span>account</span>
            </div>
          </header>
          <section class="portal-canvas">
            <div class="portal-heading">
              <h2>App Launcher</h2>
              <p>Select a workspace app to begin.</p>
            </div>
            <section id="status" class="status" role="status">Loading platform session...</section>
            <section id="identity" class="identity" hidden></section>
            <section id="workspaces" class="workspace-list" aria-live="polite"></section>
            <section id="launchResult" class="handoff" hidden></section>
          </section>
        </main>
      </div>
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
              '<a href="/api/platform/auth/start">Continue with Google</a>';
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
              workspaces.append(emptyMessage("No workspace access is available for this account."));
              return;
            }

            const adminWorkspace = context.workspaces.find((workspace) =>
              workspace.membershipRole === "owner" || workspace.membershipRole === "admin"
            );
            if (adminWorkspace) {
              const adminWorkspaces = context.workspaces.filter((workspace) =>
                workspace.membershipRole === "owner" || workspace.membershipRole === "admin"
              );
              adminLink.href = adminWorkspaces.length === 1
                ? "/app/admin"
                : "/app/admin?workspace=" + encodeURIComponent(adminWorkspace.workspaceSlug);
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
              textBlock("App", displayAppName(app)),
              textBlock("Access", app.access?.allowed === true ? "Access available." : "Unavailable.")
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
            } else {
              row.append(renderUnavailableApp(app));
            }

            return row;
          }

          function renderUnavailableApp(app) {
            const node = document.createElement("div");
            node.className = "unavailable-state";

            const title = document.createElement("strong");
            title.textContent = "Product unavailable";
            const message = document.createElement("span");
            message.textContent = unavailableAccessMessage(app);

            const actions = document.createElement("div");
            actions.className = "unavailable-actions";
            const returnLink = document.createElement("a");
            returnLink.className = "secondary-action compact";
            returnLink.href = "/app";
            returnLink.textContent = "Return to apps";
            const contact = document.createElement("span");
            contact.className = "contact-admin";
            contact.textContent = "Contact workspace admin";
            actions.append(returnLink, contact);

            node.append(title, message, actions);
            return node;
          }

          function displayAppName(app) {
            const key = String(app.appKey || "").toLowerCase();
            const name = String(app.appName || "");

            if (key === "sqag" || name.toLowerCase() === "sqag") {
              return "Swooshz Quote Auto Generator";
            }

            return name || app.appKey || "Workspace app";
          }

          function accessMessage(app) {
            if (app.access?.allowed === true) {
              return "Access available.";
            }

            return app.access?.message ||
              "This workspace access or entitlement is not available for this product.";
          }

          function unavailableAccessMessage(app) {
            const message = String(app.access?.message || "");

            if (message.toLowerCase().includes("vendor workflow pending")) {
              return "Vendor workflow pending.";
            }

            return "Access unavailable.";
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
              window.location.assign("/login?signedOut=1");
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
      <div class="portal-layout admin-layout">
        <aside class="portal-sidebar">
          <div class="portal-brand">
            <span class="brand-mark" aria-hidden="true">S</span>
            <div>
              <h1>Swooshz Platform</h1>
              <p>Enterprise Workspace</p>
            </div>
          </div>
          <a class="primary-action sidebar-launch" href="/app">Launch Apps</a>
          <nav class="portal-nav" aria-label="Workspace admin navigation">
            <a href="/app">Home</a>
            <a href="/app">Apps</a>
            <a class="portal-nav-active" href="/app/admin">Members</a>
            <a href="#activity">Activity</a>
            <span aria-disabled="true">Help</span>
            <span aria-disabled="true">Settings</span>
          </nav>
          <button id="logoutButton" class="sidebar-logout" type="button" hidden>Sign out of Swooshz Platform</button>
        </aside>
        <main class="portal-main">
          <header class="portal-topbar">
            <div class="portal-topbar-actions" aria-hidden="true">
              <span class="topbar-icon"></span>
              <span class="topbar-icon topbar-icon-history"></span>
              <span class="topbar-icon topbar-icon-account"></span>
            </div>
          </header>
          <section class="portal-canvas admin-canvas">
            <div class="admin-page-header">
              <div class="portal-heading">
                <h2>Workspace Members</h2>
                <p>Manage access and roles for your workspace.</p>
              </div>
              <button id="openAddMemberButton" class="primary-action compact" type="button" hidden>Add Member</button>
            </div>
            <section id="status" class="status" role="status">Loading platform session...</section>
            <section id="adminActionStatus" class="action-status" role="status" hidden>
              <span class="spinner" aria-hidden="true"></span>
              <span id="adminActionStatusText"></span>
            </section>
            <section id="identity" class="identity admin-summary-grid" hidden></section>
            <section id="workspaceSummary" class="workspace admin-summary" hidden></section>
            <section id="ownerTransfer" class="workspace admin-surface" hidden>
              <h2>Owner Transfer</h2>
              <p class="empty">
                Owner transfer is not available in internal alpha yet. Use a
                reviewed operator process before hosted execution.
              </p>
            </section>
            <section id="members" class="workspace admin-surface" data-admin-section="members" hidden></section>
            <section id="pendingApprovals" class="workspace admin-surface" data-admin-section="pending-approvals" hidden></section>
            <section id="activity" class="workspace admin-surface" data-admin-section="activity" hidden></section>
            <section id="entitlements" class="workspace admin-surface" data-admin-section="app-access" hidden></section>
          </section>
        </main>
      </div>
      <div id="addMemberModal" class="modal-backdrop" hidden>
        <section
          class="action-modal add-member-modal"
          role="dialog"
          aria-modal="true"
          aria-labelledby="addMemberModalTitle"
          aria-describedby="addMemberModalBody"
        >
          <div class="modal-header">
            <h2 id="addMemberModalTitle">Add Member</h2>
            <button id="closeAddMemberModalButton" class="modal-close" type="button" aria-label="Close add member form">&times;</button>
          </div>
          <div class="modal-body">
            <p id="addMemberModalBody" class="empty">
              Create a pending workspace access approval or add an existing
              provider-backed user. Access activates through the existing
              provider-backed sign-in flow.
            </p>
            <p id="addMemberResult" class="empty" role="status" hidden></p>
            <form id="addMemberForm" class="field-stack">
              <label>
                <strong>Email address</strong>
                <input name="email" type="email" autocomplete="email" placeholder="workspace.user@example.com" required>
              </label>
              <label>
                <strong>Workspace role</strong>
                <select name="role" required>
                  <option value="admin">Admin</option>
                  <option value="member" selected>Member</option>
                </select>
              </label>
              <div class="modal-actions">
                <button id="cancelAddMemberModalButton" class="secondary-action compact" type="button">Cancel</button>
                <button class="primary-action compact" type="submit">Add member</button>
              </div>
            </form>
          </div>
        </section>
      </div>
      <div id="adminActionModal" class="modal-backdrop" hidden>
        <section
          class="action-modal member-action-modal"
          role="dialog"
          aria-modal="true"
          aria-labelledby="adminActionModalTitle"
          aria-describedby="adminActionModalBody"
        >
          <div class="modal-header">
            <h2 id="adminActionModalTitle">Remove member?</h2>
            <button id="adminActionModalCancel" class="modal-close" type="button" aria-label="Cancel member action">&times;</button>
          </div>
          <div class="modal-body">
            <p id="adminActionModalBody">
              This removes workspace access for this member. Their platform account is not deleted.
            </p>
            <p id="adminActionModalLoading" class="modal-loading" role="status" hidden>
              <span class="spinner" aria-hidden="true"></span>
              <span id="adminActionModalLoadingText">Removing member...</span>
            </p>
            <p id="adminActionModalError" class="modal-error" role="alert" hidden></p>
          </div>
          <div class="modal-actions modal-footer">
            <button id="adminActionModalDismiss" class="secondary-action compact" type="button">Cancel</button>
            <button id="adminActionModalConfirm" class="primary-action compact" type="button">Remove member</button>
          </div>
        </section>
      </div>
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
            workspace: null,
            activityEvents: [],
            activityPage: 0,
            activityPageSize: 10,
            modalAction: null
          };

          const status = document.getElementById("status");
          const adminActionStatus = document.getElementById("adminActionStatus");
          const adminActionStatusText = document.getElementById("adminActionStatusText");
          const identity = document.getElementById("identity");
          const workspaceSummary = document.getElementById("workspaceSummary");
          const addMember = document.getElementById("addMemberModal");
          const openAddMemberButton = document.getElementById("openAddMemberButton");
          const closeAddMemberModalButton = document.getElementById("closeAddMemberModalButton");
          const cancelAddMemberModalButton = document.getElementById("cancelAddMemberModalButton");
          const addMemberResult = document.getElementById("addMemberResult");
          const addMemberForm = document.getElementById("addMemberForm");
          const ownerTransfer = document.getElementById("ownerTransfer");
          const pendingApprovals = document.getElementById("pendingApprovals");
          const members = document.getElementById("members");
          const entitlements = document.getElementById("entitlements");
          const activity = document.getElementById("activity");
          const logoutButton = document.getElementById("logoutButton");
          const adminActionModal = document.getElementById("adminActionModal");
          const modalTitle = document.getElementById("adminActionModalTitle");
          const modalBody = document.getElementById("adminActionModalBody");
          const modalLoading = document.getElementById("adminActionModalLoading");
          const modalLoadingText = document.getElementById("adminActionModalLoadingText");
          const modalError = document.getElementById("adminActionModalError");
          const modalCancelButton = document.getElementById("adminActionModalCancel");
          const modalDismissButton = document.getElementById("adminActionModalDismiss");
          const modalConfirmButton = document.getElementById("adminActionModalConfirm");

          logoutButton.addEventListener("click", () => {
            void logout();
          });
          addMemberForm.addEventListener("submit", (event) => {
            void addExistingMember(event);
          });
          openAddMemberButton.addEventListener("click", () => {
            openAddMemberModal();
          });
          closeAddMemberModalButton.addEventListener("click", () => {
            closeAddMemberModal();
          });
          cancelAddMemberModalButton.addEventListener("click", () => {
            closeAddMemberModal();
          });
          modalCancelButton.addEventListener("click", () => {
            closeActionModal();
          });
          modalDismissButton.addEventListener("click", () => {
            closeActionModal();
          });
          modalConfirmButton.addEventListener("click", () => {
            void runModalAction();
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
              const [
                membersResponse,
                approvalsResponse,
                entitlementsResponse,
                activityResponse
              ] = await Promise.all([
                fetch(adminMembersUrl(workspaceId), {
                  credentials: "same-origin",
                  cache: "no-store"
                }),
                fetch(adminApprovalsUrl(workspaceId), {
                  credentials: "same-origin",
                  cache: "no-store"
                }),
                fetch(adminEntitlementsUrl(workspaceId), {
                  credentials: "same-origin",
                  cache: "no-store"
                }),
                fetch(adminAuditEventsUrl(workspaceId), {
                  credentials: "same-origin",
                  cache: "no-store"
                })
              ]);
              const membersPayload = await readJson(membersResponse);
              const approvalsPayload = await readJson(approvalsResponse);
              const entitlementsPayload = await readJson(entitlementsResponse);
              const activityPayload = await readJson(activityResponse);

              if (
                !membersResponse.ok ||
                !approvalsResponse.ok ||
                !entitlementsResponse.ok ||
                !activityResponse.ok ||
                membersPayload.outcome !== "listed" ||
                approvalsPayload.outcome !== "listed" ||
                entitlementsPayload.outcome !== "listed" ||
                activityPayload.outcome !== "listed"
              ) {
                renderForbidden();
                return;
              }

              renderWorkspaceSummary(state.workspace);
              openAddMemberButton.hidden = false;
              ownerTransfer.hidden = false;
              renderPendingApprovals(approvalsPayload.approvals);
              renderMembers(membersPayload.members);
              renderEntitlements(entitlementsPayload.entitlements);
              renderActivity(activityPayload.events);
              setStatus("Workspace admin ready.");
            } catch {
              setStatus("Workspace admin could not be loaded.");
              hideAdminSections();
            }
          }

          function chooseWorkspace(context) {
            const params = new URLSearchParams(window.location.search);
            const requestedSlug = params.get("workspace");
            const requested = params.get("workspaceId");
            const adminWorkspaces = Array.isArray(context.workspaces)
              ? context.workspaces.filter((workspace) =>
                  workspace.membershipRole === "owner" || workspace.membershipRole === "admin"
                )
              : [];

            if (requestedSlug) {
              return adminWorkspaces.find((workspace) => workspace.workspaceSlug === requestedSlug) ?? null;
            }

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
              '<a href="/api/platform/auth/start">Continue with Google</a>';
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
              textBlock("Workspace slug", workspace.workspaceSlug),
              textBlock("Role", workspace.membershipRole)
            );
          }

          function renderMembers(memberList) {
            members.hidden = false;
            members.replaceChildren(
              sectionHeading("Workspace Members"),
              sectionDescription("Current workspace access and supported roles.")
            );

            if (!Array.isArray(memberList) || memberList.length === 0) {
              members.append(emptyMessage("No workspace members are available."));
              return;
            }

            const table = document.createElement("table");
            table.append(tableHead(["Member", "Role", "Status", "Last active", "Actions"]));
            const body = document.createElement("tbody");
            const activeOwnerCount = memberList.filter((member) =>
              member.role === "owner" && member.status === "active"
            ).length;

            for (const member of memberList) {
              const row = document.createElement("tr");
              row.append(
                memberIdentityCell(member),
                roleCell(member),
                tableCell(member.status || ""),
                tableCell(formatDate(member.user?.lastLoginAt)),
                memberActionsCell(member, activeOwnerCount)
              );
              body.append(row);
            }

            table.append(body);
            members.append(table);
          }

          function renderPendingApprovals(approvalList) {
            pendingApprovals.hidden = false;
            pendingApprovals.replaceChildren(
              sectionHeading("Pending Approvals"),
              sectionDescription("Review pending workspace access approvals. No email delivery is implied by this list.")
            );

            if (!Array.isArray(approvalList) || approvalList.length === 0) {
              pendingApprovals.append(emptyMessage("No pending approvals are available."));
              return;
            }

            const table = document.createElement("table");
            table.append(tableHead(["Requester", "Role", "Status", "Created", "Actions"]));
            const body = document.createElement("tbody");

            for (const approval of approvalList) {
              const row = document.createElement("tr");
              row.append(
                tableCell(approval.email || ""),
                tableCell(approval.role || ""),
                tableCell(approval.status || ""),
                timeCell(approval.createdAt),
                approvalActionsCell(approval)
              );
              body.append(row);
            }

            table.append(body);
            pendingApprovals.append(table);
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

              if (entitlement.appKey === "sqag") {
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

          function renderActivity(eventList) {
            activity.hidden = false;
            state.activityEvents = Array.isArray(eventList) ? eventList : [];
            state.activityPage = 0;
            renderActivityPage();
          }

          function renderActivityPage() {
            activity.replaceChildren(
              sectionHeading("Audit Log"),
              sectionDescription("Safe workspace activity labels without internal identifiers or provider metadata.")
            );

            const eventList = state.activityEvents;
            if (eventList.length === 0) {
              activity.append(emptyMessage("No recent workspace activity is available."));
              return;
            }

            const start = state.activityPage * state.activityPageSize;
            const visibleEvents = eventList.slice(start, start + state.activityPageSize);
            const table = document.createElement("table");
            table.append(tableHead(["Action", "Subject", "Actor", "Time", "Details"]));
            const body = document.createElement("tbody");

            for (const event of visibleEvents) {
              const row = document.createElement("tr");
              row.append(
                tableCell(activityLabel(event)),
                tableCell(subjectLabel(event)),
                tableCell(actorLabel(event)),
                timeCell(event.createdAt),
                metadataCell(event.metadata)
              );
              body.append(row);
            }

            table.append(body);
            activity.append(table);
            activity.append(activityPager(start, visibleEvents.length, eventList.length));
          }

          function activityPager(start, visibleCount, totalCount) {
            const pager = document.createElement("div");
            pager.className = "pager";
            const summary = document.createElement("p");
            summary.className = "empty";
            summary.textContent =
              "Showing " + String(start + 1) + "-" + String(start + visibleCount) +
              " of " + String(totalCount) + " recent events";

            const newer = document.createElement("button");
            newer.type = "button";
            newer.className = "secondary-action compact";
            newer.textContent = "Newer";
            newer.disabled = state.activityPage === 0;
            newer.addEventListener("click", () => {
              state.activityPage = Math.max(0, state.activityPage - 1);
              renderActivityPage();
            });

            const older = document.createElement("button");
            older.type = "button";
            older.className = "secondary-action compact";
            older.textContent = "Older";
            older.disabled = start + visibleCount >= totalCount;
            older.addEventListener("click", () => {
              state.activityPage += 1;
              renderActivityPage();
            });

            pager.append(summary, newer, older);
            return pager;
          }

          function roleCell(member) {
            const cell = document.createElement("td");
            const select = document.createElement("select");
            const roles = ["owner", "admin", "member"];
            const isSelf = member.user?.id === state.context?.user?.userId;
            const actorIsOwner = state.workspace?.membershipRole === "owner";

            for (const role of roles) {
              const option = document.createElement("option");
              option.value = role;
              option.textContent = displayRole(role);
              option.selected = member.role === role || (!roles.includes(member.role) && role === "member");
              option.disabled = role === "owner" && !actorIsOwner;
              select.append(option);
            }

            select.disabled =
              isSelf || member.status !== "active" || (member.role === "owner" && !actorIsOwner);
            select.addEventListener("change", () => {
              void changeMemberRole(member.membershipId, select.value);
            });
            cell.append(select);
            return cell;
          }

          function memberActionsCell(member, activeOwnerCount) {
            const cell = document.createElement("td");
            const menu = document.createElement("div");
            const menuButton = document.createElement("button");
            const menuPanel = document.createElement("div");
            const isSelf = member.user?.id === state.context?.user?.userId;
            const isProtectedOwner = member.role === "owner";
            const isLastActiveOwner =
              member.role === "owner" && member.status === "active" && activeOwnerCount <= 1;
            const canAct = !isSelf && !isProtectedOwner && !isLastActiveOwner;

            menu.className = "action-menu";
            menuButton.type = "button";
            menuButton.className = "secondary-action compact";
            menuButton.textContent = "Actions";
            menuButton.disabled = !canAct || !["active", "disabled"].includes(member.status);
            menuButton.setAttribute("aria-haspopup", "true");
            menuButton.setAttribute("aria-expanded", "false");
            menuButton.addEventListener("click", () => {
              const shouldOpen = menuPanel.hidden;
              closeAllActionMenus();
              menuPanel.hidden = !shouldOpen;
              menuButton.setAttribute("aria-expanded", shouldOpen ? "true" : "false");
            });

            menuPanel.className = "action-menu-panel";
            menuPanel.hidden = true;

            if (member.status === "active") {
              menuPanel.append(actionButton("Disable Access", () => {
                closeAllActionMenus();
                void disableMember(member.membershipId);
              }));
            }

            if (member.status === "disabled") {
              menuPanel.append(actionButton("Reactivate", () => {
                closeAllActionMenus();
                void reactivateMember(member.membershipId);
              }));
            }

            if (["active", "disabled"].includes(member.status)) {
              menuPanel.append(actionButton("Remove from Workspace", () => {
                closeAllActionMenus();
                void removeMember(member.membershipId);
              }));
            }

            menu.append(menuButton, menuPanel);
            cell.append(menu);
            return cell;
          }

          function closeAllActionMenus() {
            const panels = document.querySelectorAll(".action-menu-panel");
            for (const panel of panels) {
              panel.hidden = true;
            }

            const buttons = document.querySelectorAll(".action-menu button[aria-haspopup='true']");
            for (const button of buttons) {
              button.setAttribute("aria-expanded", "false");
            }
          }

          function actionButton(label, onClick) {
            const button = document.createElement("button");
            button.type = "button";
            button.className = "secondary-action compact";
            button.textContent = label;
            button.addEventListener("click", onClick);
            return button;
          }

          function approvalActionsCell(approval) {
            const cell = document.createElement("td");
            const button = document.createElement("button");
            button.type = "button";
            button.className = "secondary-action compact";
            button.textContent = "Revoke";
            button.disabled = approval.status !== "pending";
            button.addEventListener("click", () => {
              void revokeApproval(approval.approvalId);
            });
            cell.append(button);
            return cell;
          }

          async function changeMemberRole(membershipId, role) {
            await postAdminAction(
              adminMemberUrl(state.workspace.workspaceId, membershipId) +
                "/role?role=" + encodeURIComponent(role),
              "Member role updated.",
              { loadingMessage: "Saving workspace admin change..." }
            );
          }

          async function disableMember(membershipId) {
            openActionModal({
              title: "Disable member?",
              body: "This disables workspace access for this member. Their platform account is not deleted.",
              confirmLabel: "Disable member",
              url: adminMemberUrl(state.workspace.workspaceId, membershipId) + "/disable",
              successMessage: "Member disabled.",
              loadingMessage: "Disabling member..."
            });
          }

          async function reactivateMember(membershipId) {
            openActionModal({
              title: "Reactivate member?",
              body: "This restores workspace access for this member.",
              confirmLabel: "Reactivate member",
              url: adminMemberUrl(state.workspace.workspaceId, membershipId) + "/reactivate",
              successMessage: "Member reactivated.",
              loadingMessage: "Reactivating member..."
            });
          }

          async function removeMember(membershipId) {
            openActionModal({
              title: "Remove member?",
              body: "This removes workspace access for this member. Their platform account is not deleted.",
              confirmLabel: "Remove member",
              url: adminMemberUrl(state.workspace.workspaceId, membershipId) + "/remove",
              successMessage: "Member removed.",
              loadingMessage: "Removing member..."
            });
          }

          async function revokeApproval(approvalId) {
            openActionModal({
              title: "Revoke approval?",
              body: "This removes the pending workspace access approval for this email.",
              confirmLabel: "Revoke approval",
              url: adminApprovalUrl(state.workspace.workspaceId, approvalId) + "/revoke",
              successMessage: "Approval revoked.",
              loadingMessage: "Revoking approval..."
            });
          }

          async function updateEntitlement(nextStatus) {
            await postAdminAction(
              adminEntitlementsUrl(state.workspace.workspaceId) +
                "/sqag/status?status=" + encodeURIComponent(nextStatus),
              "Workspace admin change saved.",
              { loadingMessage: "Updating app access..." }
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

            const result = await postAdminAction(
              addMemberUrl(state.workspace.workspaceId, email, role),
              null,
              { loadingMessage: "Adding workspace member..." }
            );
            if (result) {
              addMemberForm.reset();
              closeAddMemberModal();
            }
          }

          function openActionModal(action) {
            state.modalAction = action;
            modalTitle.textContent = action.title;
            modalBody.textContent = action.body;
            modalConfirmButton.textContent = action.confirmLabel;
            modalError.hidden = true;
            modalError.textContent = "";
            setModalBusy(false, action.loadingMessage);
            adminActionModal.hidden = false;
            modalCancelButton.focus();
          }

          function openAddMemberModal() {
            setAddMemberResult("");
            addMember.hidden = false;
            addMemberForm.querySelector("input[name='email']").focus();
          }

          function closeAddMemberModal() {
            addMember.hidden = true;
            setAddMemberResult("");
          }

          function closeActionModal() {
            if (modalConfirmButton.disabled) {
              return;
            }

            state.modalAction = null;
            adminActionModal.hidden = true;
            modalError.hidden = true;
            modalError.textContent = "";
            setModalBusy(false, "");
          }

          async function runModalAction() {
            const action = state.modalAction;

            if (!action) {
              return;
            }

            setModalBusy(true, action.loadingMessage);
            const success = await postAdminAction(action.url, action.successMessage, {
              loadingMessage: action.loadingMessage
            });

            if (success) {
              setModalBusy(false, "");
              closeActionModal();
              return;
            }

            setModalBusy(false, action.loadingMessage);
            modalError.textContent = "Workspace admin action could not be completed.";
            modalError.hidden = false;
          }

          function setModalBusy(isBusy, message) {
            if (isBusy) {
              modalConfirmButton.disabled = true;
              modalCancelButton.disabled = true;
              modalDismissButton.disabled = true;
            } else {
              modalConfirmButton.disabled = false;
              modalCancelButton.disabled = false;
              modalDismissButton.disabled = false;
            }
            modalLoading.hidden = !isBusy;
            modalLoadingText.textContent = message || "";
          }

          async function postAdminAction(
            url,
            successMessage = "Workspace admin change saved.",
            options = {}
          ) {
            const loadingMessage = options.loadingMessage || "Saving workspace admin change...";
            setStatus(loadingMessage);
            showActionStatus(loadingMessage, true);
            setAddMemberResult("");

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
              const payload = await readJson(response);

              if (!response.ok) {
                const message = safeAdminActionMessage(payload);
                setStatus(message);
                showActionStatus(message, false);
                setAddMemberResult(message);
                await loadAdminData();
                return false;
              }

              await loadAdminData();
              const message = successMessage || adminActionSuccessMessage(payload);
              setStatus(message);
              showActionStatus(message, false);
              setAddMemberResult(message);
              return true;
            } catch {
              const message = "Workspace admin action could not be completed.";
              setStatus(message);
              showActionStatus(message, false);
              setAddMemberResult(message);
              return false;
            }
          }

          function adminActionSuccessMessage(payload) {
            if (payload?.outcome === "pending_approval_created") {
              return "Pending approval created.";
            }

            if (payload?.outcome === "created") {
              return "Existing user added to workspace.";
            }

            if (payload?.outcome === "revoked") {
              return "Approval revoked.";
            }

            return "Workspace admin change saved.";
          }

          function safeAdminActionMessage(payload) {
            if (payload && typeof payload.message === "string" && payload.message.trim()) {
              return payload.message;
            }

            return "Workspace admin action could not be completed.";
          }

          function setAddMemberResult(message) {
            if (!message) {
              addMemberResult.hidden = true;
              addMemberResult.textContent = "";
              return;
            }

            addMemberResult.textContent = message;
            addMemberResult.hidden = false;
          }

          function showActionStatus(message, busy) {
            if (!message) {
              adminActionStatus.hidden = true;
              adminActionStatusText.textContent = "";
              adminActionStatus.querySelector(".spinner").hidden = true;
              return;
            }

            adminActionStatus.hidden = false;
            adminActionStatusText.textContent = message;
            adminActionStatus.querySelector(".spinner").hidden = !busy;
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
              window.location.assign("/login?signedOut=1");
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

          function adminApprovalsUrl(workspaceId) {
            return "/api/platform/workspaces/" +
              encodeURIComponent(workspaceId) +
              "/member-approvals";
          }

          function adminApprovalUrl(workspaceId, approvalId) {
            return adminApprovalsUrl(workspaceId) + "/" + encodeURIComponent(approvalId);
          }

          function adminEntitlementsUrl(workspaceId) {
            return "/api/platform/workspaces/" +
              encodeURIComponent(workspaceId) +
              "/app-entitlements";
          }

          function adminAuditEventsUrl(workspaceId) {
            return "/api/platform/workspaces/" +
              encodeURIComponent(workspaceId) +
              "/audit-events?limit=50";
          }

          function activityLabel(event) {
            switch (event.eventType) {
              case "workspace.app_entitlement.enabled":
                return "App launch allowed";
              case "workspace.app_entitlement.disabled":
                return "App launch denied";
              case "workspace.membership.added":
                return "Member added";
              case "workspace.membership.disabled":
                return "Member removed";
              case "workspace.membership.reactivated":
                return "Member added";
              case "workspace.membership.removed":
                return "Member removed";
              case "workspace.membership.role_changed":
                return "Role changed";
              case "workspace.membership_approval.created":
                return "Login blocked for unapproved user";
              case "workspace.membership_approval.revoked":
                return "Login blocked for unapproved user";
              case "workspace.membership_approval.accepted":
                return "Member added";
              default:
                return "Workspace activity";
            }
          }

          function subjectLabel(event) {
            switch (event.targetType) {
              case "app_entitlement":
                return "SQAG access";
              case "membership":
                return event.targetLabel || "Unknown user";
              case "membership_approval":
                return event.targetLabel || "Unknown user";
              default:
                return "Workspace item";
            }
          }

          function actorLabel(event) {
            return event.actorDisplayName || event.actorEmail ||
              (event.actorUserId ? "Platform user" : "System");
          }

          function metadataCell(metadata) {
            const cell = document.createElement("td");
            const rows = metadataRows(metadata);

            if (rows.length === 0) {
              cell.textContent = "No details";
              return cell;
            }

            const list = document.createElement("dl");
            list.className = "metadata-list";

            for (const row of rows) {
              const term = document.createElement("dt");
              const detail = document.createElement("dd");
              term.textContent = row.label;
              detail.textContent = row.value;
              list.append(term, detail);
            }

            cell.append(list);
            return cell;
          }

          function metadataRows(metadata) {
            if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
              return [];
            }

            const rows = [];

            for (const [key, value] of Object.entries(metadata)) {
              const row = allowedMetadataRows(key, value);
              if (row) {
                rows.push(row);
              }
            }

            return rows;
          }

          function allowedMetadataRows(key, value) {
            if (!isSafeMetadataValue(value)) {
              return null;
            }

            switch (key) {
              case "previousRole":
                return { label: "Previous role", value: String(value) };
              case "newRole":
                return { label: "New role", value: String(value) };
              case "previousStatus":
                return { label: "Previous status", value: String(value) };
              case "newStatus":
                return { label: "New status", value: String(value) };
              case "appKey":
                return normalizeAppKeyMetadata(value);
              default:
                return null;
            }
          }

          function normalizeAppKeyMetadata(value) {
            if (String(value).toLowerCase() !== "sqag") {
              return null;
            }

            return { label: "App", value: "Swooshz Quote Auto Generator" };
          }

          function isSafeMetadataValue(value) {
            return value === null ||
              typeof value === "string" ||
              typeof value === "number" ||
              typeof value === "boolean";
          }

          function hideAdminSections() {
            identity.hidden = true;
            adminActionStatus.hidden = true;
            adminActionStatusText.textContent = "";
            workspaceSummary.hidden = true;
            openAddMemberButton.hidden = true;
            addMember.hidden = true;
            addMemberResult.hidden = true;
            addMemberResult.textContent = "";
            ownerTransfer.hidden = true;
            pendingApprovals.hidden = true;
            members.hidden = true;
            entitlements.hidden = true;
            activity.hidden = true;
            workspaceSummary.replaceChildren();
            addMemberForm.reset();
            pendingApprovals.replaceChildren();
            members.replaceChildren();
            entitlements.replaceChildren();
            activity.replaceChildren();
          }

          function setStatus(message) {
            status.textContent = message;
          }

          function sectionHeading(value) {
            const heading = document.createElement("h2");
            heading.textContent = value;
            return heading;
          }

          function sectionDescription(value) {
            const description = document.createElement("p");
            description.className = "empty section-description";
            description.textContent = value;
            return description;
          }

          function memberIdentityCell(member) {
            const cell = document.createElement("td");
            const block = document.createElement("div");
            block.className = "member-identity";
            const avatar = document.createElement("span");
            avatar.className = "member-avatar";
            avatar.textContent = initials(member.user?.displayName || member.user?.email || "Member");
            const copy = document.createElement("span");
            const name = document.createElement("strong");
            const email = document.createElement("span");
            name.textContent = member.user?.displayName || "Workspace member";
            email.textContent = member.user?.email || "";
            copy.append(name, email);
            block.append(avatar, copy);
            cell.append(block);
            return cell;
          }

          function initials(value) {
            return String(value || "M")
              .trim()
              .split(/\\s+/)
              .slice(0, 2)
              .map((part) => part[0] || "")
              .join("")
              .toUpperCase() || "M";
          }

          function displayRole(role) {
            switch (role) {
              case "owner":
                return "Owner";
              case "admin":
                return "Admin";
              default:
                return "Member";
            }
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

          function timeCell(value) {
            const cell = document.createElement("td");
            cell.textContent = formatDate(value);
            return cell;
          }

          function formatDate(value) {
            if (!value) {
              return "Not available";
            }

            const date = new Date(value);
            if (Number.isNaN(date.getTime())) {
              return String(value);
            }

            return date.toLocaleString(undefined, {
              year: "numeric",
              month: "short",
              day: "2-digit",
              hour: "2-digit",
              minute: "2-digit"
            });
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

export function renderAuthErrorPage(): string {
  return htmlDocument({
    title: "Swooshz Platform Access Not Approved",
    body: `
      <main class="landing">
        <section class="panel">
          <p class="eyebrow">Swooshz Platform internal access</p>
          <h1>Access not approved</h1>
          <p class="lede">
            This account is not approved for Swooshz Platform. Use an approved
            account or contact your workspace admin.
          </p>
          <div class="login-actions">
            <a class="primary-action" href="/api/platform/auth/start">Try another Google account</a>
            <a class="secondary-action" href="/">Back to sign in</a>
          </div>
        </section>
      </main>
    `,
  });
}

function publicNav(active: "home" | "solutions"): string {
  return `
    <header class="public-nav">
      <a class="public-brand" href="/">Swooshz</a>
      <nav aria-label="Public navigation">
        <a class="${active === "home" ? "active" : ""}" href="/">Home</a>
        <a class="${active === "solutions" ? "active" : ""}" href="/solutions">Solutions</a>
        <span aria-disabled="true">Blog</span>
        <span aria-disabled="true">About</span>
      </nav>
      <div class="public-actions">
        <a class="text-action" href="/login">Login</a>
        <a class="primary-action compact" href="/login">Access entry</a>
      </div>
    </header>
  `;
}

function publicFooter(): string {
  return `
    <footer class="public-footer">
      <strong>Swooshz</strong>
      <nav aria-label="Footer navigation">
        <span>Privacy</span>
        <span>Terms</span>
        <span>Security</span>
        <span>Status</span>
      </nav>
      <p>&copy; Swooshz. Content to be finalised before launch.</p>
    </footer>
  `;
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
      --primary: #000000;
      --secondary: #0051d5;
      --accent: #0f766e;
      --accent-strong: #115e59;
      --danger-soft: #fef3c7;
      --surface-container-low: #f2f4f6;
      --surface-container-high: #e6e8ea;
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

    .public-nav,
    .public-footer {
      width: 100%;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 24px;
      padding: 20px 28px;
      border-color: var(--line);
      background: var(--surface);
    }

    .public-nav {
      min-height: 72px;
      border-bottom: 1px solid var(--line);
      position: sticky;
      top: 0;
      z-index: 5;
    }

    .public-brand,
    .public-footer strong {
      color: var(--primary);
      font-size: 24px;
      font-weight: 700;
      text-decoration: none;
      letter-spacing: 0;
    }

    .public-nav nav,
    .public-actions,
    .public-footer nav,
    .button-row {
      display: flex;
      align-items: center;
      gap: 20px;
    }

    .public-nav nav a,
    .public-nav nav span,
    .text-action,
    .public-footer span,
    .public-footer p {
      color: var(--ink);
      font-size: 15px;
      text-decoration: none;
    }

    .public-nav nav span,
    .public-footer span,
    .public-footer p {
      color: var(--muted);
    }

    .public-nav nav a.active {
      color: var(--secondary);
      border-bottom: 2px solid var(--secondary);
      padding-bottom: 8px;
      font-weight: 700;
    }

    .public-page {
      background: var(--bg);
    }

    .public-hero,
    .solutions-hero,
    .public-band,
    .process-section {
      width: min(1280px, calc(100% - 48px));
      margin: 0 auto;
    }

    .public-hero,
    .solutions-hero {
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(360px, 0.92fr);
      gap: 56px;
      align-items: center;
      min-height: 520px;
      padding: 64px 0;
    }

    .solutions-hero {
      border-bottom: 1px solid var(--line);
      background-image: radial-gradient(circle at 2px 2px, #dfe4e8 1px, transparent 0);
      background-size: 32px 32px;
    }

    .hero-copy {
      display: flex;
      flex-direction: column;
      align-items: flex-start;
      gap: 20px;
    }

    .hero-copy h1 {
      max-width: 640px;
      margin: 0;
      color: var(--primary);
      font-size: 48px;
      line-height: 1.12;
      letter-spacing: 0;
    }

    .utility-label {
      margin: 0;
      color: var(--secondary);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .architecture-card,
    .product-preview {
      min-height: 360px;
      padding: 18px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface);
      box-shadow: 0 12px 28px rgb(24 33 43 / 8%);
    }

    .architecture-bar,
    .preview-window-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding-bottom: 12px;
      border-bottom: 1px solid var(--line);
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }

    .architecture-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 14px;
      padding-top: 24px;
    }

    .architecture-grid span,
    .mini-workflow span,
    .role-rail span {
      min-height: 42px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 8px 10px;
      border: 1px solid var(--line);
      border-radius: 4px;
      background: var(--bg);
      color: var(--ink);
      font-size: 13px;
      text-align: center;
    }

    .preview-empty {
      min-height: 280px;
      display: grid;
      place-items: center;
      align-content: center;
      gap: 16px;
      margin-top: 16px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--surface-container-low, #f2f4f6);
      text-align: center;
    }

    .preview-empty p {
      max-width: 360px;
      margin: 0;
      color: var(--muted);
      font-size: 18px;
    }

    .public-band,
    .process-section {
      padding: 64px 0;
      border-top: 1px solid var(--line);
    }

    .section-heading {
      display: grid;
      gap: 8px;
      margin-bottom: 28px;
    }

    .section-heading.centered {
      justify-items: center;
      text-align: center;
    }

    .section-heading h2 {
      margin: 0;
      color: var(--primary);
      font-size: 32px;
      line-height: 1.25;
      letter-spacing: 0;
    }

    .section-heading p,
    .module-card p,
    .process-grid p {
      color: var(--muted);
    }

    .module-grid,
    .capability-grid {
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 16px;
    }

    .capability-grid {
      grid-template-columns: 2fr 1fr;
    }

    .module-card {
      display: flex;
      flex-direction: column;
      gap: 14px;
      min-height: 220px;
      padding: 28px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface);
    }

    .module-card h3 {
      margin: 0;
      color: var(--primary);
      font-size: 24px;
      line-height: 1.25;
    }

    .module-card p {
      margin: 0;
      font-size: 16px;
    }

    .module-card-wide {
      grid-column: span 1;
    }

    .module-stack {
      display: grid;
      gap: 16px;
    }

    .muted-card,
    .unavailable-card {
      background: #fbfcfd;
    }

    .unavailable-card {
      grid-column: 1 / -1;
      align-items: center;
      min-height: 210px;
      text-align: center;
    }

    .card-title-row {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 16px;
    }

    .status-pill {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: max-content;
      min-height: 28px;
      padding: 4px 10px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--surface-container-high, #e6e8ea);
      color: var(--muted);
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
    }

    .mini-workflow,
    .role-rail,
    .process-grid {
      display: grid;
      gap: 14px;
    }

    .mini-workflow {
      grid-template-columns: repeat(3, minmax(0, 1fr));
      margin-top: auto;
    }

    .role-rail {
      grid-template-columns: repeat(4, minmax(0, 1fr));
      margin-top: auto;
      padding: 28px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--bg);
    }

    .process-grid {
      grid-template-columns: repeat(3, minmax(0, 1fr));
      margin-top: 36px;
      text-align: center;
    }

    .process-grid article {
      display: grid;
      justify-items: center;
      gap: 12px;
    }

    .process-grid span {
      display: grid;
      place-items: center;
      width: 58px;
      height: 58px;
      border: 1px solid var(--ink);
      border-radius: 6px;
      background: var(--surface);
      color: var(--primary);
      font-size: 24px;
      font-weight: 700;
    }

    .process-grid article:last-child span {
      background: var(--primary);
      color: #ffffff;
    }

    .public-footer {
      border-top: 1px solid var(--line);
    }

    .public-footer p {
      margin: 0;
      text-align: right;
    }

    .login-canvas {
      position: relative;
      min-height: calc(100vh - 76px);
      display: grid;
      place-items: center;
      padding: 40px 24px;
      overflow: hidden;
    }

    .access-panel {
      position: relative;
      z-index: 1;
      width: min(560px, 100%);
      display: grid;
      gap: 20px;
      padding: 48px 42px;
      border: 1px solid var(--line);
      background: var(--surface);
      text-align: center;
    }

    .access-heading {
      display: grid;
      gap: 8px;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--line);
    }

    .access-heading h1,
    .access-heading p {
      margin: 0;
    }

    .login-lines::before,
    .login-lines::after {
      content: "";
      position: fixed;
      width: 52vw;
      height: 52vh;
      border: 1px solid var(--line);
      opacity: 0.36;
      transform: rotate(10deg);
    }

    .login-lines::before {
      top: -18vh;
      right: 4vw;
    }

    .login-lines::after {
      left: -12vw;
      bottom: -16vh;
    }

    .portal-layout {
      min-height: 100vh;
      display: grid;
      grid-template-columns: 320px minmax(0, 1fr);
      background: var(--bg);
    }

    .portal-sidebar {
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      gap: 24px;
      padding: 28px 20px;
      border-right: 1px solid var(--line);
      background: var(--surface);
    }

    .portal-brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .portal-brand h1,
    .portal-brand p,
    .portal-topbar p,
    .portal-heading h2,
    .portal-heading p {
      margin: 0;
    }

    .portal-brand h1 {
      color: var(--primary);
      font-size: 26px;
      line-height: 1.15;
    }

    .portal-brand p {
      color: var(--ink);
      font-size: 13px;
      letter-spacing: 0;
    }

    .brand-mark,
    .icon-mark {
      display: inline-grid;
      place-items: center;
      min-width: 42px;
      min-height: 42px;
      border-radius: 6px;
      background: var(--primary);
      color: #ffffff;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }

    .icon-mark {
      border: 1px solid var(--line);
      background: var(--surface-container-high, #e6e8ea);
      color: var(--primary);
    }

    .icon-mark.large {
      min-width: 58px;
      min-height: 58px;
    }

    .sidebar-launch {
      width: 100%;
    }

    .portal-nav {
      display: grid;
      gap: 8px;
    }

    .portal-nav a,
    .portal-nav span,
    .sidebar-logout {
      min-height: 44px;
      display: flex;
      align-items: center;
      padding: 0 18px;
      border: 0;
      border-radius: 4px;
      background: transparent;
      color: var(--ink);
      font-weight: 700;
      text-decoration: none;
    }

    .portal-nav span {
      color: var(--muted);
    }

    .portal-nav .portal-nav-active {
      border-right: 4px solid var(--primary);
      background: var(--secondary);
      color: #ffffff;
    }

    .sidebar-logout {
      margin-top: auto;
      border-top: 1px solid var(--line);
      border-radius: 0;
      cursor: pointer;
    }

    .portal-main {
      min-width: 0;
      display: flex;
      flex-direction: column;
    }

    .portal-topbar {
      min-height: 80px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 20px;
      padding: 0 32px;
      border-bottom: 1px solid var(--line);
      background: var(--surface);
    }

    .portal-topbar p {
      color: var(--primary);
      font-size: 24px;
    }

    .portal-topbar-actions {
      display: flex;
      gap: 18px;
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
    }

    .portal-canvas {
      width: min(1180px, calc(100% - 64px));
      display: grid;
      gap: 20px;
      margin: 0 auto;
      padding: 44px 0 56px;
    }

    .portal-heading h2 {
      color: var(--primary);
      font-size: 40px;
      line-height: 1.15;
      letter-spacing: 0;
    }

    .portal-heading p {
      color: var(--muted);
      font-size: 18px;
    }

    .unavailable-state {
      display: grid;
      gap: 8px;
      min-width: min(420px, 100%);
      color: var(--ink);
    }

    .unavailable-state strong {
      color: var(--muted);
    }

    .unavailable-state span {
      overflow-wrap: anywhere;
    }

    .unavailable-actions {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px 12px;
      margin-top: 2px;
    }

    .contact-admin {
      color: var(--ink);
      font-size: 14px;
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
    .empty,
    .helper {
      color: var(--muted);
    }

    .status,
    .identity {
      margin-bottom: 16px;
    }

    .signed-out {
      margin-bottom: 16px;
      padding: 12px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--danger-soft);
    }

    .login-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      justify-content: flex-end;
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

    .metadata-list {
      display: grid;
      grid-template-columns: max-content 1fr;
      gap: 4px 10px;
      margin: 0;
    }

    .metadata-list dt {
      color: var(--muted);
      font-weight: 700;
    }

    .metadata-list dd {
      margin: 0;
    }

    .pager {
      display: flex;
      align-items: center;
      justify-content: flex-end;
      gap: 10px;
      margin-top: 14px;
    }

    .pager .empty {
      margin-right: auto;
    }

    .action-menu {
      position: relative;
      display: inline-flex;
    }

    .action-menu-panel {
      position: absolute;
      right: 0;
      top: calc(100% + 6px);
      z-index: 2;
      display: grid;
      gap: 6px;
      min-width: 132px;
      padding: 8px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--surface);
      box-shadow: 0 12px 24px rgb(0 0 0 / 12%);
    }

    .action-menu-panel[hidden] {
      display: none;
    }

    .action-menu-panel .secondary-action {
      width: 100%;
      min-height: 38px;
    }

    .action-status,
    .modal-loading {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .action-status {
      min-height: 44px;
      margin-bottom: 16px;
      padding: 10px 12px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--surface);
      color: var(--muted);
    }

    .admin-layout .portal-sidebar {
      position: sticky;
      top: 0;
      height: 100vh;
    }

    .admin-layout .portal-topbar {
      justify-content: flex-end;
    }

    .admin-canvas {
      width: min(1240px, calc(100% - 64px));
      gap: 18px;
    }

    .admin-page-header {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 24px;
      margin-bottom: 4px;
    }

    .topbar-icon {
      display: inline-block;
      width: 22px;
      height: 22px;
      border: 2px solid var(--primary);
      border-radius: 999px;
      vertical-align: middle;
    }

    .topbar-icon-history {
      border-style: dashed;
    }

    .topbar-icon-account {
      position: relative;
    }

    .topbar-icon-account::after {
      position: absolute;
      left: 4px;
      right: 4px;
      bottom: 3px;
      height: 6px;
      border-top: 2px solid var(--primary);
      border-radius: 999px 999px 0 0;
      content: "";
    }

    .admin-summary-grid {
      margin-bottom: 0;
    }

    .admin-summary,
    .admin-surface {
      padding: 22px;
    }

    .admin-surface h2,
    .admin-summary h2 {
      margin: 0 0 6px;
      color: var(--primary);
      font-size: 24px;
      line-height: 1.25;
    }

    .section-description {
      margin-bottom: 18px;
    }

    .member-identity {
      display: flex;
      align-items: center;
      gap: 14px;
    }

    .member-identity strong {
      color: var(--primary);
      font-size: 15px;
      text-transform: none;
    }

    .member-avatar {
      display: grid;
      place-items: center;
      width: 44px;
      height: 44px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--secondary);
      color: #ffffff;
      font-weight: 700;
    }

    .spinner {
      width: 14px;
      height: 14px;
      border: 2px solid var(--line);
      border-top-color: var(--accent);
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      flex: 0 0 auto;
    }

    .spinner[hidden] {
      display: none;
    }

    .modal-backdrop {
      position: fixed;
      inset: 0;
      z-index: 10;
      display: grid;
      place-items: center;
      padding: 24px;
      background: rgb(24 33 43 / 42%);
    }

    .action-modal {
      width: min(420px, 100%);
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface);
      box-shadow: 0 18px 46px rgb(0 0 0 / 18%);
      overflow: hidden;
    }

    .add-member-modal {
      width: min(560px, 100%);
    }

    .modal-header,
    .modal-body,
    .modal-footer {
      padding: 20px 24px;
    }

    .modal-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      border-bottom: 1px solid var(--line);
    }

    .modal-header h2 {
      margin: 0;
      color: var(--primary);
      font-size: 24px;
      line-height: 1.25;
    }

    .modal-body {
      display: grid;
      gap: 16px;
    }

    .modal-close {
      width: 36px;
      min-height: 36px;
      border: 0;
      background: transparent;
      color: var(--ink);
      cursor: pointer;
      font-size: 20px;
    }

    .field-stack {
      display: grid;
      gap: 16px;
    }

    .field-stack label {
      display: grid;
      gap: 8px;
    }

    .modal-actions {
      display: flex;
      justify-content: flex-end;
      gap: 10px;
    }

    .modal-footer {
      border-top: 1px solid var(--line);
      background: var(--surface-container-low);
    }

    .modal-error {
      margin-top: 12px;
      color: #991b1b;
    }

    @keyframes spin {
      to {
        transform: rotate(360deg);
      }
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
      background: var(--primary);
      color: #ffffff;
    }

    .primary-action:hover {
      background: var(--secondary);
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
      .public-nav,
      .public-footer {
        align-items: stretch;
        flex-direction: column;
        padding: 18px 20px;
      }

      .public-nav {
        position: static;
      }

      .public-nav nav,
      .public-actions,
      .public-footer nav,
      .button-row {
        flex-wrap: wrap;
        gap: 12px;
      }

      .public-hero,
      .solutions-hero,
      .public-band,
      .process-section {
        width: min(100% - 32px, 1280px);
      }

      .public-hero,
      .solutions-hero {
        grid-template-columns: 1fr;
        min-height: auto;
        padding: 36px 0;
      }

      .hero-copy h1 {
        font-size: 36px;
        line-height: 1.16;
      }

      .architecture-card,
      .product-preview {
        min-height: auto;
      }

      .architecture-grid,
      .module-grid,
      .capability-grid,
      .mini-workflow,
      .role-rail,
      .process-grid {
        grid-template-columns: 1fr;
      }

      .public-footer p {
        text-align: left;
      }

      .access-panel {
        padding: 32px 24px;
      }

      .portal-layout {
        display: block;
      }

      .portal-sidebar {
        position: static;
        min-height: auto;
        height: auto;
        border-right: 0;
        border-bottom: 1px solid var(--line);
      }

      .portal-nav {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }

      .portal-main,
      .portal-canvas {
        width: 100%;
      }

      .portal-topbar {
        min-height: 64px;
        padding: 0 20px;
      }

      .portal-topbar-actions {
        display: none;
      }

      .portal-canvas {
        padding: 28px 16px 40px;
        overflow: hidden;
      }

      .admin-canvas {
        width: 100%;
      }

      .admin-page-header {
        display: grid;
        gap: 16px;
      }

      .admin-summary,
      .admin-surface {
        padding: 18px;
      }

      .member-identity {
        align-items: flex-start;
      }

      .portal-heading h2 {
        font-size: 34px;
      }

      .identity {
        grid-template-columns: 1fr;
      }

      .workspace,
      .workspace-list,
      .apps,
      .app-row,
      .app-row > div,
      .unavailable-state {
        min-width: 0;
        width: 100%;
      }

      .app-row {
        display: grid;
        grid-template-columns: minmax(0, 1fr);
      }

      .workspace span,
      .app-row span {
        max-width: calc(100vw - 104px);
        overflow-wrap: anywhere;
        white-space: normal;
      }

      .unavailable-actions {
        display: grid;
        width: 100%;
      }

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
      .pager,
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

      .modal-actions {
        display: grid;
      }

      .modal-header,
      .modal-body,
      .modal-footer {
        padding: 18px;
      }
    }
  </style>
</head>
<body>
${body}
</body>
</html>`;
}
