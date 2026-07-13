(() => {
  const app = document.getElementById("study-app");
  const liveRegion = document.getElementById("live-region");
  const params = new URLSearchParams(window.location.search);
  const direction = document.body.dataset.direction || "a";
  const directionName = {
    a: "Editorial Operations",
    b: "Precision Workspace",
    c: "Product Gallery Workspace",
  }[direction];

  const state = {
    screen: params.get("screen") === "admin" ? "admin" : "app",
    scenario: params.get("scenario") || "default",
    section: ["members", "pending", "access", "activity"].includes(params.get("section"))
      ? params.get("section")
      : "members",
    selectedWorkspace: params.get("workspace") === "field" ? "field" : "northstar",
    activityPage: 0,
    workspaceMenu: false,
    mobileMenu: false,
    menu: params.get("scenario") === "menu" ? "member_4" : null,
    modal: modalFromScenario(params.get("scenario")),
    lastFocusId: null,
  };

  const workspace = {
    northstar: {
      id: "workspace_northstar_example",
      name: "Northstar Studio",
      role: "Owner",
      roleKey: "owner",
    },
    field: {
      id: "workspace_field_example",
      name: "Field Office",
      role: "Member",
      roleKey: "member",
    },
  };

  const members = [
    ["member_1", "Alex Morgan", "alex.morgan@example.com", "Owner", "active", "Today"],
    ["member_2", "Jordan Lee", "jordan.lee@example.com", "Admin", "active", "Today"],
    ["member_3", "Priya Shah", "priya.shah@example.com", "Member", "active", "Yesterday"],
    ["member_4", "A very long synthetic member name used to test wrapping", "long-member-name@example.com", "Member", "active", "3 days ago"],
    ["member_5", "Sam Rivera", "sam.rivera@example.com", "Member", "disabled", "Unavailable"],
  ];

  const approvals = [
    ["approval_1", "new.teammate@example.com", "Member", "Pending", "Today"],
    ["approval_2", "long.pending.approval.address@example.com", "Admin", "Pending", "Yesterday"],
  ];

  const auditEvents = [
    ["App launch allowed", "Swooshz Quote Auto Generator access", "Alex Morgan", "Today, 10:24", "Workspace access: Allowed"],
    ["Member added", "Priya Shah", "Jordan Lee", "Yesterday, 15:10", "Role: Member"],
    ["Role changed", "A very long synthetic member name used to test wrapping", "Alex Morgan", "Yesterday, 09:42", "Previous role: Member"],
    ["Approval created", "new.teammate@example.com", "Jordan Lee", "Monday, 16:02", "Role: Member"],
    ["App launch denied", "Swooshz Quote Auto Generator access", "Alex Morgan", "Monday, 11:16", "Workspace access: Unavailable"],
    ["Member disabled", "Sam Rivera", "Alex Morgan", "Friday, 14:30", "Previous status: Active"],
  ];

  function modalFromScenario(scenario) {
    if (scenario === "add-modal") return { type: "add" };
    if (scenario === "confirm") return { type: "confirm", action: "remove", target: "Priya Shah" };
    if (scenario === "busy-action") return { type: "confirm", action: "remove", target: "Priya Shah", busy: true };
    if (scenario === "action-error") return { type: "confirm", action: "remove", target: "Priya Shah", error: true };
    return null;
  }

  function announce(message) {
    liveRegion.textContent = "";
    window.setTimeout(() => { liveRegion.textContent = message; }, 10);
  }

  function updateUrl() {
    const next = new URL(window.location.href);
    next.searchParams.set("screen", state.screen);
    next.searchParams.set("section", state.section);
    if (state.selectedWorkspace === "field") next.searchParams.set("workspace", "field");
    else next.searchParams.delete("workspace");
    history.replaceState({}, "", next);
  }

  function currentWorkspace() {
    return workspace[state.selectedWorkspace];
  }

  function isAdmin() {
    return currentWorkspace().roleKey === "owner" || currentWorkspace().roleKey === "admin";
  }

  function render() {
    app.innerHTML = shell(state.screen === "admin" ? adminPage() : launcherPage());
    bindEvents();
    if (state.modal) focusModal();
    window.__authenticatedVisualStudy = { direction, ...state };
  }

  function shell(content) {
    const signedOut = state.scenario === "unauthenticated";
    const name = signedOut ? "Signed out" : "Alex Morgan";
    return `
      <div class="app-shell ${state.mobileMenu ? "menu-open" : ""}">
        <header class="app-header">
          <div class="header-inner">
            <a class="brand" href="#app" aria-label="Swooshz Platform study home"><span class="brand-mark" aria-hidden="true">S</span><span>Swooshz</span><small>Platform</small></a>
            <div class="header-utility">
              <span class="public-label">Public website / separate</span>
              <span class="account-chip"><span class="account-dot" aria-hidden="true"></span>${name}</span>
            </div>
          </div>
        </header>
        <div class="shell-grid">
          <aside class="side-rail" aria-label="Platform navigation">
            <div class="rail-context"><p class="eyebrow">Current context</p><strong>${signedOut ? "No session" : currentWorkspace().name}</strong><span>${signedOut ? "Sign in required" : `${currentWorkspace().role} workspace role`}</span></div>
            <button id="mobile-nav-toggle" class="mobile-menu-button" type="button" aria-expanded="${state.mobileMenu}" aria-controls="primary-nav" aria-label="Toggle platform navigation"><span aria-hidden="true">${state.mobileMenu ? "×" : "≡"}</span></button>
            <nav id="primary-nav" class="primary-nav" aria-label="Authenticated platform" ${state.mobileMenu ? "" : "hidden"}>
              <button type="button" data-screen="app" aria-current="${state.screen === "app" ? "page" : "false"}">Product launcher <span aria-hidden="true">→</span></button>
              ${isAdmin() && !signedOut ? `<button type="button" data-screen="admin" aria-current="${state.screen === "admin" ? "page" : "false"}">Workspace administration <span aria-hidden="true">→</span></button>` : ""}
            </nav>
            <div class="rail-footer"><span class="public-label">Public website is outside this product study.</span>${signedOut ? "" : `<button id="logout" class="logout-button" type="button">Sign out</button>`}</div>
          </aside>
          <main id="study-main" class="content" tabindex="-1">${content}</main>
        </div>
      </div>
      ${state.modal ? modal() : ""}
    `;
  }

  function launcherPage() {
    if (state.scenario === "loading") return loadingPage("Loading your workspace context...");
    if (state.scenario === "unauthenticated") return unauthenticatedPage();
    const context = currentWorkspace();
    const multiple = state.scenario === "multiple" || state.selectedWorkspace === "field";
    const noAccess = state.scenario === "no-workspaces";
    const noApps = state.scenario === "no-apps";
    const unavailable = state.scenario === "unavailable" || state.selectedWorkspace === "field";
    const launchLoading = state.scenario === "launch-loading";
    const launchError = state.scenario === "launch-error";
    return `
      <section class="page-intro" aria-labelledby="launcher-title">
        <div><p class="eyebrow">Workspace product launcher</p><h1 id="launcher-title">Ready when your workspace is.</h1><p>One clear starting point for approved applications. The platform keeps workspace access visible, then hands focused work to the separate product.</p></div>
        <div class="context-actions">${multiple ? workspaceSwitcher() : `<span class="role-badge">${context.role}</span>`}</div>
      </section>
      ${statusLine(launchLoading ? "Opening Swooshz Quote Auto Generator..." : launchError ? "Swooshz Quote Auto Generator could not be opened. Please try again." : "Platform session active. Workspace context is current.", launchError ? "error" : launchLoading ? "busy" : "")}
      <dl class="identity-strip" aria-label="Signed-in workspace context">
        <div><dt>Signed in</dt><dd>Alex Morgan</dd></div><div><dt>Account</dt><dd>alex.morgan@example.com</dd></div><div><dt>Workspace</dt><dd>${context.name}</dd></div><div><dt>Role</dt><dd>${context.role}</dd></div>
      </dl>
      ${noAccess ? emptyState("No workspace access is available", "This signed-in account has no active workspace membership. Contact a workspace owner or administrator for access.") : noApps ? workspaceSection(context, emptyState("No registered applications", "This workspace is active, but no applications are registered for it yet.")) : workspaceSection(context, appRows({ unavailable, launchLoading, launchError }))}
    `;
  }

  function workspaceSwitcher() {
    return `<div class="workspace-switcher"><button id="workspace-trigger" class="workspace-trigger" type="button" aria-expanded="${state.workspaceMenu}" aria-controls="workspace-panel"><span><small>Current workspace</small>${currentWorkspace().name}</span><span aria-hidden="true">⌄</span></button><div id="workspace-panel" class="workspace-panel" ${state.workspaceMenu ? "" : "hidden"} role="menu"><button type="button" data-workspace="northstar" role="menuitem" aria-current="${state.selectedWorkspace === "northstar"}">Northstar Studio<small>Owner / application access available</small></button><button type="button" data-workspace="field" role="menuitem" aria-current="${state.selectedWorkspace === "field"}">Field Office<small>Member / access unavailable</small></button></div></div>`;
  }

  function workspaceSection(context, content) {
    return `<section aria-labelledby="workspace-title"><div class="workspace-head"><div><p class="eyebrow">Workspace</p><h2 id="workspace-title">${context.name}</h2><p>${context.role} role. Application availability is checked per workspace.</p></div><span class="role-badge">${context.role}</span></div>${content}</section>`;
  }

  function appRows({ unavailable, launchLoading, launchError }) {
    const launchCopy = launchLoading ? `<button class="button" type="button" disabled><span class="spinner" aria-hidden="true"></span>Opening</button>` : launchError ? `<button class="button" type="button" data-launch data-retry="true">Try again</button>` : `<button class="button" type="button" data-launch>Launch app <span aria-hidden="true">↗</span></button>`;
    const sqagStatus = unavailable ? `<span class="state-badge denied">Access unavailable</span>` : `<span class="state-badge">Access available</span>`;
    const sqagAction = unavailable ? `<div class="app-actions"><small>Access is not available for this workspace. Contact a workspace administrator.</small></div>` : `<div class="app-actions">${launchCopy}<small>Opens as a separate product.</small></div>`;
    return `<div class="launcher-list">
      <article class="app-row"><div><div class="app-title"><span class="app-glyph" aria-hidden="true">Q</span><div><h3>Swooshz Quote Auto Generator</h3><p>Approved workspace access can launch this separate product application.</p></div></div><div class="app-meta">${sqagStatus}<span class="state-badge">Workspace checked</span></div></div>${sqagAction}</article>
      <article class="app-row"><div><div class="app-title"><span class="app-glyph" aria-hidden="true">G</span><div><h3>SEO / GEO / Seozilla</h3><p>Vendor workflow pending. This product is unavailable until the runtime integration is confirmed.</p></div></div><div class="app-meta"><span class="state-badge vendor">Vendor pending</span><span class="state-badge denied">Unavailable</span></div></div><div class="app-actions"><small>No launch action is offered.</small></div></article>
    </div>`;
  }

  function unauthenticatedPage() {
    return `<section class="page-intro" aria-labelledby="signed-out-title"><div><p class="eyebrow">Platform session</p><h1 id="signed-out-title">Sign in to see your workspace.</h1><p>Workspace applications and administration are only available after a current platform session is confirmed.</p></div></section>${statusLine("No active platform session. Continue with the approved provider-backed account.", "error")}<div class="section-rule"></div><button class="button" type="button" data-signin>Continue with approved provider</button>`;
  }

  function adminPage() {
    if (state.scenario === "loading") return loadingPage("Loading workspace administration...");
    if (state.scenario === "unauthenticated") return unauthenticatedPage();
    if (!isAdmin() || state.scenario === "permission-denied") return `<section class="page-intro"><div><p class="eyebrow">Workspace administration</p><h1>Administration is not available for this workspace role.</h1><p>Members can launch approved products, but only workspace owners and administrators can review team access, approvals, app access, and activity.</p></div></section>${statusLine("Permission denied. Select an owner or administrator workspace to continue.", "error")}<div class="section-rule"></div><button class="button secondary" type="button" data-screen="app">Return to product launcher</button>`;
    const context = currentWorkspace();
    return `
      <section class="page-intro" aria-labelledby="admin-title"><div><p class="eyebrow">Workspace administration</p><h1 id="admin-title">Access, with a clear record.</h1><p>Manage the current workspace only. Membership changes and app access actions are kept deliberate and visible.</p></div><div class="context-actions">${workspaceSwitcher()}<button class="button" type="button" data-open-modal="add" data-focus-id="add-member">Add member</button></div></section>
      ${statusLine(state.scenario === "admin-error" ? "Workspace administration could not be loaded. Try again." : "Workspace administration ready. Synthetic study state only.", state.scenario === "admin-error" ? "error" : "")}
      <dl class="identity-strip" aria-label="Signed-in administration context"><div><dt>Signed in</dt><dd>Alex Morgan</dd></div><div><dt>Workspace</dt><dd>${context.name}</dd></div><div><dt>Role</dt><dd>${context.role}</dd></div><div><dt>Scope</dt><dd>Current workspace</dd></div></dl>
      <div class="admin-context"><nav class="subnav" aria-label="Workspace administration sections"><button type="button" data-section="members" aria-current="${state.section === "members" ? "page" : "false"}">Members</button><button type="button" data-section="pending" aria-current="${state.section === "pending" ? "page" : "false"}">Pending approvals</button><button type="button" data-section="access" aria-current="${state.section === "access" ? "page" : "false"}">App access</button><button type="button" data-section="activity" aria-current="${state.section === "activity" ? "page" : "false"}">Audit activity</button></nav><span class="role-badge">${context.role}</span></div>
      <section class="admin-summary" aria-label="Workspace summary"><div><small>Workspace</small><strong>${context.name}</strong></div><div><small>Administration</small><strong>Owner access</strong></div><div><small>Applications</small><strong>1 registered product</strong></div></section>
      ${adminSection()}
    `;
  }

  function adminSection() {
    if (state.section === "pending") return pendingSection();
    if (state.section === "access") return accessSection();
    if (state.section === "activity") return activitySection();
    return membersSection();
  }

  function membersSection() {
    const list = state.scenario === "empty" ? [] : state.scenario === "long" ? longMembers() : members;
    if (!list.length) return `<section class="surface"><div class="surface-heading"><div><h2>Members</h2><p>Active and disabled workspace memberships.</p></div><button class="button" type="button" data-open-modal="add" data-focus-id="add-member">Add member</button></div>${emptyState("No workspace members are available", "Add a provider-backed user or create a pending workspace approval.")}</section>`;
    return `<section class="surface" aria-labelledby="members-heading"><div class="surface-heading"><div><h2 id="members-heading">Members</h2><p>Change roles deliberately. Owners remain protected from routine removal actions.</p></div><button class="button" type="button" data-open-modal="add" data-focus-id="add-member">Add member</button></div><div class="table-wrap"><table><caption class="sr-only">Workspace members</caption><thead><tr><th>Member</th><th>Role</th><th>Status</th><th>Last active</th><th>Actions</th></tr></thead><tbody>${list.map(memberRow).join("")}</tbody></table></div></section>`;
  }

  function memberRow([id, name, email, role, status, active]) {
    const owner = role === "Owner";
    const disabled = status === "disabled";
    const menuOpen = state.menu === id;
    const menu = owner ? `<span class="owner-protected">Owner protected</span>` : `<div class="action-menu"><button class="menu-button" type="button" data-menu="${id}" data-focus-id="menu-${id}" aria-haspopup="menu" aria-expanded="${menuOpen}">Actions <span aria-hidden="true">⌄</span></button><div class="menu-panel" role="menu" ${menuOpen ? "" : "hidden"}>${disabled ? `<button type="button" role="menuitem" data-open-modal="confirm" data-action="reactivate" data-target="${name}">Reactivate</button>` : `<button type="button" role="menuitem" data-open-modal="confirm" data-action="disable" data-target="${name}">Disable access</button>`}<button type="button" role="menuitem" class="danger-option" data-open-modal="confirm" data-action="remove" data-target="${name}">Remove from workspace</button></div></div>`;
    return `<tr><td data-label="Member"><div class="person"><strong>${name}</strong><small>${email}</small></div></td><td data-label="Role">${owner ? `<span class="role-badge">Owner</span>` : `<select class="role-select" aria-label="Role for ${name}" data-role="${id}"><option ${role === "Admin" ? "selected" : ""}>Admin</option><option ${role === "Member" ? "selected" : ""}>Member</option></select>`}</td><td data-label="Status"><span class="state-badge ${disabled ? "disabled" : ""}">${disabled ? "Disabled" : "Active"}</span></td><td data-label="Last active" class="muted">${active}</td><td data-label="Actions">${menu}</td></tr>`;
  }

  function pendingSection() {
    const list = state.scenario === "empty" ? [] : approvals;
    return `<section class="surface" aria-labelledby="pending-heading"><div class="surface-heading"><div><h2 id="pending-heading">Pending approvals</h2><p>These approvals do not send email or grant access before a matching provider-backed sign-in.</p></div></div>${list.length ? `<div class="table-wrap"><table><caption class="sr-only">Pending workspace approvals</caption><thead><tr><th>Requester</th><th>Role</th><th>Status</th><th>Created</th><th>Action</th></tr></thead><tbody>${list.map(([id, email, role, status, created]) => `<tr><td data-label="Requester"><div class="person"><strong>${email}</strong><small>Pending workspace approval</small></div></td><td data-label="Role"><span class="role-badge">${role}</span></td><td data-label="Status"><span class="state-badge pending">${status}</span></td><td data-label="Created" class="muted">${created}</td><td data-label="Action"><button class="menu-button" type="button" data-open-modal="confirm" data-action="revoke" data-target="${email}" data-focus-id="revoke-${id}">Revoke</button></td></tr>`).join("")}</tbody></table></div>` : emptyState("No pending approvals", "A new teammate approval will appear here until their matching provider-backed sign-in activates access.")}</section>`;
  }

  function accessSection() {
    if (state.scenario === "empty") return `<section class="surface" aria-labelledby="access-heading"><div class="surface-heading"><div><h2 id="access-heading">App access</h2><p>Workspace app availability and launch access controls.</p></div></div>${emptyState("No app entitlements are configured", "This workspace currently has no registered app access records.")}</section>`;
    const disabled = state.scenario === "unavailable";
    return `<section class="surface" aria-labelledby="access-heading"><div class="surface-heading"><div><h2 id="access-heading">App access</h2><p>Workspace-level access only. Platform does not expose product workflow data here.</p></div></div><div class="entitlement-row"><div><h3>Swooshz Quote Auto Generator</h3><p>Registered application / ${disabled ? "launch unavailable" : "launch available"} for this workspace.</p><div class="app-meta"><span class="state-badge ${disabled ? "denied" : ""}">${disabled ? "Disabled" : "Enabled"}</span><span class="state-badge">Available</span></div></div><button class="button ${disabled ? "" : "secondary"}" type="button" data-open-modal="confirm" data-action="${disabled ? "enable" : "disable-app"}" data-target="Swooshz Quote Auto Generator" data-focus-id="app-entitlement">${disabled ? "Allow launch" : "Disable access"}</button></div></section>`;
  }

  function activitySection() {
    const list = state.scenario === "empty" ? [] : state.scenario === "long" ? longAuditEvents() : auditEvents;
    const pageSize = 8;
    const start = state.activityPage * pageSize;
    const visible = list.slice(start, start + pageSize);
    const end = Math.min(start + visible.length, list.length);
    return `<section class="surface" aria-labelledby="activity-heading"><div class="surface-heading"><div><h2 id="activity-heading" tabindex="-1">Audit activity</h2><p>Recent, bounded workspace activity with safe labels rather than raw identifiers.</p></div></div>${list.length ? `<div class="table-wrap"><table><caption class="sr-only">Recent workspace audit activity</caption><thead><tr><th>Action</th><th>Subject</th><th>Actor</th><th>Time</th><th>Details</th></tr></thead><tbody>${visible.map(([action, subject, actor, time, detail]) => `<tr><td data-label="Action"><strong>${action}</strong></td><td data-label="Subject">${subject}</td><td data-label="Actor">${actor}</td><td data-label="Time" class="muted">${time}</td><td data-label="Details" class="muted">${detail}</td></tr>`).join("")}</tbody></table></div><div class="pagination"><p>Showing ${start + 1}-${end} of ${list.length} recent events</p><div><button class="menu-button" type="button" data-activity-page="${Math.max(0, state.activityPage - 1)}" ${state.activityPage === 0 ? "disabled" : ""}>Newer</button><button class="menu-button" type="button" data-activity-page="${state.activityPage + 1}" ${end >= list.length ? "disabled" : ""}>Older</button></div></div>` : emptyState("No recent workspace activity", "New membership and app-access actions would appear here after they are completed.")}</section>`;
  }

  function longMembers() {
    return [...members, ...Array.from({ length: 11 }, (_, index) => [`long_${index}`, `Synthetic Member ${index + 6} With an Intentionally Long Display Name`, `synthetic.member.${index + 6}@example.com`, index % 3 === 0 ? "Admin" : "Member", "active", `${index + 4} days ago`])];
  }

  function longAuditEvents() {
    return [...auditEvents, ...Array.from({ length: 14 }, (_, index) => ["Member added", `Synthetic Member ${index + 1}`, "Alex Morgan", `${index + 2} weeks ago`, "Role: Member"])];
  }

  function loadingPage(message) {
    return `<section class="page-intro"><div><p class="eyebrow">Session loading</p><h1>${message}</h1><p>Essential context stays readable while the platform checks the current session and workspace scope.</p></div></section>${statusLine(message, "busy")}<div class="loading-screen" aria-hidden="true"><div class="skeleton wide"></div><div class="skeleton medium"></div><div class="skeleton short"></div><div class="skeleton wide"></div></div>`;
  }

  function emptyState(title, copy) {
    return `<div class="empty-state"><h2>${title}</h2><p>${copy}</p></div>`;
  }

  function statusLine(message, tone) {
    const busy = tone === "busy";
    return `<section class="status-line" role="status" aria-live="polite" data-tone="${tone === "busy" ? "" : tone}">${busy ? `<span class="spinner" aria-hidden="true"></span>` : ""}<span>${message}</span></section>`;
  }

  function modal() {
    if (state.modal.type === "add") return `<div class="modal-backdrop" data-backdrop><section class="modal" role="dialog" aria-modal="true" aria-labelledby="add-title"><header><div><h2 id="add-title">Add member</h2><p>Create a pending workspace access approval or add an existing provider-backed user. No email delivery is implied.</p></div><button class="close-modal" type="button" data-close-modal aria-label="Close add member form">×</button></header><form id="add-member-form"><div class="modal-content"><div class="form-row"><label for="member-email">Email address</label><input id="member-email" name="email" type="email" autocomplete="email" placeholder="teammate@example.com" required /></div><div class="form-row"><label for="member-role">Workspace role</label><select id="member-role" name="role"><option value="admin">Admin</option><option value="member" selected>Member</option></select></div><p class="modal-feedback">Access activates only after the matching approved provider-backed sign-in.</p></div><footer class="modal-footer"><button class="button secondary" type="button" data-close-modal>Cancel</button><button class="button" type="submit">Add member</button></footer></form></section></div>`;
    const action = state.modal.action;
    const copy = {
      disable: ["Disable member?", "This disables workspace access for this member. Their platform account is not deleted.", "Disable member"],
      reactivate: ["Reactivate member?", "This restores workspace access for this member.", "Reactivate member"],
      remove: ["Remove member?", "This removes workspace access for this member. Their platform account is not deleted.", "Remove member"],
      revoke: ["Revoke approval?", "This removes this pending workspace access approval. No email is sent.", "Revoke approval"],
      enable: ["Allow application launch?", "This enables Swooshz Quote Auto Generator for this workspace.", "Allow launch"],
      "disable-app": ["Disable application access?", "This makes Swooshz Quote Auto Generator unavailable for this workspace.", "Disable access"],
    }[action || "remove"];
    const busy = Boolean(state.modal.busy);
    const error = Boolean(state.modal.error);
    return `<div class="modal-backdrop" data-backdrop><section class="modal" role="dialog" aria-modal="true" aria-labelledby="confirm-title"><header><div><h2 id="confirm-title">${copy[0]}</h2><p>${state.modal.target}</p></div><button class="close-modal" type="button" data-close-modal aria-label="Cancel ${copy[0]}" ${busy ? "disabled" : ""}>×</button></header><div class="modal-content"><p>${copy[1]}</p>${busy ? `<p class="modal-feedback"><span class="spinner" aria-hidden="true"></span> Completing this workspace action...</p>` : ""}${error ? `<p class="modal-feedback error" role="alert">Workspace admin action could not be completed. The current access state was not changed.</p>` : ""}</div><footer class="modal-footer"><button class="button secondary" type="button" data-close-modal ${busy ? "disabled" : ""}>Cancel</button><button class="button ${action === "remove" || action === "disable" || action === "disable-app" ? "danger" : ""}" type="button" data-confirm-action ${busy ? "disabled" : ""}>${busy ? `<span class="spinner" aria-hidden="true"></span>Working` : error ? "Try again" : copy[2]}</button></footer></section></div>`;
  }

  function bindEvents() {
    document.querySelectorAll("[data-screen]").forEach((button) => button.addEventListener("click", () => {
      state.screen = button.dataset.screen;
      state.mobileMenu = false;
      state.workspaceMenu = false;
      updateUrl();
      render();
      document.getElementById("study-main").focus();
      announce(state.screen === "admin" ? "Workspace administration selected." : "Product launcher selected.");
    }));
    document.querySelectorAll("[data-section]").forEach((button) => button.addEventListener("click", () => {
      state.section = button.dataset.section;
      state.menu = null;
      state.activityPage = 0;
      updateUrl();
      render();
      const heading = document.querySelector(".surface h2");
      if (heading) heading.setAttribute("tabindex", "-1"), heading.focus();
      announce(`${button.textContent.trim()} selected.`);
    }));
    document.getElementById("mobile-nav-toggle")?.addEventListener("click", () => {
      state.mobileMenu = !state.mobileMenu;
      render();
      if (state.mobileMenu) document.querySelector("#primary-nav button")?.focus();
      else document.getElementById("mobile-nav-toggle")?.focus();
    });
    document.getElementById("workspace-trigger")?.addEventListener("click", () => {
      state.workspaceMenu = !state.workspaceMenu;
      render();
      if (state.workspaceMenu) document.querySelector("[data-workspace]")?.focus();
    });
    document.querySelectorAll("[data-workspace]").forEach((button) => button.addEventListener("click", () => {
      state.selectedWorkspace = button.dataset.workspace;
      state.workspaceMenu = false;
      state.screen = "app";
      updateUrl();
      render();
      announce(`${currentWorkspace().name} selected.`);
    }));
    document.querySelectorAll("[data-launch]").forEach((button) => button.addEventListener("click", () => {
      button.disabled = true;
      button.innerHTML = `<span class="spinner" aria-hidden="true"></span>Opening`;
      announce("Opening Swooshz Quote Auto Generator.");
      window.setTimeout(() => toast("Launch request accepted in this local study. The product would open separately.", "success"), 650);
    }));
    document.getElementById("logout")?.addEventListener("click", () => {
      state.scenario = "unauthenticated";
      state.screen = "app";
      render();
      announce("Signed out of the local study.");
    });
    document.querySelector("[data-signin]")?.addEventListener("click", () => {
      state.scenario = "default";
      render();
      announce("Local session restored for this design study.");
    });
    document.querySelectorAll("[data-menu]").forEach((button) => button.addEventListener("click", (event) => {
      event.stopPropagation();
      state.menu = state.menu === button.dataset.menu ? null : button.dataset.menu;
      render();
      if (state.menu) document.querySelector(".menu-panel button")?.focus();
    }));
    document.querySelectorAll("[data-role]").forEach((select) => select.addEventListener("change", () => toast("Member role updated in this local study.", "success")));
    document.querySelectorAll("[data-activity-page]").forEach((button) => button.addEventListener("click", () => {
      state.activityPage = Number(button.dataset.activityPage || 0);
      render();
      document.querySelector("#activity-heading")?.focus();
      announce(`Audit activity page ${state.activityPage + 1} selected.`);
    }));
    document.querySelectorAll("[data-open-modal]").forEach((button) => button.addEventListener("click", () => openModal(button.dataset.openModal, button.dataset.focusId, button.dataset.action, button.dataset.target)));
    document.querySelectorAll("[data-close-modal]").forEach((button) => button.addEventListener("click", closeModal));
    document.querySelector("[data-backdrop]")?.addEventListener("click", (event) => { if (event.target === event.currentTarget && !state.modal?.busy) closeModal(); });
    document.getElementById("add-member-form")?.addEventListener("submit", (event) => {
      event.preventDefault();
      const email = new FormData(event.currentTarget).get("email");
      state.modal = null;
      render();
      restoreFocus();
      toast(`Pending approval created for ${email}. This local study sends no email.`, "success");
      announce("Pending workspace approval created.");
    });
    document.querySelector("[data-confirm-action]")?.addEventListener("click", () => {
      if (state.modal.error) { state.modal.error = false; render(); return; }
      state.modal.busy = true;
      render();
      window.setTimeout(() => {
        const action = state.modal?.action || "action";
        state.modal = null;
        render();
        restoreFocus();
        toast(`${action.replace("-", " ")} completed in this local study.`, "success");
        announce("Workspace action completed.");
      }, 700);
    });
  }

  function openModal(type, focusId, action, target) {
    state.lastFocusId = focusId || null;
    state.menu = null;
    state.modal = type === "add" ? { type } : { type, action: action || "remove", target: target || "this member" };
    render();
  }

  function closeModal() {
    if (state.modal?.busy) return;
    state.modal = null;
    render();
    restoreFocus();
  }

  function focusModal() {
    window.setTimeout(() => {
      const target = document.querySelector(".modal input:not([disabled])")
        || document.querySelector(".modal select:not([disabled])")
        || document.querySelector(".modal button:not([disabled])");
      target?.focus();
    }, 0);
  }

  function restoreFocus() {
    const focusId = state.lastFocusId;
    state.lastFocusId = null;
    if (!focusId) return;
    window.setTimeout(() => document.querySelector(`[data-focus-id="${focusId}"]`)?.focus(), 0);
  }

  function toast(message, tone) {
    document.querySelector(".toast")?.remove();
    const node = document.createElement("div");
    node.className = "toast";
    node.dataset.tone = tone;
    node.setAttribute("role", "status");
    node.textContent = message;
    document.body.append(node);
    window.setTimeout(() => node.remove(), 4200);
  }

  document.addEventListener("click", (event) => {
    if (!event.target.closest(".action-menu")) {
      if (state.menu) { state.menu = null; render(); }
    }
    if (!event.target.closest(".workspace-switcher") && state.workspaceMenu) { state.workspaceMenu = false; render(); }
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      if (state.modal && !state.modal.busy) { event.preventDefault(); closeModal(); return; }
      if (state.menu) { state.menu = null; render(); return; }
      if (state.workspaceMenu) { state.workspaceMenu = false; render(); document.getElementById("workspace-trigger")?.focus(); return; }
      if (state.mobileMenu) { state.mobileMenu = false; render(); document.getElementById("mobile-nav-toggle")?.focus(); }
    }
    if (event.key === "Tab" && state.modal) {
      const focusable = [...document.querySelectorAll(".modal button:not([disabled]), .modal input:not([disabled]), .modal select:not([disabled])")];
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    }
  });

  render();
})();
