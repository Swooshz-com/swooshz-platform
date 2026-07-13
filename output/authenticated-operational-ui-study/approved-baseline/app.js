(() => {
  const params = new URLSearchParams(window.location.search);
  const allowedViews = new Set(["launcher", "members", "access", "pending", "audit"]);
  const view = allowedViews.has(params.get("view")) ? params.get("view") : "launcher";
  const adminViews = new Set(["members", "access", "pending", "audit"]);
  const liveRegion = document.querySelector("#live-region");
  document.body.dataset.view = view;
  document.body.dataset.admin = adminViews.has(view) ? "true" : "false";

  const announce = message => { liveRegion.textContent = ""; requestAnimationFrame(() => { liveRegion.textContent = message; }); };
  const wait = milliseconds => new Promise(resolve => window.setTimeout(resolve, milliseconds));

  const labels = { members: "Members", pending: "Pending approvals", access: "Product access", audit: "Audit activity" };
  document.querySelectorAll(".nav-inner a, .section-menu a").forEach(link => {
    const target = new URL(link.href).searchParams.get("view");
    const active = target === view;
    link.classList.toggle("is-active", active);
    if (active) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
  const sectionLabel = document.querySelector("#section-label");
  if (sectionLabel && labels[view]) sectionLabel.textContent = labels[view];

  const workspaceSelect = document.querySelector("#workspace-select");
  const mobileWorkspace = document.querySelector("#mobile-workspace strong");
  const readinessWorkspace = document.querySelector(".launch-readiness dd");
  workspaceSelect?.addEventListener("change", () => {
    mobileWorkspace.textContent = workspaceSelect.value;
    if (readinessWorkspace) readinessWorkspace.textContent = workspaceSelect.value;
    announce(`Workspace changed to ${workspaceSelect.value}.`);
  });
  document.querySelector("#mobile-workspace")?.addEventListener("click", () => {
    workspaceSelect.selectedIndex = workspaceSelect.selectedIndex === 0 ? 1 : 0;
    workspaceSelect.dispatchEvent(new Event("change"));
  });

  const sectionMenu = document.querySelector("#section-menu");
  const selectorButtons = [...document.querySelectorAll("#section-selector, [data-shared-section-selector]")];
  const closeSectionMenu = () => {
    sectionMenu.hidden = true;
    selectorButtons.forEach(button => button.setAttribute("aria-expanded", "false"));
  };
  selectorButtons.forEach(button => button.addEventListener("click", () => {
    const opening = sectionMenu.hidden;
    sectionMenu.hidden = !opening;
    selectorButtons.forEach(item => item.setAttribute("aria-expanded", String(opening)));
    if (opening) sectionMenu.querySelector("[aria-current='page']")?.focus();
  }));

  const mobileMenuButton = document.querySelector(".mobile-menu-button");
  const accountMenu = document.createElement("div");
  accountMenu.className = "action-menu";
  accountMenu.hidden = true;
  accountMenu.setAttribute("role", "menu");
  accountMenu.innerHTML = '<button type="button" role="menuitem">Account details</button><button type="button" role="menuitem">Log out</button>';
  document.body.append(accountMenu);
  mobileMenuButton?.addEventListener("click", () => {
    const opening = accountMenu.hidden;
    accountMenu.hidden = !opening;
    accountMenu.style.top = "54px";
    accountMenu.style.right = "12px";
    accountMenu.style.left = "auto";
    mobileMenuButton.setAttribute("aria-expanded", String(opening));
    if (opening) accountMenu.querySelector("button")?.focus();
  });
  accountMenu.lastElementChild.addEventListener("click", () => announce("Logout is disabled in this local study."));

  const launchButton = document.querySelector("#launch-button");
  const launchReadiness = document.querySelector(".launch-readiness");
  const launchFeedback = document.querySelector("#launch-feedback");
  const launchStatus = launchReadiness?.querySelector("dl > div:nth-child(2) dd");
  const setLaunchState = state => {
    launchReadiness?.classList.remove("is-loading", "is-unavailable");
    launchFeedback.hidden = true;
    launchButton.disabled = false;
    launchButton.querySelector("span").textContent = "Launch quote generator";
    if (launchStatus) launchStatus.innerHTML = '<span class="status-dot" aria-hidden="true"></span>Active';
    if (state === "loading") {
      launchReadiness.classList.add("is-loading");
      launchButton.disabled = true;
      launchButton.querySelector("span").textContent = "Opening quote workspace…";
      announce("Opening the quote workspace.");
    } else if (state === "failure") {
      launchFeedback.hidden = false;
      launchFeedback.innerHTML = '<strong>Launch could not complete.</strong>Your session is safe. Check your connection and try again.<button type="button" data-retry-launch>Retry launch</button>';
      launchFeedback.querySelector("button").addEventListener("click", launchSequence);
      announce("Launch could not complete. Retry is available.");
    } else if (state === "unavailable") {
      launchReadiness.classList.add("is-unavailable");
      launchButton.disabled = true;
      launchButton.querySelector("span").textContent = "Product unavailable";
      if (launchStatus) launchStatus.innerHTML = '<span class="status-dot" aria-hidden="true"></span>Unavailable';
      launchFeedback.hidden = false;
      launchFeedback.innerHTML = '<strong>Product access is unavailable.</strong>Ask a workspace administrator to check the current entitlement.';
    }
  };
  async function launchSequence() {
    setLaunchState("loading");
    await wait(650);
    setLaunchState("failure");
  }
  launchButton?.addEventListener("click", launchSequence);
  setLaunchState(params.get("state") || "ready");

  let restoreFocusTo = null;
  const overlay = document.querySelector("#modal-overlay");
  const addModal = document.querySelector("#add-member-modal");
  const confirmModal = document.querySelector("#confirm-modal");
  const focusableSelector = 'button:not([disabled]), input:not([disabled]), select:not([disabled]), a[href], [tabindex]:not([tabindex="-1"])';

  function openModal(panel, trigger) {
    restoreFocusTo = trigger || document.activeElement;
    overlay.hidden = false;
    addModal.hidden = panel !== addModal;
    confirmModal.hidden = panel !== confirmModal;
    document.body.style.overflow = "hidden";
    requestAnimationFrame(() => (panel === addModal ? panel.querySelector("#member-email") : panel.querySelector(focusableSelector))?.focus());
  }
  function closeModal() {
    overlay.hidden = true;
    addModal.hidden = true;
    confirmModal.hidden = true;
    document.body.style.overflow = "";
    restoreFocusTo?.focus?.();
    restoreFocusTo = null;
  }
  document.querySelectorAll("[data-open-add-member]").forEach(button => button.addEventListener("click", () => openModal(addModal, button)));
  document.querySelectorAll("[data-close-modal]").forEach(button => button.addEventListener("click", closeModal));
  overlay.addEventListener("keydown", event => {
    if (event.key !== "Tab") return;
    const panel = addModal.hidden ? confirmModal : addModal;
    const focusable = [...panel.querySelectorAll(focusableSelector)];
    if (!focusable.length) return;
    const first = focusable[0], last = focusable.at(-1);
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  });

  const addForm = document.querySelector("#add-member-form");
  const modalFeedback = document.querySelector("#modal-feedback");
  addForm.addEventListener("submit", async event => {
    event.preventDefault();
    const submit = addForm.querySelector("[type='submit']");
    const email = document.querySelector("#member-email").value.trim();
    submit.disabled = true;
    submit.textContent = "Adding member…";
    modalFeedback.hidden = true;
    await wait(500);
    submit.disabled = false;
    submit.textContent = "Add member";
    modalFeedback.hidden = false;
    if (email.endsWith("fail.invalid")) {
      modalFeedback.className = "inline-feedback is-error";
      modalFeedback.textContent = "Member could not be added. Check the account and try again.";
      announce("Member could not be added.");
      return;
    }
    modalFeedback.className = "inline-feedback";
    modalFeedback.textContent = "Member added to the workspace.";
    announce("Member added successfully.");
    await wait(550);
    closeModal();
  });

  const memberMenu = document.querySelector("#member-menu");
  document.querySelectorAll("[data-member-menu]").forEach(button => button.addEventListener("click", () => {
    const rect = button.getBoundingClientRect();
    memberMenu.hidden = false;
    memberMenu.dataset.member = button.dataset.memberMenu;
    memberMenu.style.top = `${Math.min(innerHeight - 150, rect.bottom + 4)}px`;
    memberMenu.style.left = innerWidth <= 760 ? "16px" : `${Math.max(16, rect.right - 190)}px`;
    memberMenu.querySelector("button")?.focus();
  }));

  const confirmationCopy = {
    "disable-product": ["Disable product access?", "Members will be unable to start new quote sessions until access is enabled again.", "Disable access"],
    "disable-member": ["Disable this member?", "The member will lose workspace access until reactivated.", "Disable member"],
    "remove-member": ["Remove this member?", "The member will be removed from this workspace. Their account is not deleted.", "Remove member"],
    "reactivate": ["Reactivate this member?", "The member will regain access using their current role.", "Reactivate member"],
    "role": ["Change this member’s role?", "Choose the new role in the production flow before confirming this change.", "Confirm role"]
  };
  document.addEventListener("click", event => {
    const trigger = event.target.closest("[data-confirm]");
    if (!trigger) return;
    const content = confirmationCopy[trigger.dataset.confirm];
    if (!content) return;
    memberMenu.hidden = true;
    document.querySelector("#confirm-title").textContent = content[0];
    document.querySelector("#confirm-copy").textContent = content[1];
    document.querySelector("#confirm-action").textContent = content[2];
    openModal(confirmModal, trigger);
  });
  document.querySelector("#confirm-action").addEventListener("click", async event => {
    const button = event.currentTarget;
    const label = button.textContent;
    button.disabled = true;
    button.textContent = "Applying change…";
    await wait(550);
    button.disabled = false;
    button.textContent = label;
    announce("Administrative change completed.");
    closeModal();
  });

  document.addEventListener("keydown", event => {
    if (event.key === "Escape") {
      if (!overlay.hidden) closeModal();
      memberMenu.hidden = true;
      accountMenu.hidden = true;
      mobileMenuButton?.setAttribute("aria-expanded", "false");
      closeSectionMenu();
    }
  });
  document.addEventListener("click", event => {
    if (!event.target.closest("#member-menu, [data-member-menu]")) memberMenu.hidden = true;
  });

  if (params.get("modal") === "add") openModal(addModal, document.querySelector("[data-open-add-member]"));
  if (params.get("menu") === "member") document.querySelector("[data-member-menu]")?.click();
  if (params.get("focus") === "launch") requestAnimationFrame(() => launchButton?.focus());
})();
