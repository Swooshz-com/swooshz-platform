(() => {
  const body = document.body;

  if (!body?.classList.contains("public-site")) {
    return;
  }

  const root = document.documentElement;
  const menuButton = document.querySelector("[data-public-menu-toggle]");
  const navigation = document.querySelector("[data-public-navigation]");
  const hero = document.querySelector("[data-public-hero]");
  const heroArtwork = document.querySelector("[data-public-hero-art]");
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  const mobileNavigation = window.matchMedia("(max-width: 900px)");
  const desktopFinePointer = window.matchMedia("(min-width: 901px) and (hover: hover) and (pointer: fine)");
  const shortViewport = window.matchMedia("(max-height: 639px)");
  let scrollFrame = 0;
  let resizeFrame = 0;

  function isMenuOpen() {
    return menuButton?.getAttribute("aria-expanded") === "true";
  }

  function setNavigationAccess(open) {
    if (!(menuButton instanceof HTMLButtonElement) || !(navigation instanceof HTMLElement)) {
      return;
    }

    const hidden = mobileNavigation.matches && !open;
    menuButton.setAttribute("aria-expanded", String(open));
    menuButton.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
    navigation.classList.toggle("is-open", open);
    navigation.toggleAttribute("inert", hidden);
    navigation.setAttribute("aria-hidden", String(hidden));
    body.classList.toggle("public-menu-open", open);
  }

  function closeMenu({ restoreFocus = false } = {}) {
    if (!menuButton || !navigation) {
      return;
    }

    setNavigationAccess(false);

    if (restoreFocus && mobileNavigation.matches) {
      menuButton.focus();
    }
  }

  function openMenu() {
    if (!mobileNavigation.matches || !navigation) {
      return;
    }

    setNavigationAccess(true);
    requestAnimationFrame(() => navigation.querySelector("a")?.focus());
  }

  function syncNavigation() {
    if (!menuButton || !navigation) {
      return;
    }

    if (!mobileNavigation.matches) {
      navigation.classList.remove("is-open");
      navigation.removeAttribute("inert");
      navigation.setAttribute("aria-hidden", "false");
      menuButton.setAttribute("aria-expanded", "false");
      menuButton.setAttribute("aria-label", "Open navigation");
      body.classList.remove("public-menu-open");
      return;
    }

    setNavigationAccess(isMenuOpen());
  }

  menuButton?.addEventListener("click", () => {
    if (isMenuOpen()) {
      closeMenu({ restoreFocus: true });
    } else {
      openMenu();
    }
  });

  navigation?.querySelectorAll("a").forEach((link) => {
    link.addEventListener("click", () => closeMenu());
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && isMenuOpen()) {
      event.preventDefault();
      closeMenu({ restoreFocus: true });
    }
  });

  document.addEventListener("pointerdown", (event) => {
    if (!isMenuOpen() || navigation?.contains(event.target) || menuButton?.contains(event.target)) {
      return;
    }

    closeMenu({ restoreFocus: true });
  });

  mobileNavigation.addEventListener?.("change", syncNavigation);
  window.addEventListener("orientationchange", () => {
    closeMenu();
    window.setTimeout(syncNavigation, 80);
  });

  function resetPointer() {
    root.style.setProperty("--pointer-x", "0");
    root.style.setProperty("--pointer-y", "0");
  }

  heroArtwork?.addEventListener("pointermove", (event) => {
    if (!desktopFinePointer.matches || reducedMotion.matches) {
      resetPointer();
      return;
    }

    const rect = heroArtwork.getBoundingClientRect();
    const x = ((event.clientX - rect.left) / rect.width - 0.5) * 2;
    const y = ((event.clientY - rect.top) / rect.height - 0.5) * 2;
    root.style.setProperty("--pointer-x", x.toFixed(3));
    root.style.setProperty("--pointer-y", y.toFixed(3));
  });

  heroArtwork?.addEventListener("pointerleave", resetPointer);
  heroArtwork?.addEventListener("pointercancel", resetPointer);
  window.addEventListener("blur", resetPointer);
  window.addEventListener("pagehide", resetPointer);

  function updateHeroProgress() {
    scrollFrame = 0;

    if (!hero || reducedMotion.matches) {
      root.style.setProperty("--hero-progress", "0");
      return;
    }

    const rect = hero.getBoundingClientRect();
    const distance = Math.max(1, rect.height - window.innerHeight * 0.35);
    const progress = Math.min(1, Math.max(0, -rect.top / distance));
    root.style.setProperty("--hero-progress", progress.toFixed(4));
  }

  function requestHeroProgress() {
    if (!scrollFrame) {
      scrollFrame = requestAnimationFrame(updateHeroProgress);
    }
  }

  const scenes = Array.from(document.querySelectorAll("[data-scroll-scene]"));

  function focusSuppressesSettling() {
    const active = document.activeElement;

    return active instanceof HTMLElement && active !== body && active !== root;
  }

  function selectionSuppressesSettling() {
    return !window.getSelection()?.isCollapsed;
  }

  function hasTallScene() {
    const headerHeight = document.querySelector(".public-nav")?.getBoundingClientRect().height ?? 0;
    const availableHeight = Math.max(1, window.innerHeight - headerHeight);
    let tall = false;

    scenes.forEach((scene) => {
      const isTall = scene.scrollHeight > availableHeight + 2;
      scene.toggleAttribute("data-scroll-tall", isTall);
      tall ||= isTall;
    });

    return tall;
  }

  function scrollAssistReason() {
    if (body.dataset.publicRoute !== "home") return "route";
    if (!scenes.length) return "no-scenes";
    if (reducedMotion.matches) return "reduced-motion";
    if (!desktopFinePointer.matches) return "input-or-width";
    if (shortViewport.matches) return "short-viewport";
    if (window.visualViewport && window.visualViewport.scale !== 1) return "zoom";
    if (Number.parseFloat(getComputedStyle(root).fontSize) > 19) return "text-size";
    if (window.location.hash) return "deep-link";
    if (focusSuppressesSettling()) return "focus";
    if (selectionSuppressesSettling()) return "selection";
    if (hasTallScene()) return "tall-scene";
    return "enabled";
  }

  function updateScrollAssist() {
    resizeFrame = 0;
    const reason = scrollAssistReason();
    const enabled = reason === "enabled";
    root.classList.toggle("public-scroll-assist", enabled);
    root.dataset.scrollAssist = enabled ? "enabled" : "disabled";
    root.dataset.scrollAssistReason = reason;
    root.dataset.scrollStrategy = "native-proximity";
  }

  function requestScrollAssistUpdate() {
    if (!resizeFrame) {
      resizeFrame = requestAnimationFrame(updateScrollAssist);
    }
  }

  window.addEventListener("scroll", requestHeroProgress, { passive: true });
  window.addEventListener("resize", () => {
    closeMenu();
    syncNavigation();
    requestHeroProgress();
    requestScrollAssistUpdate();
  });
  window.visualViewport?.addEventListener("resize", requestScrollAssistUpdate);
  document.addEventListener("focusin", requestScrollAssistUpdate);
  document.addEventListener("focusout", () => window.setTimeout(requestScrollAssistUpdate, 0));
  document.addEventListener("selectionchange", requestScrollAssistUpdate);
  window.addEventListener("hashchange", requestScrollAssistUpdate);
  reducedMotion.addEventListener?.("change", () => {
    root.classList.toggle("motion-capable", !reducedMotion.matches);
    root.classList.add("public-ready");
    resetPointer();
    updateHeroProgress();
    updateScrollAssist();
  });
  desktopFinePointer.addEventListener?.("change", updateScrollAssist);
  shortViewport.addEventListener?.("change", updateScrollAssist);

  document.addEventListener("visibilitychange", () => {
    resetPointer();
    if (!document.hidden) {
      syncNavigation();
      updateHeroProgress();
      updateScrollAssist();
    }
  });

  window.addEventListener("pageshow", () => {
    syncNavigation();
    resetPointer();
    updateHeroProgress();
    updateScrollAssist();
  });

  root.classList.toggle("motion-capable", !reducedMotion.matches);
  syncNavigation();
  updateHeroProgress();
  updateScrollAssist();

  if (reducedMotion.matches) {
    root.classList.add("public-ready");
  } else {
    requestAnimationFrame(() => window.setTimeout(() => root.classList.add("public-ready"), 60));
  }
})();
