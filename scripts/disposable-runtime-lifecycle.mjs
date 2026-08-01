const lifecycleErrorMessage = "Disposable runtime lifecycle failed.";

export class DisposableRuntimeLifecycleError extends Error {
  constructor() {
    super(lifecycleErrorMessage);
    this.name = "DisposableRuntimeLifecycleError";
    this.code = "disposable_runtime_lifecycle_failed";
  }
}

export async function runDisposableRuntimeLifecycle({
  construct,
  admitConstruction,
  deriveProvisioning,
  provision,
  admitConfigured,
  runFocusedTests,
  cleanup,
  verifyAbsence,
} = {}) {
  for (const step of [
    construct,
    admitConstruction,
    deriveProvisioning,
    provision,
    admitConfigured,
    runFocusedTests,
    cleanup,
    verifyAbsence,
  ]) {
    if (typeof step !== "function") {
      throw new DisposableRuntimeLifecycleError();
    }
  }

  const resources = {
    construction: null,
    constructionAuthority: null,
    configuredAdmission: null,
    provisioningAuthorities: null,
    runnerOwned: new Set(),
    callerManaged: new Set(),
  };
  let primaryError = null;
  let cleanupError = null;
  let absenceError = null;
  try {
    resources.construction = await construct(resources);
    resources.constructionAuthority = await admitConstruction(
      resources.construction,
      resources,
    );
    resources.provisioningAuthorities = await deriveProvisioning(
      resources.constructionAuthority,
      resources.construction,
      resources,
    );
    await provision(
      resources.provisioningAuthorities,
      resources.construction,
      resources,
    );
    resources.configuredAdmission = await admitConfigured(
      resources.construction,
      resources,
    );
    await runFocusedTests(resources.configuredAdmission, resources);
  } catch {
    primaryError = new DisposableRuntimeLifecycleError();
  } finally {
    try {
      await cleanup(resources);
    } catch {
      cleanupError = new DisposableRuntimeLifecycleError();
    }
    try {
      await verifyAbsence(resources);
    } catch {
      absenceError = new DisposableRuntimeLifecycleError();
    }
  }

  if (cleanupError || absenceError || primaryError) {
    throw cleanupError ?? absenceError ?? primaryError;
  }
  return resources;
}
