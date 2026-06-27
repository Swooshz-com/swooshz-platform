import {
  decideAppAccess,
  type AccessDecision,
  type BillingGate,
} from "../access/decide-app-access.js";
import type { PlatformRepositories } from "./repositories.js";

export interface DecidePlatformAppAccessInput {
  sessionId: string | null;
  selectedWorkspaceId: string | null;
  appKey: string;
  now: string;
  billingGate?: BillingGate;
}

export async function decidePlatformAppAccess(
  repositories: PlatformRepositories,
  input: DecidePlatformAppAccessInput,
): Promise<AccessDecision> {
  const session = input.sessionId
    ? await repositories.sessions.findById(input.sessionId)
    : null;
  const user = session ? await repositories.users.findById(session.userId) : null;

  if (!session || !user || !input.selectedWorkspaceId) {
    return decideAppAccess({
      appKey: input.appKey,
      session,
      user,
      selectedWorkspaceId: input.selectedWorkspaceId,
      workspaces: [],
      memberships: [],
      apps: [],
      entitlements: [],
      billingGate: input.billingGate,
      now: input.now,
    });
  }

  const [workspace, membership, app] = await Promise.all([
    repositories.workspaces.findById(input.selectedWorkspaceId),
    repositories.memberships.findForUserInWorkspace(user.id, input.selectedWorkspaceId),
    repositories.apps.findByKey(input.appKey),
  ]);

  const entitlement =
    workspace && app
      ? await repositories.appEntitlements.findForWorkspaceApp(workspace.id, app.id)
      : null;

  return decideAppAccess({
    appKey: input.appKey,
    session,
    user,
    selectedWorkspaceId: input.selectedWorkspaceId,
    workspaces: workspace ? [workspace] : [],
    memberships: membership ? [membership] : [],
    apps: app ? [app] : [],
    entitlements: entitlement ? [entitlement] : [],
    billingGate: input.billingGate,
    now: input.now,
  });
}
