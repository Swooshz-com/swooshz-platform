export function createInMemoryPlatformRepositories(records = {}) {
  const users = records.users ?? [];
  const sessions = records.sessions ?? [];
  const workspaces = records.workspaces ?? [];
  const memberships = records.memberships ?? [];
  const invitations = records.invitations ?? [];
  const apps = records.apps ?? [];
  const appEntitlements = records.appEntitlements ?? [];
  const auditEvents = records.auditEvents ?? [];

  return {
    users: {
      async findById(id) {
        return users.find((user) => user.id === id) ?? null;
      },
      async findByNormalizedEmail(email) {
        return users.find((user) => user.email === email) ?? null;
      },
    },
    sessions: {
      async findById(id) {
        return sessions.find((session) => session.id === id) ?? null;
      },
    },
    workspaces: {
      async findById(id) {
        return workspaces.find((workspace) => workspace.id === id) ?? null;
      },
      async findBySlug(slug) {
        return workspaces.find((workspace) => workspace.slug === slug) ?? null;
      },
    },
    memberships: {
      async findForUserInWorkspace(userId, workspaceId) {
        return (
          memberships.find(
            (membership) =>
              membership.userId === userId && membership.workspaceId === workspaceId,
          ) ?? null
        );
      },
      async listForUser(userId) {
        return memberships.filter((membership) => membership.userId === userId);
      },
    },
    invitations: {
      async findById(id) {
        return invitations.find((invitation) => invitation.id === id) ?? null;
      },
      async create(invitation) {
        invitations.push(invitation);
        return invitation;
      },
      async updateStatus(id, status, timestamps = {}) {
        const invitation = invitations.find((candidate) => candidate.id === id);
        if (!invitation) {
          return null;
        }

        Object.assign(invitation, { status }, timestamps);
        return invitation;
      },
    },
    apps: {
      async findByKey(key) {
        return apps.find((app) => app.key === key) ?? null;
      },
      async findById(id) {
        return apps.find((app) => app.id === id) ?? null;
      },
    },
    appEntitlements: {
      async findForWorkspaceApp(workspaceId, appId) {
        return (
          appEntitlements.find(
            (entitlement) =>
              entitlement.workspaceId === workspaceId && entitlement.appId === appId,
          ) ?? null
        );
      },
    },
    auditEvents: {
      async append(event) {
        auditEvents.push(event);
        return event;
      },
    },
  };
}
