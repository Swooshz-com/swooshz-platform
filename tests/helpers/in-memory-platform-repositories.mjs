export function createInMemoryPlatformRepositories(records = {}) {
  const users = records.users ?? [];
  const providerIdentities = records.providerIdentities ?? [];
  const sessions = records.sessions ?? [];
  const workspaces = records.workspaces ?? [];
  const memberships = records.memberships ?? [];
  const invitations = records.invitations ?? [];
  const apps = records.apps ?? [];
  const appEntitlements = records.appEntitlements ?? [];
  const auditEvents = records.auditEvents ?? [];
  const appLaunchTokens = records.appLaunchTokens ?? [];

  const repositories = {
    users: {
      async findById(id) {
        return users.find((user) => user.id === id) ?? null;
      },
      async findByNormalizedEmail(email) {
        return users.find((user) => user.email === email) ?? null;
      },
      async create(user) {
        users.push(user);
        return user;
      },
    },
    providerIdentities: {
      async findByProviderSubject(providerKey, providerSubject) {
        return (
          providerIdentities.find(
            (identity) =>
              identity.providerKey === providerKey &&
              identity.providerSubject === providerSubject,
          ) ?? null
        );
      },
      async listForUser(userId) {
        return providerIdentities.filter((identity) => identity.userId === userId);
      },
      async create(identity) {
        providerIdentities.push(identity);
        return identity;
      },
    },
    sessions: {
      async findById(id) {
        return sessions.find((session) => session.id === id) ?? null;
      },
      async create(session) {
        sessions.push(session);
        return session;
      },
      async revoke(id, revokedAt) {
        const session = sessions.find((candidate) => candidate.id === id);

        if (!session) {
          return null;
        }

        session.revokedAt = revokedAt;
        return session;
      },
    },
    workspaces: {
      async findById(id) {
        return workspaces.find((workspace) => workspace.id === id) ?? null;
      },
      async findBySlug(slug) {
        return workspaces.find((workspace) => workspace.slug === slug) ?? null;
      },
      async create(workspace) {
        workspaces.push(workspace);
        return workspace;
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
      async listForWorkspace(workspaceId) {
        return memberships.filter((membership) => membership.workspaceId === workspaceId);
      },
      async create(membership) {
        memberships.push(membership);
        return membership;
      },
      async updateRole(id, role, updatedAt) {
        const membership = memberships.find((candidate) => candidate.id === id);

        if (!membership) {
          return null;
        }

        membership.role = role;
        membership.updatedAt = updatedAt;
        return membership;
      },
      async updateStatus(id, status, updatedAt) {
        const membership = memberships.find((candidate) => candidate.id === id);

        if (!membership) {
          return null;
        }

        membership.status = status;
        membership.updatedAt = updatedAt;
        return membership;
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
      async listAll() {
        return apps;
      },
      async create(app) {
        apps.push(app);
        return app;
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
      async listForWorkspace(workspaceId) {
        return appEntitlements.filter(
          (entitlement) => entitlement.workspaceId === workspaceId,
        );
      },
      async create(entitlement) {
        appEntitlements.push(entitlement);
        return entitlement;
      },
      async updateStatus(id, status, grantedByUserId, updatedAt) {
        const entitlement = appEntitlements.find((candidate) => candidate.id === id);

        if (!entitlement) {
          return null;
        }

        entitlement.status = status;
        entitlement.grantedByUserId = grantedByUserId;
        entitlement.updatedAt = updatedAt;
        return entitlement;
      },
    },
    auditEvents: {
      async append(event) {
        auditEvents.push(event);
        return event;
      },
      async listForWorkspace(workspaceId, limit) {
        return auditEvents
          .filter((event) => event.workspaceId === workspaceId)
          .sort((left, right) => right.createdAt.localeCompare(left.createdAt))
          .slice(0, limit);
      },
    },
    appLaunchTokens: {
      async create(record) {
        appLaunchTokens.push(record);
        return record;
      },
      async findByTokenHash(tokenHash) {
        return appLaunchTokens.find((record) => record.tokenHash === tokenHash) ?? null;
      },
      async consumeUnconsumed(id, consumedAt) {
        const record = appLaunchTokens.find((candidate) => candidate.id === id);

        if (!record || record.consumedAt || record.revokedAt) {
          return null;
        }

        record.consumedAt = consumedAt;
        return record;
      },
    },
  };

  repositories.workspaceAdminTransactions = {
    async run(operation) {
      const snapshots = [
        users,
        providerIdentities,
        sessions,
        workspaces,
        memberships,
        invitations,
        apps,
        appEntitlements,
        auditEvents,
        appLaunchTokens,
      ].map(snapshotRecords);

      try {
        return await operation(repositories);
      } catch (error) {
        restoreRecords(users, snapshots[0]);
        restoreRecords(providerIdentities, snapshots[1]);
        restoreRecords(sessions, snapshots[2]);
        restoreRecords(workspaces, snapshots[3]);
        restoreRecords(memberships, snapshots[4]);
        restoreRecords(invitations, snapshots[5]);
        restoreRecords(apps, snapshots[6]);
        restoreRecords(appEntitlements, snapshots[7]);
        restoreRecords(auditEvents, snapshots[8]);
        restoreRecords(appLaunchTokens, snapshots[9]);
        throw error;
      }
    },
  };

  return repositories;
}

function snapshotRecords(records) {
  return records.map((record) => ({ ...record }));
}

function restoreRecords(records, snapshot) {
  records.splice(0, records.length, ...snapshot.map((record) => ({ ...record })));
}
