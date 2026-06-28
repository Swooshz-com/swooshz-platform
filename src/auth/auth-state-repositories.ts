import type {
  AuthStateIssueStore,
  AuthStateStore,
  StoredAuthState,
} from "./callback.js";

export interface StoredAuthStateLifecycleRecord extends StoredAuthState {
  consumedAt: string | null;
  revokedAt: string | null;
}

export interface AuthStateRepository extends AuthStateIssueStore, AuthStateStore {}
