import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  CircleDot,
  Cloud,
  Copy,
  Download,
  ExternalLink,
  FileText,
  KeyRound,
  Loader2,
  LogIn,
  Minus,
  MoreHorizontal,
  Network,
  Pencil,
  PlugZap,
  Plus,
  Power,
  RefreshCw,
  ScrollText,
  Settings as SettingsIcon,
  Shield,
  Square,
  Trash2,
  Upload,
  WifiOff,
  X,
  type LucideIcon,
} from "lucide-react";
import { FormEvent, useEffect, useMemo, useReducer, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type {
  AuthPrompt,
  AuthPromptField,
  AuthSubmittedField,
  DaemonState,
  DaemonStatus,
  DiagnosticsSnapshot,
  IpcEvent,
  IpcExchange,
  IpcResponse,
} from "@/types/ipc";

const appIconUrl = new URL("./assets/app-icon.svg", import.meta.url).href;

type LogEntry = {
  id: number;
  level: "info" | "warn" | "error";
  message: string;
};

type AppView = "profiles" | "secrets" | "diagnostics" | "logs" | "settings";

type ActivityItem = {
  id: AppView;
  label: string;
  icon: LucideIcon;
};

type ProfileItem = {
  name: string;
};

type ProfileList = {
  profile_dir: string;
  profiles: ProfileItem[];
};

type ProfileDetail = {
  name: string;
  server: string;
  username: string | null;
  authgroup: string | null;
  reported_os: string;
  company_domains_count: number;
  local_bypass_count: number;
};

type ProfileDetailState =
  | { status: "unknown" | "checking"; detail: null; message: null }
  | { status: "ready"; detail: ProfileDetail; message: null }
  | { status: "error"; detail: null; message: string };

type VpnPasswordStatus = {
  saved: boolean;
};

type DaemonHandoffStatus = {
  socketPath: string;
  serviceName: string;
  socketReachable: boolean;
  serviceInstalled: boolean | null;
  serviceActive: boolean | null;
  message: string | null;
};

type DaemonHandoffState = {
  status: "unknown" | "checking" | "ready" | "starting" | "error";
  detail: DaemonHandoffStatus | null;
  message: string | null;
};

type GithubSyncAuthState = "not_authorized" | "authorized" | "refresh_failed";

type GithubSyncManifestState = "unknown" | "missing" | "present" | "created";

type GithubSyncStatus = {
  auth: GithubSyncAuthState;
  repository: string;
  keyringAccount: string;
  manifest: GithubSyncManifestState;
  manifestSha: string | null;
  manifestBytes: number | null;
  message: string | null;
};

type GithubSyncHistoryEntry = {
  recordedAt: string;
  operation: string;
  outcome: string;
  repository: string;
  manifestSha: string | null;
  manifestBytes: number | null;
  message: string;
};

type GithubSyncHistory = {
  entries: GithubSyncHistoryEntry[];
};

type GithubSyncState = {
  status: "unknown" | "checking" | "ready" | "error";
  detail: GithubSyncStatus | null;
  message: string | null;
  lastCheckedAt: number | null;
};

type GithubSyncHistoryState = {
  status: "unknown" | "checking" | "ready" | "error";
  entries: GithubSyncHistoryEntry[];
  message: string | null;
};

type GithubDeviceFlowStartResult = {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  expiresInSecs: number;
  intervalSecs: number;
};

type GithubDeviceFlowPollResult = {
  status: "pending" | "slow_down" | "authorized" | "access_denied" | "expired";
  nextIntervalSecs: number;
  expiresInSecs: number | null;
  refreshTokenExpiresInSecs: number | null;
};

type GithubDeviceFlowState = GithubDeviceFlowStartResult & {
  expiresAtMs: number;
  nextIntervalSecs: number;
  pollStatus: GithubDeviceFlowPollResult["status"] | "waiting";
};

type GithubSyncOperation =
  | "idle"
  | "checking"
  | "signing_in"
  | "polling"
  | "initializing"
  | "uploading"
  | "downloading"
  | "deleting";

type CredentialState =
  | { status: "unknown" | "checking"; message: null }
  | { status: "saved" | "not_saved"; message: null }
  | { status: "error"; message: string };

type CreateProfileInput = {
  name: string;
  server: string;
  reportedOs: string | null;
  username: string | null;
  authgroup: string | null;
  companyDomains: string[];
  localBypass: string[];
  vpnPassword: string | null;
};

type CreateProfileDraft = {
  name: string;
  server: string;
  reportedOs: string;
  username: string;
  authgroup: string;
  companyDomains: string;
  localBypass: string;
  vpnPassword: string;
  savePassword: boolean;
};

type CreateProfileField = keyof CreateProfileDraft;

type CreateProfileFieldErrors = Partial<Record<CreateProfileField, string>>;

type CreateProfileErrorMap = {
  formError: string | null;
  fieldErrors: CreateProfileFieldErrors;
};

type AuthSaveRequest = {
  profile: string;
  password: string;
};

type AppState = {
  daemon: DaemonStatus;
  diagnostics: DiagnosticsSnapshot | null;
  authPrompt: AuthPrompt | null;
  logs: LogEntry[];
  busy: boolean;
  error: string | null;
};

type Action =
  | { type: "busy"; busy: boolean }
  | { type: "error"; message: string | null }
  | { type: "status"; status: DaemonStatus }
  | { type: "diagnostics"; diagnostics: DiagnosticsSnapshot }
  | { type: "event"; event: IpcEvent }
  | { type: "log"; level: LogEntry["level"]; message: string };

const initialState: AppState = {
  daemon: { state: "idle", active_profile: null, interface: null },
  diagnostics: null,
  authPrompt: null,
  logs: [],
  busy: false,
  error: null,
};

const activityItems: ActivityItem[] = [
  { id: "profiles", label: "Profiles", icon: Shield },
  { id: "secrets", label: "Secrets", icon: KeyRound },
  { id: "diagnostics", label: "Diagnostics", icon: Network },
  { id: "logs", label: "Logs", icon: ScrollText },
];

const settingsActivityItem: ActivityItem = { id: "settings", label: "Settings", icon: SettingsIcon };

const viewCopy: Record<AppView, { title: string; eyebrow: string }> = {
  profiles: { title: "Profiles", eyebrow: "Connection control" },
  secrets: { title: "Secrets", eyebrow: "OS keyring" },
  diagnostics: { title: "Diagnostics", eyebrow: "Daemon and policy state" },
  logs: { title: "Logs", eyebrow: "Recent daemon events" },
  settings: { title: "Settings", eyebrow: "Preferences" },
};

const initialCreateProfileDraft: CreateProfileDraft = {
  name: "",
  server: "",
  reportedOs: "",
  username: "",
  authgroup: "",
  companyDomains: "",
  localBypass: "198.18.0.0/15",
  vpnPassword: "",
  savePassword: false,
};

const initialProfileDetailState: ProfileDetailState = {
  status: "unknown",
  detail: null,
  message: null,
};

const initialCredentialState: CredentialState = { status: "unknown", message: null };

const initialDaemonHandoffState: DaemonHandoffState = {
  status: "unknown",
  detail: null,
  message: null,
};

const initialGithubSyncState: GithubSyncState = {
  status: "unknown",
  detail: null,
  message: null,
  lastCheckedAt: null,
};

const initialGithubSyncHistoryState: GithubSyncHistoryState = {
  status: "unknown",
  entries: [],
  message: null,
};

function reducer(state: AppState, action: Action): AppState {
  switch (action.type) {
    case "busy":
      return { ...state, busy: action.busy };
    case "error":
      return {
        ...state,
        error: action.message,
        logs: action.message ? appendLog(state.logs, "error", action.message) : state.logs,
      };
    case "status":
      return { ...state, daemon: action.status };
    case "diagnostics":
      return { ...state, diagnostics: action.diagnostics };
    case "log":
      return { ...state, logs: appendLog(state.logs, action.level, action.message) };
    case "event":
      return applyIpcEvent(state, action.event);
  }
}

function applyIpcEvent(state: AppState, event: IpcEvent): AppState {
  switch (event.type) {
    case "progress":
      return { ...state, logs: appendLog(state.logs, "info", event.message) };
    case "auth_prompt":
      return {
        ...state,
        authPrompt: {
          form_id: event.form_id,
          title: event.title,
          message: event.message,
          error: event.error,
          fields: event.fields,
        },
        daemon: { ...state.daemon, state: "awaiting_auth" },
        logs: appendLog(state.logs, "info", "authentication requested"),
      };
    case "network_applied":
      return {
        ...state,
        logs: appendLog(
          state.logs,
          "info",
          `network applied: routes=${event.route_commands} dns=${event.dns_commands}`,
        ),
      };
    case "connected":
      return {
        ...state,
        authPrompt: null,
        daemon: {
          ...state.daemon,
          state: "connected",
          interface: event.interface,
        },
        logs: appendLog(state.logs, "info", `connected on ${event.interface}`),
      };
    case "disconnecting":
      return {
        ...state,
        daemon: { ...state.daemon, state: "disconnecting" },
        logs: appendLog(state.logs, "info", "disconnecting"),
      };
    case "disconnected":
      return {
        ...state,
        authPrompt: null,
        daemon: { state: "disconnected", active_profile: null, interface: null },
        logs: appendLog(state.logs, "info", `disconnected: ${event.reason}`),
      };
    case "auth_rejected":
      return { ...state, logs: appendLog(state.logs, "warn", event.message) };
    case "event_error":
      return {
        ...state,
        error: `${event.code}: ${event.message}`,
        logs: appendLog(state.logs, "error", `${event.code}: ${event.message}`),
      };
    case "stats":
      return state;
  }
}

function appendLog(logs: LogEntry[], level: LogEntry["level"], message: string) {
  return [...logs, { id: Date.now() + logs.length, level, message }].slice(-120);
}

export default function App() {
  const [state, dispatch] = useReducer(reducer, initialState);
  const [profile, setProfile] = useState("");
  const [profiles, setProfiles] = useState<ProfileItem[]>([]);
  const [profileDir, setProfileDir] = useState<string | null>(null);
  const [profileError, setProfileError] = useState<string | null>(null);
  const [activeView, setActiveView] = useState<AppView>("profiles");
  const [createProfileTabOpen, setCreateProfileTabOpen] = useState(false);
  const [createProfileDraft, setCreateProfileDraft] = useState<CreateProfileDraft>(
    initialCreateProfileDraft,
  );
  const [createProfileError, setCreateProfileError] = useState<string | null>(null);
  const [createProfileFieldErrors, setCreateProfileFieldErrors] =
    useState<CreateProfileFieldErrors>({});
  const [profileDetailState, setProfileDetailState] =
    useState<ProfileDetailState>(initialProfileDetailState);
  const [credentialState, setCredentialState] = useState<CredentialState>(initialCredentialState);
  const [daemonHandoffState, setDaemonHandoffState] =
    useState<DaemonHandoffState>(initialDaemonHandoffState);
  const [githubSyncState, setGithubSyncState] =
    useState<GithubSyncState>(initialGithubSyncState);
  const [githubSyncHistoryState, setGithubSyncHistoryState] =
    useState<GithubSyncHistoryState>(initialGithubSyncHistoryState);
  const [githubSyncFlow, setGithubSyncFlow] = useState<GithubDeviceFlowState | null>(null);
  const [githubSyncLoginOpen, setGithubSyncLoginOpen] = useState(false);
  const [githubSyncUploadOpen, setGithubSyncUploadOpen] = useState(false);
  const [githubSyncDownloadOpen, setGithubSyncDownloadOpen] = useState(false);
  const [githubSyncUploadError, setGithubSyncUploadError] = useState<string | null>(null);
  const [githubSyncDownloadError, setGithubSyncDownloadError] = useState<string | null>(null);
  const [githubSyncBusy, setGithubSyncBusy] = useState(false);
  const [githubSyncAutoRefreshStarted, setGithubSyncAutoRefreshStarted] = useState(false);
  const [githubSyncOperation, setGithubSyncOperation] =
    useState<GithubSyncOperation>("idle");

  useEffect(() => {
    if (!isTauriRuntime()) {
      dispatch({
        type: "error",
        message: "Tauri runtime is unavailable. Start the desktop app with npm run tauri dev.",
      });
      return;
    }

    const unlistenResponse = listen<IpcResponse>("daemon-response", (event) => {
      applyResponse(event.payload, dispatch);
    });
    const unlistenEvent = listen<IpcEvent>("daemon-event", (event) => {
      dispatch({ type: "event", event: event.payload });
    });

    void refreshAll();

    return () => {
      void unlistenResponse.then((fn) => fn());
      void unlistenEvent.then((fn) => fn());
    };
  }, []);

  const canConnect = useMemo(
    () => ["idle", "disconnected", "error"].includes(state.daemon.state),
    [state.daemon.state],
  );
  const canDisconnect = useMemo(
    () => ["awaiting_auth", "connecting", "connected", "disconnecting"].includes(state.daemon.state),
    [state.daemon.state],
  );
  const selectedProfileExists = useMemo(
    () => profiles.some((item) => item.name === profile),
    [profile, profiles],
  );

  useEffect(() => {
    if (state.daemon.active_profile) {
      setProfile(state.daemon.active_profile);
    }
  }, [state.daemon.active_profile]);

  useEffect(() => {
    if (
      activeView === "settings" &&
      !githubSyncAutoRefreshStarted &&
      !githubSyncBusy &&
      isTauriRuntime()
    ) {
      setGithubSyncAutoRefreshStarted(true);
      void refreshGithubSyncStatus();
    }
  }, [activeView, githubSyncAutoRefreshStarted, githubSyncBusy]);

  useEffect(() => {
    if (activeView !== "settings" || !githubSyncLoginOpen || !githubSyncFlow) {
      return;
    }
    if (["access_denied", "expired"].includes(githubSyncFlow.pollStatus)) {
      return;
    }

    const delayMs = Math.max(1, githubSyncFlow.nextIntervalSecs) * 1000;
    const timeout = window.setTimeout(() => {
      void pollGithubSyncLogin();
    }, delayMs);

    return () => window.clearTimeout(timeout);
  }, [activeView, githubSyncLoginOpen, githubSyncFlow]);

  useEffect(() => {
    if (selectedProfileExists && profile && !createProfileTabOpen) {
      void refreshProfileDetail(profile);
      void refreshCredentialStatus(profile);
    } else {
      setProfileDetailState(initialProfileDetailState);
      setCredentialState(initialCredentialState);
    }
  }, [profile, selectedProfileExists, createProfileTabOpen]);

  async function connect() {
    if (!selectedProfileExists) {
      dispatch({ type: "error", message: "select an available profile before connecting" });
      return;
    }

    dispatch({ type: "busy", busy: true });
    dispatch({ type: "error", message: null });
    dispatch({ type: "status", status: { state: "configuring", active_profile: profile, interface: null } });
    try {
      try {
        await invoke("daemon_connect", { profile });
      } catch (error) {
        const message = formatError(error);
        if (!isDaemonSocketError(message)) {
          throw error;
        }

        const handoff = await startDaemonFromDesktop();
        if (!handoff.socketReachable) {
          throw new Error(handoff.message ?? "daemon service did not expose its IPC socket");
        }
        await invoke("daemon_connect", { profile });
      }
    } catch (error) {
      dispatch({ type: "error", message: formatError(error) });
    } finally {
      dispatch({ type: "busy", busy: false });
    }
  }

  async function disconnect() {
    dispatch({ type: "busy", busy: true });
    try {
      await invoke("daemon_disconnect");
      await refreshStatus(dispatch);
    } catch (error) {
      dispatch({ type: "error", message: formatError(error) });
    } finally {
      dispatch({ type: "busy", busy: false });
    }
  }

  async function refreshAll() {
    dispatch({ type: "busy", busy: true });
    try {
      await refreshProfiles();
      try {
        await refreshStatus(dispatch);
        await refreshDiagnostics(dispatch);
        setDaemonHandoffState(initialDaemonHandoffState);
      } catch (error) {
        const message = formatError(error);
        if (!isDaemonSocketError(message)) {
          throw error;
        }
        dispatch({ type: "error", message });
        await refreshDaemonHandoffStatus();
      }
    } catch (error) {
      dispatch({ type: "error", message: formatError(error) });
    } finally {
      dispatch({ type: "busy", busy: false });
    }
  }

  async function refreshDaemonHandoffStatus() {
    setDaemonHandoffState((current) => ({ ...current, status: "checking", message: null }));
    try {
      const detail = await invoke<DaemonHandoffStatus>("daemon_handoff_status");
      setDaemonHandoffState({
        status: "ready",
        detail,
        message: detail.message,
      });
      return detail;
    } catch (error) {
      const message = formatError(error);
      setDaemonHandoffState((current) => ({ ...current, status: "error", message }));
      throw error;
    }
  }

  async function startDaemonFromDesktop() {
    setDaemonHandoffState((current) => ({ ...current, status: "starting", message: null }));
    try {
      const detail = await invoke<DaemonHandoffStatus>("daemon_handoff_start");
      setDaemonHandoffState({
        status: "ready",
        detail,
        message: detail.message,
      });
      dispatch({
        type: "log",
        level: detail.socketReachable ? "info" : "warn",
        message: detail.message ?? "daemon start requested",
      });
      if (detail.socketReachable) {
        dispatch({ type: "error", message: null });
        await refreshStatus(dispatch);
      }
      return detail;
    } catch (error) {
      const message = formatError(error);
      setDaemonHandoffState((current) => ({ ...current, status: "error", message }));
      dispatch({ type: "error", message });
      throw error;
    }
  }

  async function refreshActiveView() {
    if (activeView === "settings") {
      await refreshGithubSyncStatus();
      return;
    }

    await refreshAll();
  }

  async function refreshProfiles() {
    try {
      const list = await invoke<ProfileList>("profiles_list");
      setProfiles(list.profiles);
      setProfileDir(list.profile_dir);
      setProfileError(null);
      setProfile((current) => {
        if (state.daemon.active_profile) {
          return state.daemon.active_profile;
        }
        if (list.profiles.some((item) => item.name === current)) {
          return current;
        }
        return list.profiles[0]?.name ?? "";
      });
    } catch (error) {
      setProfileError(formatError(error));
      setProfiles([]);
      setProfileDir(null);
    }
  }

  async function createProfile(input: CreateProfileInput) {
    dispatch({ type: "busy", busy: true });
    dispatch({ type: "error", message: null });
    setCreateProfileError(null);
    setCreateProfileFieldErrors({});
    try {
      const created = await invoke<ProfileItem>("profile_create", {
        input: { ...input, vpnPassword: null },
      });
      if (input.vpnPassword) {
        try {
          await invoke("profile_save_vpn_password", {
            profile: created.name,
            password: input.vpnPassword,
          });
          setCredentialState({ status: "saved", message: null });
          dispatch({ type: "log", level: "info", message: "VPN password saved to keyring" });
        } catch (error) {
          dispatch({ type: "error", message: formatError(error) });
        }
      } else {
        setCredentialState({ status: "not_saved", message: null });
      }
      await refreshProfiles();
      setProfile(created.name);
      setCreateProfileTabOpen(false);
      setCreateProfileDraft(initialCreateProfileDraft);
      dispatch({ type: "log", level: "info", message: `profile created: ${created.name}` });
    } catch (error) {
      const message = formatError(error);
      const mapped = mapCreateProfileError(message);
      setCreateProfileError(mapped.formError);
      setCreateProfileFieldErrors(mapped.fieldErrors);
      dispatch({ type: "error", message });
    } finally {
      dispatch({ type: "busy", busy: false });
    }
  }

  async function duplicateProfile() {
    if (!profile || !selectedProfileExists || !canConnect) {
      return;
    }

    dispatch({ type: "busy", busy: true });
    dispatch({ type: "error", message: null });
    try {
      const created = await invoke<ProfileItem>("profile_duplicate", { profile });
      await refreshProfiles();
      setProfile(created.name);
      setCredentialState({ status: "not_saved", message: null });
      dispatch({ type: "log", level: "info", message: `profile duplicated: ${created.name}` });
    } catch (error) {
      dispatch({ type: "error", message: formatError(error) });
    } finally {
      dispatch({ type: "busy", busy: false });
    }
  }

  async function renameProfile(newName: string) {
    if (!profile || !selectedProfileExists || !canConnect) {
      return;
    }

    const previous = profile;
    dispatch({ type: "busy", busy: true });
    dispatch({ type: "error", message: null });
    try {
      const renamed = await invoke<ProfileItem>("profile_rename", {
        profile: previous,
        newName,
      });
      await refreshProfiles();
      setProfile(renamed.name);
      dispatch({
        type: "log",
        level: "info",
        message: `profile renamed: ${previous} -> ${renamed.name}`,
      });
    } catch (error) {
      dispatch({ type: "error", message: formatError(error) });
      throw error;
    } finally {
      dispatch({ type: "busy", busy: false });
    }
  }

  async function deleteProfile(syncTombstone = false) {
    if (!profile || !selectedProfileExists || !canConnect) {
      return;
    }

    const deleted = profile;
    dispatch({ type: "busy", busy: true });
    dispatch({ type: "error", message: null });
    try {
      await invoke("profile_delete", { profile: deleted });
      await refreshProfiles();
      setCredentialState(initialCredentialState);
      dispatch({ type: "log", level: "info", message: `profile deleted: ${deleted}` });
      if (syncTombstone) {
        setGithubSyncBusy(true);
        setGithubSyncOperation("deleting");
        const detail = await invoke<GithubSyncStatus>("github_sync_delete_profile", {
          profile: deleted,
        });
        setGithubSyncState({
          status: "ready",
          detail,
          message: null,
          lastCheckedAt: Date.now(),
        });
        await refreshGithubSyncHistory();
        dispatch({
          type: "log",
          level: "info",
          message: detail.message ?? `GitHub sync tombstone uploaded for ${deleted}`,
        });
      }
    } catch (error) {
      dispatch({ type: "error", message: formatError(error) });
    } finally {
      setGithubSyncBusy(false);
      setGithubSyncOperation("idle");
      dispatch({ type: "busy", busy: false });
    }
  }

  function openCreateProfileTab() {
    setActiveView("profiles");
    setCreateProfileError(null);
    setCreateProfileFieldErrors({});
    setCreateProfileTabOpen(true);
  }

  function closeCreateProfileTab() {
    setCreateProfileTabOpen(false);
    setCreateProfileDraft(initialCreateProfileDraft);
    setCreateProfileError(null);
    setCreateProfileFieldErrors({});
  }

  function selectProfileItem(nextProfile: string) {
    setProfile(nextProfile);
    if (createProfileTabOpen) {
      closeCreateProfileTab();
    }
  }

  async function refreshProfileDetail(targetProfile = profile) {
    if (!targetProfile) {
      setProfileDetailState(initialProfileDetailState);
      return;
    }

    setProfileDetailState({ status: "checking", detail: null, message: null });
    try {
      const detail = await invoke<ProfileDetail>("profile_detail", {
        profile: targetProfile,
      });
      setProfileDetailState({ status: "ready", detail, message: null });
    } catch (error) {
      setProfileDetailState({ status: "error", detail: null, message: formatError(error) });
    }
  }

  async function refreshCredentialStatus(targetProfile = profile) {
    if (!targetProfile) {
      setCredentialState(initialCredentialState);
      return;
    }

    setCredentialState({ status: "checking", message: null });
    try {
      const status = await invoke<VpnPasswordStatus>("profile_vpn_password_status", {
        profile: targetProfile,
      });
      setCredentialState({ status: status.saved ? "saved" : "not_saved", message: null });
    } catch (error) {
      setCredentialState({ status: "error", message: formatError(error) });
    }
  }

  async function forgetVpnPassword(targetProfile = profile) {
    if (!targetProfile) {
      return;
    }

    dispatch({ type: "busy", busy: true });
    dispatch({ type: "error", message: null });
    try {
      await invoke<VpnPasswordStatus>("profile_forget_vpn_password", {
        profile: targetProfile,
      });
      setCredentialState({ status: "not_saved", message: null });
      dispatch({ type: "log", level: "info", message: "VPN password removed from keyring" });
    } catch (error) {
      const message = formatError(error);
      setCredentialState({ status: "error", message });
      dispatch({ type: "error", message });
    } finally {
      dispatch({ type: "busy", busy: false });
    }
  }

  async function refreshGithubSyncStatus() {
    setGithubSyncBusy(true);
    setGithubSyncOperation("checking");
    setGithubSyncState((current) => ({ ...current, status: "checking", message: null }));
    try {
      const detail = await invoke<GithubSyncStatus>("github_sync_status");
      setGithubSyncState({
        status: "ready",
        detail,
        message: null,
        lastCheckedAt: Date.now(),
      });
      await refreshGithubSyncHistory();
    } catch (error) {
      setGithubSyncState((current) => ({
        ...current,
        status: "error",
        message: formatError(error),
      }));
    } finally {
      setGithubSyncBusy(false);
      setGithubSyncOperation("idle");
    }
  }

  async function refreshGithubSyncHistory() {
    setGithubSyncHistoryState((current) => ({ ...current, status: "checking", message: null }));
    try {
      const history = await invoke<GithubSyncHistory>("github_sync_history");
      setGithubSyncHistoryState({
        status: "ready",
        entries: history.entries,
        message: null,
      });
    } catch (error) {
      setGithubSyncHistoryState((current) => ({
        ...current,
        status: "error",
        message: formatError(error),
      }));
    }
  }

  async function startGithubSyncLogin() {
    setGithubSyncBusy(true);
    setGithubSyncOperation("signing_in");
    setGithubSyncFlow(null);
    setGithubSyncLoginOpen(true);
    try {
      const start = await invoke<GithubDeviceFlowStartResult>("github_sync_device_flow_start");
      setGithubSyncFlow({
        ...start,
        expiresAtMs: Date.now() + start.expiresInSecs * 1000,
        nextIntervalSecs: start.intervalSecs,
        pollStatus: "waiting",
      });
      setGithubSyncState((current) => ({ ...current, message: null }));
    } catch (error) {
      setGithubSyncState((current) => ({
        ...current,
        status: "error",
        message: formatError(error),
      }));
    } finally {
      setGithubSyncBusy(false);
      setGithubSyncOperation("idle");
    }
  }

  async function pollGithubSyncLogin() {
    if (!githubSyncFlow || Date.now() >= githubSyncFlow.expiresAtMs) {
      setGithubSyncFlow((current) =>
        current ? { ...current, pollStatus: "expired" } : current,
      );
      return;
    }

    setGithubSyncBusy(true);
    setGithubSyncOperation("polling");
    try {
      const result = await invoke<GithubDeviceFlowPollResult>("github_sync_device_flow_poll", {
        deviceCode: githubSyncFlow.deviceCode,
        intervalSecs: githubSyncFlow.nextIntervalSecs,
      });
      if (result.status === "authorized") {
        setGithubSyncFlow(null);
        setGithubSyncLoginOpen(false);
        dispatch({ type: "log", level: "info", message: "GitHub sync authorized" });
        await refreshGithubSyncStatus();
        return;
      }

      setGithubSyncFlow((current) =>
        current
          ? {
              ...current,
              nextIntervalSecs: result.nextIntervalSecs,
              pollStatus: result.status,
            }
          : current,
      );
    } catch (error) {
      setGithubSyncState((current) => ({
        ...current,
        status: "error",
        message: formatError(error),
      }));
    } finally {
      setGithubSyncBusy(false);
      setGithubSyncOperation("idle");
    }
  }

  function cancelGithubSyncLogin() {
    setGithubSyncFlow(null);
    setGithubSyncLoginOpen(false);
    setGithubSyncOperation("idle");
  }

  async function initGithubSyncManifest() {
    setGithubSyncBusy(true);
    setGithubSyncOperation("initializing");
    try {
      const detail = await invoke<GithubSyncStatus>("github_sync_init_manifest");
      setGithubSyncState({
        status: "ready",
        detail,
        message: null,
        lastCheckedAt: Date.now(),
      });
      await refreshGithubSyncHistory();
      dispatch({ type: "log", level: "info", message: "GitHub sync manifest initialized" });
    } catch (error) {
      setGithubSyncState((current) => ({
        ...current,
        status: "error",
        message: formatError(error),
      }));
    } finally {
      setGithubSyncBusy(false);
      setGithubSyncOperation("idle");
    }
  }

  function openGithubSyncUploadDialog() {
    setGithubSyncUploadError(null);
    setGithubSyncUploadOpen(true);
  }

  function cancelGithubSyncUpload() {
    if (githubSyncBusy) {
      return;
    }
    setGithubSyncUploadError(null);
    setGithubSyncUploadOpen(false);
  }

  function openGithubSyncDownloadDialog() {
    setGithubSyncDownloadError(null);
    setGithubSyncDownloadOpen(true);
  }

  function cancelGithubSyncDownload() {
    if (githubSyncBusy) {
      return;
    }
    setGithubSyncDownloadError(null);
    setGithubSyncDownloadOpen(false);
  }

  async function uploadGithubSyncProfiles() {
    setGithubSyncBusy(true);
    setGithubSyncOperation("uploading");
    setGithubSyncUploadError(null);
    try {
      const detail = await invoke<GithubSyncStatus>("github_sync_upload_profiles");
      setGithubSyncUploadOpen(false);
      setGithubSyncState({
        status: "ready",
        detail,
        message: null,
        lastCheckedAt: Date.now(),
      });
      await refreshGithubSyncHistory();
      dispatch({ type: "log", level: "info", message: detail.message ?? "GitHub profiles uploaded" });
    } catch (error) {
      const message = formatError(error);
      setGithubSyncUploadError(message);
      setGithubSyncState((current) => ({
        ...current,
        status: "error",
        message,
      }));
    } finally {
      setGithubSyncBusy(false);
      setGithubSyncOperation("idle");
    }
  }

  async function downloadGithubSyncProfiles() {
    setGithubSyncBusy(true);
    setGithubSyncOperation("downloading");
    setGithubSyncDownloadError(null);
    try {
      const detail = await invoke<GithubSyncStatus>("github_sync_download_profiles");
      setGithubSyncDownloadOpen(false);
      setGithubSyncState({
        status: "ready",
        detail,
        message: null,
        lastCheckedAt: Date.now(),
      });
      await refreshProfiles();
      await refreshGithubSyncHistory();
      dispatch({ type: "log", level: "info", message: detail.message ?? "GitHub profiles restored" });
    } catch (error) {
      const message = formatError(error);
      setGithubSyncDownloadError(message);
      setGithubSyncState((current) => ({
        ...current,
        status: "error",
        message,
      }));
    } finally {
      setGithubSyncBusy(false);
      setGithubSyncOperation("idle");
    }
  }

  async function submitAuth(fields: AuthSubmittedField[], saveRequest: AuthSaveRequest | null) {
    if (!state.authPrompt) {
      return;
    }

    dispatch({ type: "busy", busy: true });
    try {
      if (saveRequest) {
        try {
          await invoke("profile_save_vpn_password", {
            profile: saveRequest.profile,
            password: saveRequest.password,
          });
          if (saveRequest.profile === profile) {
            setCredentialState({ status: "saved", message: null });
          }
          dispatch({ type: "log", level: "info", message: "VPN password saved to keyring" });
        } catch (error) {
          dispatch({ type: "error", message: formatError(error) });
        }
      }
      await invoke("daemon_submit_auth", {
        formId: state.authPrompt.form_id,
        fields,
      });
      dispatch({ type: "event", event: { type: "progress", level: 0, message: "auth response submitted" } });
    } catch (error) {
      dispatch({ type: "error", message: formatError(error) });
    } finally {
      dispatch({ type: "busy", busy: false });
    }
  }

  return (
    <main className="flex h-screen flex-col overflow-hidden bg-background">
      <AppTitleBar />
      <div className="flex min-h-0 flex-1 overflow-hidden">
        <ActivityBar activeView={activeView} state={state.daemon.state} onSelect={setActiveView} />
        <WorkbenchSidebar
          activeView={activeView}
          profile={profile}
          profiles={profiles}
          profileDir={profileDir}
          profileError={profileError}
          selectProfile={selectProfileItem}
          daemon={state.daemon}
          canSelectProfile={canConnect}
          createProfileTabOpen={createProfileTabOpen}
          onCreateProfile={openCreateProfileTab}
        />
        <section className="flex min-w-0 flex-1 flex-col overflow-hidden bg-background">
          <WorkbenchHeader
            activeView={activeView}
            daemon={state.daemon}
            busy={state.busy}
            refreshBusy={activeView === "settings" ? githubSyncBusy : state.busy}
            canDisconnect={canDisconnect}
            onRefresh={refreshActiveView}
            onDisconnect={disconnect}
          />
          <div className="min-h-0 flex-1 overflow-auto px-4 py-4 sm:px-6">
            <WorkbenchView
              activeView={activeView}
              profile={profile}
              profiles={profiles}
              profileDir={profileDir}
              profileError={profileError}
              selectProfile={selectProfileItem}
              state={state}
              canConnect={canConnect}
              selectedProfileExists={selectedProfileExists}
              canDisconnect={canDisconnect}
              profileDetailState={profileDetailState}
              credentialState={credentialState}
              daemonHandoffState={daemonHandoffState}
              createProfileTabOpen={createProfileTabOpen}
              createProfileDraft={createProfileDraft}
              createProfileError={createProfileError}
              createProfileFieldErrors={createProfileFieldErrors}
              githubSyncState={githubSyncState}
              githubSyncHistoryState={githubSyncHistoryState}
              githubSyncBusy={githubSyncBusy}
              githubSyncOperation={githubSyncOperation}
              setCreateProfileDraft={setCreateProfileDraft}
              setCreateProfileFieldErrors={setCreateProfileFieldErrors}
              onCloseCreateProfile={closeCreateProfileTab}
              onForgetCredential={() => forgetVpnPassword(profile)}
              onStartGithubSyncLogin={startGithubSyncLogin}
              onInitGithubSyncManifest={initGithubSyncManifest}
              onUploadGithubSyncProfiles={openGithubSyncUploadDialog}
              onDownloadGithubSyncProfiles={openGithubSyncDownloadDialog}
              onDuplicateProfile={duplicateProfile}
              onRenameProfile={renameProfile}
              onDeleteProfile={deleteProfile}
              onStartDaemon={startDaemonFromDesktop}
              connect={connect}
              disconnect={disconnect}
              createProfile={createProfile}
            />
          </div>
        </section>
      </div>

      <AuthDialog
        prompt={state.authPrompt}
        profile={state.daemon.active_profile ?? profile}
        busy={state.busy}
        onSubmit={submitAuth}
        onCancel={disconnect}
      />
      <GithubSyncLoginDialog
        open={githubSyncLoginOpen}
        flow={githubSyncFlow}
        busy={githubSyncBusy}
        operation={githubSyncOperation}
        onPoll={pollGithubSyncLogin}
        onCancel={cancelGithubSyncLogin}
      />
      <GithubSyncUploadDialog
        open={githubSyncUploadOpen}
        busy={githubSyncBusy}
        operation={githubSyncOperation}
        error={githubSyncUploadError}
        onUpload={uploadGithubSyncProfiles}
        onCancel={cancelGithubSyncUpload}
      />
      <GithubSyncDownloadDialog
        open={githubSyncDownloadOpen}
        busy={githubSyncBusy}
        operation={githubSyncOperation}
        error={githubSyncDownloadError}
        onDownload={downloadGithubSyncProfiles}
        onCancel={cancelGithubSyncDownload}
      />
    </main>
  );
}

function ActivityBar({
  activeView,
  state,
  onSelect,
}: {
  activeView: AppView;
  state: DaemonState;
  onSelect: (view: AppView) => void;
}) {
  return (
    <nav className="flex w-14 shrink-0 flex-col items-center bg-[#2c3e50] py-2 text-[#bdc3c7]">
      <div className="mb-2 flex h-11 w-11 items-center justify-center">
        <img src={appIconUrl} alt="" className={`h-7 w-7 object-contain ${appMarkClass(state)}`} />
      </div>
      <div className="flex w-full flex-1 flex-col items-center gap-1">
        {activityItems.map((item) => (
          <ActivityBarButton
            key={item.id}
            item={item}
            active={activeView === item.id}
            onSelect={onSelect}
          />
        ))}
      </div>
      <div className="flex w-full flex-col items-center gap-1">
        <ActivityBarButton
          item={settingsActivityItem}
          active={activeView === settingsActivityItem.id}
          onSelect={onSelect}
        />
      </div>
    </nav>
  );
}

function ActivityBarButton({
  item,
  active,
  onSelect,
}: {
  item: ActivityItem;
  active: boolean;
  onSelect: (view: AppView) => void;
}) {
  const Icon = item.icon;

  return (
    <button
      type="button"
      aria-label={item.label}
      title={item.label}
      onClick={() => onSelect(item.id)}
      className={`relative flex h-12 w-full items-center justify-center transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-inset ${
        active ? "bg-[#34495e] text-white" : "hover:bg-[#34495e] hover:text-white"
      }`}
    >
      {active ? <span className="absolute left-0 h-8 w-1 bg-primary" /> : null}
      <Icon className="h-5 w-5" />
    </button>
  );
}

function WorkbenchSidebar({
  activeView,
  profile,
  profiles,
  profileDir,
  profileError,
  selectProfile,
  daemon,
  canSelectProfile,
  createProfileTabOpen,
  onCreateProfile,
}: {
  activeView: AppView;
  profile: string;
  profiles: ProfileItem[];
  profileDir: string | null;
  profileError: string | null;
  selectProfile: (profile: string) => void;
  daemon: DaemonStatus;
  canSelectProfile: boolean;
  createProfileTabOpen: boolean;
  onCreateProfile: () => void;
}) {
  return (
    <aside className="hidden w-72 shrink-0 flex-col border-r-4 border-[#2c3e50] bg-[#34495e] text-[#ecf0f1] md:flex">
      <div className="min-h-0 flex-1 overflow-auto px-3 py-3">
        {activeView === "profiles" ? (
          <div className="space-y-4">
            <ProfileListPanel
              profiles={profiles}
              selectedProfile={profile}
              profileDir={profileDir}
              profileError={profileError}
              canSelectProfile={canSelectProfile}
              createProfileTabOpen={createProfileTabOpen}
              activeProfile={daemon.active_profile}
              onSelect={selectProfile}
              onCreateProfile={onCreateProfile}
            />
            {!canSelectProfile ? (
              <div className="rounded-md bg-[#2c3e50] p-3 text-sm font-medium text-[#bdc3c7]">
                Disconnect before switching profiles.
              </div>
            ) : null}
          </div>
        ) : null}

        {activeView === "secrets" ? (
          <div className="space-y-3 text-sm">
            <SidebarRow icon={KeyRound} label="VPN password" value="OS keyring" />
            <SidebarRow icon={Activity} label="OTP" value="prompt only" />
            <SidebarRow icon={FileText} label="Profile files" value="no secrets" />
          </div>
        ) : null}

        {activeView === "diagnostics" ? (
          <div className="space-y-3 text-sm">
            <SidebarRow icon={CircleDot} label="Daemon" value={daemon.state} />
            <SidebarRow icon={Shield} label="Profile" value={daemon.active_profile ?? profile} />
            <SidebarRow icon={Network} label="Interface" value={daemon.interface ?? "-"} />
          </div>
        ) : null}

        {activeView === "logs" ? (
          <div className="space-y-2">
            <button
              type="button"
              className="flex w-full items-center gap-3 rounded-md bg-[#2c3e50] px-3 py-3 text-left text-sm text-white"
            >
              <ScrollText className="h-4 w-4 text-primary" />
              <span className="min-w-0 flex-1 truncate">Daemon events</span>
            </button>
          </div>
        ) : null}

        {activeView === "settings" ? (
          <div className="space-y-2">
            <div className="px-1 text-[11px] font-bold uppercase tracking-wide text-[#bdc3c7]">
              Settings
            </div>
            <button
              type="button"
              className="flex w-full items-center gap-3 rounded-md bg-[#2c3e50] px-3 py-3 text-left text-sm text-white"
            >
              <Cloud className="h-4 w-4 text-primary" />
              <span className="min-w-0 flex-1 truncate font-semibold">Cloud Sync</span>
            </button>
          </div>
        ) : null}
      </div>
    </aside>
  );
}

function ProfileListPanel({
  profiles,
  selectedProfile,
  profileDir,
  profileError,
  canSelectProfile,
  createProfileTabOpen,
  activeProfile,
  onSelect,
  onCreateProfile,
}: {
  profiles: ProfileItem[];
  selectedProfile: string;
  profileDir: string | null;
  profileError: string | null;
  canSelectProfile: boolean;
  createProfileTabOpen: boolean;
  activeProfile: string | null;
  onSelect: (profile: string) => void;
  onCreateProfile: () => void;
}) {
  if (profileError) {
    return (
      <div className="rounded-md bg-destructive p-3 text-sm font-semibold text-white">
        {profileError}
      </div>
    );
  }

  if (profiles.length === 0) {
    return (
      <div className="space-y-3">
        <div className="rounded-md bg-[#2c3e50] p-3 text-sm text-[#ecf0f1]">
          <div className="font-semibold text-white">No profiles found</div>
          <div className="mt-1 break-words text-[#bdc3c7]">{profileDir ?? "profile directory unavailable"}</div>
        </div>
        <NewProfileListItem
          active={createProfileTabOpen}
          disabled={!canSelectProfile}
          onClick={onCreateProfile}
        />
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <div className="px-1 text-[11px] font-bold uppercase tracking-wide text-[#bdc3c7]">
        Profiles
      </div>
      {profiles.map((item) => {
        const selected = selectedProfile === item.name;
        const active = activeProfile === item.name;
        return (
          <button
            key={item.name}
            type="button"
            disabled={!canSelectProfile}
            onClick={() => onSelect(item.name)}
            className={`flex w-full items-center gap-3 rounded-md px-3 py-3 text-left text-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary ${
              selected ? "bg-[#2c3e50] text-white" : "text-[#ecf0f1] hover:bg-[#2c3e50]"
            } disabled:cursor-not-allowed disabled:opacity-80`}
          >
            <Shield className="h-4 w-4 shrink-0 text-primary" />
            <span className="min-w-0 flex-1 truncate font-semibold">{item.name}</span>
            {active ? <Badge variant="default">active</Badge> : null}
          </button>
        );
      })}
      <NewProfileListItem
        active={createProfileTabOpen}
        disabled={!canSelectProfile}
        onClick={onCreateProfile}
      />
    </div>
  );
}

function NewProfileListItem({
  active,
  disabled,
  onClick,
}: {
  active: boolean;
  disabled: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      className={`flex w-full items-center gap-3 rounded-md px-3 py-3 text-left text-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary ${
        active ? "bg-[#2c3e50] text-white" : "text-[#ecf0f1] hover:bg-[#2c3e50]"
      } disabled:cursor-not-allowed disabled:opacity-80`}
    >
      <Plus className="h-4 w-4 shrink-0 text-primary" />
      <span className="min-w-0 flex-1 truncate font-semibold">New Profile</span>
      {active ? <Badge variant="outline">draft</Badge> : null}
    </button>
  );
}

function SidebarRow({
  icon: Icon,
  label,
  value,
}: {
  icon: LucideIcon;
  label: string;
  value: string;
}) {
  return (
    <div className="flex items-center gap-3 rounded-md bg-[#2c3e50] px-3 py-3">
      <Icon className="h-4 w-4 shrink-0 text-primary" />
      <div className="min-w-0 flex-1">
        <div className="truncate text-[#bdc3c7]">{label}</div>
        <div className="truncate font-semibold text-white">{value}</div>
      </div>
    </div>
  );
}

function WorkbenchHeader({
  activeView,
  daemon,
  busy,
  refreshBusy,
  canDisconnect,
  onRefresh,
  onDisconnect,
}: {
  activeView: AppView;
  daemon: DaemonStatus;
  busy: boolean;
  refreshBusy: boolean;
  canDisconnect: boolean;
  onRefresh: () => Promise<void>;
  onDisconnect: () => Promise<void>;
}) {
  return (
    <header className="flex h-[68px] shrink-0 items-center justify-between border-b-4 border-primary bg-white px-4 sm:px-6">
      <div className="min-w-0">
        <div className="text-[11px] font-bold uppercase tracking-wide text-muted-foreground">
          oc-oxide
        </div>
        <h1 className="truncate text-lg font-semibold leading-tight text-foreground">
          {viewCopy[activeView].title}
        </h1>
      </div>
      <HeaderControls
        state={daemon.state}
        busy={busy}
        refreshBusy={refreshBusy}
        canDisconnect={canDisconnect}
        onRefresh={onRefresh}
        onDisconnect={onDisconnect}
      />
    </header>
  );
}

function HeaderControls({
  state,
  busy,
  refreshBusy,
  canDisconnect,
  onRefresh,
  onDisconnect,
}: {
  state: DaemonState;
  busy: boolean;
  refreshBusy: boolean;
  canDisconnect: boolean;
  onRefresh: () => Promise<void>;
  onDisconnect: () => Promise<void>;
}) {
  return (
    <div className="flex shrink-0 items-center overflow-hidden rounded-md bg-[#ecf0f1]">
      <HeaderStatusChip
        state={state}
        canDisconnect={canDisconnect}
        disabled={busy}
        onDisconnect={onDisconnect}
      />
      <button
        type="button"
        disabled={refreshBusy}
        aria-label="Refresh status"
        title="Refresh"
        onClick={onRefresh}
        className="flex h-8 w-9 items-center justify-center border-l border-white text-[#7f8c8d] transition-colors hover:bg-[#d5dbdb] hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-inset disabled:cursor-not-allowed disabled:opacity-70"
      >
        <RefreshCw className={spinnerClass(refreshBusy)} />
      </button>
    </div>
  );
}

function HeaderStatusChip({
  state,
  canDisconnect,
  disabled,
  onDisconnect,
}: {
  state: DaemonState;
  canDisconnect: boolean;
  disabled: boolean;
  onDisconnect: () => Promise<void>;
}) {
  const content = (
    <>
      <span className={`h-2.5 w-2.5 rounded-full ${statusDotClass(state)}`} />
      <span>{state}</span>
    </>
  );

  if (!canDisconnect) {
    return <div className="flex h-8 items-center gap-2 px-3 text-sm font-semibold text-foreground">{content}</div>;
  }

  return (
    <button
      type="button"
      disabled={disabled}
      aria-label="Disconnect VPN"
      title="Disconnect"
      onClick={() => void onDisconnect()}
      className="flex h-8 items-center gap-2 px-3 text-sm font-semibold text-foreground transition-colors hover:bg-destructive hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-destructive focus-visible:ring-inset disabled:cursor-not-allowed disabled:opacity-70"
    >
      {content}
      <Power className="h-3.5 w-3.5" />
    </button>
  );
}

function WorkbenchView({
  activeView,
  profile,
  profiles,
  profileDir,
  profileError,
  selectProfile,
  state,
  canConnect,
  selectedProfileExists,
  canDisconnect,
  profileDetailState,
  credentialState,
  daemonHandoffState,
  createProfileTabOpen,
  createProfileDraft,
  createProfileError,
  createProfileFieldErrors,
  githubSyncState,
  githubSyncHistoryState,
  githubSyncBusy,
  githubSyncOperation,
  setCreateProfileDraft,
  setCreateProfileFieldErrors,
  onCloseCreateProfile,
  onForgetCredential,
  onStartGithubSyncLogin,
  onInitGithubSyncManifest,
  onUploadGithubSyncProfiles,
  onDownloadGithubSyncProfiles,
  onDuplicateProfile,
  onRenameProfile,
  onDeleteProfile,
  onStartDaemon,
  connect,
  disconnect,
  createProfile,
}: {
  activeView: AppView;
  profile: string;
  profiles: ProfileItem[];
  profileDir: string | null;
  profileError: string | null;
  selectProfile: (profile: string) => void;
  state: AppState;
  canConnect: boolean;
  selectedProfileExists: boolean;
  canDisconnect: boolean;
  profileDetailState: ProfileDetailState;
  credentialState: CredentialState;
  daemonHandoffState: DaemonHandoffState;
  createProfileTabOpen: boolean;
  createProfileDraft: CreateProfileDraft;
  createProfileError: string | null;
  createProfileFieldErrors: CreateProfileFieldErrors;
  githubSyncState: GithubSyncState;
  githubSyncHistoryState: GithubSyncHistoryState;
  githubSyncBusy: boolean;
  githubSyncOperation: GithubSyncOperation;
  setCreateProfileDraft: React.Dispatch<React.SetStateAction<CreateProfileDraft>>;
  setCreateProfileFieldErrors: React.Dispatch<React.SetStateAction<CreateProfileFieldErrors>>;
  onCloseCreateProfile: () => void;
  onForgetCredential: () => void;
  onStartGithubSyncLogin: () => Promise<void>;
  onInitGithubSyncManifest: () => Promise<void>;
  onUploadGithubSyncProfiles: () => void;
  onDownloadGithubSyncProfiles: () => void;
  onDuplicateProfile: () => Promise<void>;
  onRenameProfile: (newName: string) => Promise<void>;
  onDeleteProfile: (syncTombstone?: boolean) => Promise<void>;
  onStartDaemon: () => Promise<DaemonHandoffStatus>;
  connect: () => Promise<void>;
  disconnect: () => Promise<void>;
  createProfile: (input: CreateProfileInput) => Promise<void>;
}) {
  if (activeView === "secrets") {
    return <SecretsView profile={profile} />;
  }

  if (activeView === "diagnostics") {
    return <DiagnosticsView diagnostics={state.diagnostics} error={state.error} />;
  }

  if (activeView === "settings") {
    return (
      <SettingsView
        profile={profile}
        profileDir={profileDir}
        githubSyncState={githubSyncState}
        githubSyncHistoryState={githubSyncHistoryState}
        githubSyncBusy={githubSyncBusy}
        githubSyncOperation={githubSyncOperation}
        onStartGithubSyncLogin={onStartGithubSyncLogin}
        onInitGithubSyncManifest={onInitGithubSyncManifest}
        onUploadGithubSyncProfiles={onUploadGithubSyncProfiles}
        onDownloadGithubSyncProfiles={onDownloadGithubSyncProfiles}
      />
    );
  }

  if (activeView === "logs") {
    return <LogsView logs={state.logs} />;
  }

  return (
    <ProfilesView
      profile={profile}
      profiles={profiles}
      profileDir={profileDir}
      profileError={profileError}
      selectProfile={selectProfile}
      state={state}
      canConnect={canConnect}
      selectedProfileExists={selectedProfileExists}
      canDisconnect={canDisconnect}
      profileDetailState={profileDetailState}
      credentialState={credentialState}
      daemonHandoffState={daemonHandoffState}
      createProfileTabOpen={createProfileTabOpen}
      createProfileDraft={createProfileDraft}
      createProfileError={createProfileError}
      createProfileFieldErrors={createProfileFieldErrors}
      setCreateProfileDraft={setCreateProfileDraft}
      setCreateProfileFieldErrors={setCreateProfileFieldErrors}
      onCloseCreateProfile={onCloseCreateProfile}
      onForgetCredential={onForgetCredential}
      onDuplicateProfile={onDuplicateProfile}
      onRenameProfile={onRenameProfile}
      onDeleteProfile={onDeleteProfile}
      onStartDaemon={onStartDaemon}
      connect={connect}
      disconnect={disconnect}
      createProfile={createProfile}
    />
  );
}

function ProfilesView({
  profile,
  profiles,
  profileDir,
  profileError,
  selectProfile,
  state,
  canConnect,
  selectedProfileExists,
  canDisconnect,
  profileDetailState,
  credentialState,
  daemonHandoffState,
  createProfileTabOpen,
  createProfileDraft,
  createProfileError,
  createProfileFieldErrors,
  setCreateProfileDraft,
  setCreateProfileFieldErrors,
  onCloseCreateProfile,
  onForgetCredential,
  onDuplicateProfile,
  onRenameProfile,
  onDeleteProfile,
  onStartDaemon,
  connect,
  disconnect,
  createProfile,
}: {
  profile: string;
  profiles: ProfileItem[];
  profileDir: string | null;
  profileError: string | null;
  selectProfile: (profile: string) => void;
  state: AppState;
  canConnect: boolean;
  selectedProfileExists: boolean;
  canDisconnect: boolean;
  profileDetailState: ProfileDetailState;
  credentialState: CredentialState;
  daemonHandoffState: DaemonHandoffState;
  createProfileTabOpen: boolean;
  createProfileDraft: CreateProfileDraft;
  createProfileError: string | null;
  createProfileFieldErrors: CreateProfileFieldErrors;
  setCreateProfileDraft: React.Dispatch<React.SetStateAction<CreateProfileDraft>>;
  setCreateProfileFieldErrors: React.Dispatch<React.SetStateAction<CreateProfileFieldErrors>>;
  onCloseCreateProfile: () => void;
  onForgetCredential: () => void;
  onDuplicateProfile: () => Promise<void>;
  onRenameProfile: (newName: string) => Promise<void>;
  onDeleteProfile: (syncTombstone?: boolean) => Promise<void>;
  onStartDaemon: () => Promise<DaemonHandoffStatus>;
  connect: () => Promise<void>;
  disconnect: () => Promise<void>;
  createProfile: (input: CreateProfileInput) => Promise<void>;
}) {
  return (
    <section className="workbench-surface overflow-hidden rounded-md bg-card">
      <div className="p-4">
        {createProfileTabOpen ? (
          <CreateProfileForm
            draft={createProfileDraft}
            error={createProfileError}
            fieldErrors={createProfileFieldErrors}
            setDraft={setCreateProfileDraft}
            setFieldErrors={setCreateProfileFieldErrors}
            busy={state.busy}
            onCancel={onCloseCreateProfile}
            onCreate={createProfile}
          />
        ) : (
          <ProfileConnectionPanel
            profile={profile}
            profiles={profiles}
            profileDir={profileDir}
            profileError={profileError}
            selectProfile={selectProfile}
            state={state}
            canConnect={canConnect}
            selectedProfileExists={selectedProfileExists}
            canDisconnect={canDisconnect}
            profileDetailState={profileDetailState}
            credentialState={credentialState}
            daemonHandoffState={daemonHandoffState}
            onForgetCredential={onForgetCredential}
            onDuplicateProfile={onDuplicateProfile}
            onRenameProfile={onRenameProfile}
            onDeleteProfile={onDeleteProfile}
            onStartDaemon={onStartDaemon}
            connect={connect}
            disconnect={disconnect}
          />
        )}
      </div>
    </section>
  );
}

function ProfileConnectionPanel({
  profile,
  profiles,
  profileDir,
  profileError,
  selectProfile,
  state,
  canConnect,
  selectedProfileExists,
  canDisconnect,
  profileDetailState,
  credentialState,
  daemonHandoffState,
  onForgetCredential,
  onDuplicateProfile,
  onRenameProfile,
  onDeleteProfile,
  onStartDaemon,
  connect,
  disconnect,
}: {
  profile: string;
  profiles: ProfileItem[];
  profileDir: string | null;
  profileError: string | null;
  selectProfile: (profile: string) => void;
  state: AppState;
  canConnect: boolean;
  selectedProfileExists: boolean;
  canDisconnect: boolean;
  profileDetailState: ProfileDetailState;
  credentialState: CredentialState;
  daemonHandoffState: DaemonHandoffState;
  onForgetCredential: () => void;
  onDuplicateProfile: () => Promise<void>;
  onRenameProfile: (newName: string) => Promise<void>;
  onDeleteProfile: (syncTombstone?: boolean) => Promise<void>;
  onStartDaemon: () => Promise<DaemonHandoffStatus>;
  connect: () => Promise<void>;
  disconnect: () => Promise<void>;
}) {
  return (
    <div className="responsive-two-panel grid gap-4">
      <section className="rounded-md bg-card p-4">
        <div className="mb-4 flex items-center justify-between gap-3">
          <h2 className="text-sm font-semibold text-foreground">Connection</h2>
          {state.daemon.interface ? (
            <Badge variant="outline">{state.daemon.interface}</Badge>
          ) : (
            <Badge variant="outline">no interface</Badge>
          )}
        </div>
        <div className="space-y-4">
          <div className="space-y-2 md:hidden">
            <Label htmlFor="profile">Profile</Label>
            <select
              id="profile"
              value={profile}
              onChange={(event) => selectProfile(event.target.value)}
              disabled={!canConnect}
              className="flex h-[42px] w-full rounded-md border-2 border-input bg-white px-3 py-2 text-[15px] text-foreground shadow-none transition-colors focus-visible:border-primary focus-visible:outline-none focus-visible:ring-0 disabled:cursor-not-allowed disabled:bg-muted"
            >
              {profiles.length === 0 ? <option value="">No profiles found</option> : null}
              {profiles.map((item) => (
                <option key={item.name} value={item.name}>
                  {item.name}
                </option>
              ))}
            </select>
          </div>
          <ProfileSummaryCard
            profile={profile}
            detailState={profileDetailState}
            actionsDisabled={!profile || !selectedProfileExists || !canConnect}
            busy={state.busy}
            onDuplicate={onDuplicateProfile}
            onRename={onRenameProfile}
            onDelete={onDeleteProfile}
          />
          <DaemonHandoffPanel
            state={daemonHandoffState}
            busy={state.busy}
            onStart={onStartDaemon}
          />
          {profileError ? (
            <div className="rounded-md bg-destructive p-3 text-sm font-semibold text-white">
              {profileError}
            </div>
          ) : null}
          {!profileError && profiles.length === 0 ? (
            <div className="rounded-md bg-muted p-3 text-sm">
              <div className="font-semibold">No profiles found</div>
              <div className="mt-1 break-words text-muted-foreground">
                {profileDir ?? "profile directory unavailable"}
              </div>
            </div>
          ) : null}
          <div className="grid gap-2 sm:grid-cols-2">
            <Button
              onClick={connect}
              disabled={!canConnect || state.busy || !selectedProfileExists}
            >
              <PlugZap className="h-4 w-4" />
              Connect
            </Button>
            <Button
              variant={canDisconnect ? "destructive" : "outline"}
              onClick={disconnect}
              disabled={!canDisconnect || state.busy}
            >
              <Power className="h-4 w-4" />
              Disconnect
            </Button>
          </div>
        </div>
      </section>

      <div className="space-y-4">
        <section className="rounded-md bg-card p-4">
          <div className="mb-3 flex items-center justify-between gap-3">
            <h2 className="text-sm font-semibold text-foreground">Session</h2>
          </div>
          <dl className="responsive-description-list grid gap-x-3 gap-y-3 text-sm">
            <dt className="text-muted-foreground">State</dt>
            <dd className="font-medium">{state.daemon.state}</dd>
            <dt className="text-muted-foreground">Profile</dt>
            <dd className="break-words">{state.daemon.active_profile ?? profile}</dd>
            <dt className="text-muted-foreground">Interface</dt>
            <dd>{state.daemon.interface ?? "-"}</dd>
            <dt className="text-muted-foreground">Last error</dt>
            <dd className="break-words">{state.error ?? "-"}</dd>
          </dl>
        </section>

        <CredentialsSection
          profile={profile}
          busy={state.busy}
          disabled={!profile || !selectedProfileExists || !canConnect}
          credentialState={credentialState}
          onForget={onForgetCredential}
        />
      </div>
    </div>
  );
}

function ProfileSummaryCard({
  profile,
  detailState,
  actionsDisabled,
  busy,
  onDuplicate,
  onRename,
  onDelete,
}: {
  profile: string;
  detailState: ProfileDetailState;
  actionsDisabled: boolean;
  busy: boolean;
  onDuplicate: () => Promise<void>;
  onRename: (newName: string) => Promise<void>;
  onDelete: (syncTombstone?: boolean) => Promise<void>;
}) {
  const detail = detailState.detail;

  return (
    <div className="rounded-md bg-muted p-3 text-sm">
      <div className="mb-3 flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-muted-foreground">Profile</div>
          <div className="mt-1 break-words font-semibold">{detail?.name ?? (profile || "none")}</div>
        </div>
        <ProfileActionsMenu
          profile={profile}
          disabled={actionsDisabled || busy}
          busy={busy}
          onDuplicate={onDuplicate}
          onRename={onRename}
          onDelete={onDelete}
        />
      </div>

      {detailState.status === "error" ? (
        <div className="rounded-md bg-destructive p-2 font-semibold text-white">
          {detailState.message}
        </div>
      ) : (
        <dl className="responsive-description-list grid gap-x-3 gap-y-2">
          <dt className="text-muted-foreground">Server</dt>
          <dd className="break-words font-medium">{profileDetailValue(detail?.server, detailState)}</dd>
          <dt className="text-muted-foreground">Username</dt>
          <dd className="break-words font-medium">{detail?.username ?? profileDetailFallback(detailState, "Prompt")}</dd>
          <dt className="text-muted-foreground">Auth group</dt>
          <dd className="break-words font-medium">{detail?.authgroup ?? profileDetailFallback(detailState, "Default")}</dd>
          <dt className="text-muted-foreground">Reported OS</dt>
          <dd className="break-words font-medium">{profileDetailValue(detail?.reported_os, detailState)}</dd>
          <dt className="text-muted-foreground">Policy</dt>
          <dd className="break-words font-medium">
            {detail ? profilePolicySummary(detail) : profileDetailFallback(detailState, "-")}
          </dd>
        </dl>
      )}
    </div>
  );
}

function DaemonHandoffPanel({
  state,
  busy,
  onStart,
}: {
  state: DaemonHandoffState;
  busy: boolean;
  onStart: () => Promise<DaemonHandoffStatus>;
}) {
  const detail = state.detail;
  if (state.status === "unknown" || detail?.socketReachable) {
    return null;
  }

  const starting = state.status === "starting";
  const canStart = detail?.serviceInstalled !== false && detail?.serviceActive !== true;
  const serviceState = detail?.serviceInstalled === false
    ? "not installed"
    : detail?.serviceActive
      ? "active"
      : "not active";
  const message =
    state.message ??
    detail?.message ??
    "The privileged daemon is not reachable. Start the packaged systemd service before connecting.";

  return (
    <div className="rounded-md border-2 border-primary/30 bg-[#ecf0f1] p-3 text-sm">
      <div className="mb-2 flex items-center justify-between gap-3">
        <div className="flex min-w-0 items-center gap-2 font-semibold text-foreground">
          <AlertTriangle className="h-4 w-4 shrink-0 text-primary" />
          <span className="truncate">Daemon required</span>
        </div>
        <Badge variant="outline">{serviceState}</Badge>
      </div>
      <div className="space-y-1 break-words text-muted-foreground">
        <div>{message}</div>
        {detail ? (
          <div>
            {detail.serviceName} via {detail.socketPath}
          </div>
        ) : null}
      </div>
      {canStart ? (
        <Button
          type="button"
          className="mt-3 w-full"
          variant="outline"
          disabled={busy || starting}
          onClick={() => void onStart()}
        >
          {starting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Power className="h-4 w-4" />}
          Start Daemon
        </Button>
      ) : null}
    </div>
  );
}

function profileDetailValue(value: string | undefined, state: ProfileDetailState) {
  if (value) {
    return value;
  }

  return profileDetailFallback(state, "-");
}

function profileDetailFallback(state: ProfileDetailState, fallback: string) {
  if (state.status === "checking") {
    return "Loading...";
  }

  return fallback;
}

function profilePolicySummary(detail: ProfileDetail) {
  const domains = countLabel(detail.company_domains_count, "domain");
  const bypasses = countLabel(detail.local_bypass_count, "bypass CIDR");
  return `${domains}, ${bypasses}`;
}

function countLabel(count: number, singular: string) {
  return `${count} ${singular}${count === 1 ? "" : "s"}`;
}

function CredentialsSection({
  profile,
  busy,
  disabled,
  credentialState,
  onForget,
}: {
  profile: string;
  busy: boolean;
  disabled: boolean;
  credentialState: CredentialState;
  onForget: () => void;
}) {
  const [confirmOpen, setConfirmOpen] = useState(false);
  const saved = credentialState.status === "saved";

  return (
    <section className="rounded-md bg-card p-4">
      <div className="mb-3 flex items-center justify-between gap-3">
        <h2 className="text-sm font-semibold text-foreground">Credentials</h2>
        <CredentialActionsMenu
          disabled={disabled || busy}
          canForget={saved}
          onForget={() => setConfirmOpen(true)}
        />
      </div>
      <div className="space-y-3">
        <div className="rounded-md bg-muted p-3 text-sm">
          <div className="flex items-center justify-between gap-3">
            <div className="min-w-0">
              <div className="font-semibold text-foreground">VPN password</div>
              <div className="mt-1 break-words text-muted-foreground">
                {credentialStatusText(credentialState)}
              </div>
            </div>
            <CredentialBadge state={credentialState} />
          </div>
          {credentialState.status === "error" ? (
            <div className="mt-3 rounded-md bg-destructive p-2 font-semibold text-white">
              {credentialState.message}
            </div>
          ) : null}
        </div>
      </div>

      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <KeyRound className="h-4 w-4" />
              Forget saved password?
            </DialogTitle>
            <DialogDescription>
              This removes the VPN password saved for profile "{profile}" from the OS keyring. The
              profile file will not be deleted.
            </DialogDescription>
          </DialogHeader>
          <div className="flex justify-end gap-2">
            <Button type="button" variant="outline" onClick={() => setConfirmOpen(false)} disabled={busy}>
              Cancel
            </Button>
            <Button
              type="button"
              variant="destructive"
              disabled={busy}
              onClick={() => {
                setConfirmOpen(false);
                onForget();
              }}
            >
              <Trash2 className="h-4 w-4" />
              Forget Password
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </section>
  );
}

function CredentialActionsMenu({
  disabled,
  canForget,
  onForget,
}: {
  disabled: boolean;
  canForget: boolean;
  onForget: () => void;
}) {
  const [open, setOpen] = useState(false);

  return (
    <div className="relative">
      <button
        type="button"
        disabled={disabled}
        aria-label="Credential actions"
        title="Credential actions"
        onClick={() => setOpen((current) => !current)}
        className="flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary disabled:cursor-not-allowed disabled:opacity-60"
      >
        <MoreHorizontal className="h-4 w-4" />
      </button>
      {open ? (
        <div
          className="absolute right-0 z-20 mt-2 w-52 rounded-md bg-white p-1 shadow-lg ring-1 ring-black/10"
          onClick={(event) => event.stopPropagation()}
        >
          <button
            type="button"
            disabled={!canForget}
            onClick={() => {
              setOpen(false);
              onForget();
            }}
            className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-sm font-semibold text-destructive transition-colors hover:bg-muted disabled:cursor-not-allowed disabled:text-muted-foreground disabled:opacity-70"
          >
            <Trash2 className="h-4 w-4" />
            Forget Password...
          </button>
        </div>
      ) : null}
    </div>
  );
}

function CredentialBadge({ state }: { state: CredentialState }) {
  if (state.status === "saved") {
    return <Badge variant="outline">saved</Badge>;
  }

  if (state.status === "error") {
    return <Badge variant="destructive">error</Badge>;
  }

  if (state.status === "checking") {
    return <Badge variant="warning">checking</Badge>;
  }

  if (state.status === "not_saved") {
    return <Badge variant="secondary">not saved</Badge>;
  }

  return <Badge variant="outline">unknown</Badge>;
}

function credentialStatusText(state: CredentialState) {
  switch (state.status) {
    case "saved":
      return "Saved in OS keyring.";
    case "not_saved":
      return "Not saved. You will be prompted next time you connect.";
    case "checking":
      return "Checking OS keyring...";
    case "error":
      return "Could not read OS keyring status.";
    case "unknown":
      return "Select an available profile to check keyring status.";
  }
}

function ProfileActionsMenu({
  profile,
  disabled,
  busy,
  onDuplicate,
  onRename,
  onDelete,
}: {
  profile: string;
  disabled: boolean;
  busy: boolean;
  onDuplicate: () => Promise<void>;
  onRename: (newName: string) => Promise<void>;
  onDelete: (syncTombstone?: boolean) => Promise<void>;
}) {
  const [open, setOpen] = useState(false);
  const [renameOpen, setRenameOpen] = useState(false);
  const [renameValue, setRenameValue] = useState(profile);
  const [renameError, setRenameError] = useState<string | null>(null);
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);
  const [deleteSyncTombstone, setDeleteSyncTombstone] = useState(false);

  useEffect(() => {
    setRenameValue(profile);
    setRenameError(null);
  }, [profile]);

  useEffect(() => {
    if (!open) {
      return;
    }

    function close() {
      setOpen(false);
    }

    window.addEventListener("click", close);
    return () => window.removeEventListener("click", close);
  }, [open]);

  return (
    <div className="relative">
      <Button
        type="button"
        variant="ghost"
        size="icon"
        disabled={disabled}
        aria-label="Profile actions"
        title="Profile actions"
          onClick={(event) => {
            event.stopPropagation();
            setOpen((current) => !current);
        }}
      >
        <MoreHorizontal className="h-4 w-4" />
      </Button>
      {open ? (
        <div
          className="absolute right-0 z-20 mt-2 w-48 rounded-md bg-white p-1 shadow-lg ring-1 ring-black/10"
          onClick={(event) => event.stopPropagation()}
        >
          <button
            type="button"
            disabled={disabled || busy}
            onClick={() => {
              setOpen(false);
              void onDuplicate();
            }}
            className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-sm font-semibold text-foreground transition-colors hover:bg-muted disabled:cursor-not-allowed disabled:text-muted-foreground disabled:opacity-70"
          >
            <Copy className="h-4 w-4" />
            Duplicate
          </button>
          <button
            type="button"
            disabled={disabled || busy}
            onClick={() => {
              setOpen(false);
              setRenameValue(profile);
              setRenameError(null);
              setRenameOpen(true);
            }}
            className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-sm font-semibold text-foreground transition-colors hover:bg-muted disabled:cursor-not-allowed disabled:text-muted-foreground disabled:opacity-70"
          >
            <Pencil className="h-4 w-4" />
            Rename...
          </button>
          <button
            type="button"
            disabled={disabled || busy}
            onClick={() => {
              setOpen(false);
              setDeleteSyncTombstone(false);
              setDeleteConfirmOpen(true);
            }}
            className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-sm font-semibold text-destructive transition-colors hover:bg-muted disabled:cursor-not-allowed disabled:text-muted-foreground disabled:opacity-70"
          >
            <Trash2 className="h-4 w-4" />
            Delete...
          </button>
        </div>
      ) : null}
      <Dialog open={renameOpen} onOpenChange={setRenameOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Pencil className="h-4 w-4" />
              Rename profile
            </DialogTitle>
            <DialogDescription>
              Rename profile "{profile}". Saved VPN password entries will be moved to the new name.
            </DialogDescription>
          </DialogHeader>
          <form
            className="space-y-4"
            onSubmit={(event) => {
              event.preventDefault();
              const nextName = renameValue.trim();
              if (!nextName) {
                setRenameError("Profile name is required.");
                return;
              }
              setRenameError(null);
              void onRename(nextName)
                .then(() => setRenameOpen(false))
                .catch((error) => setRenameError(formatError(error)));
            }}
          >
            <div className="space-y-2">
              <Label htmlFor="rename-profile-name">Name</Label>
              <Input
                id="rename-profile-name"
                value={renameValue}
                onChange={(event) => {
                  setRenameValue(event.target.value);
                  setRenameError(null);
                }}
                autoComplete="off"
                className={renameError ? "border-destructive focus-visible:border-destructive" : undefined}
              />
              <FieldError message={renameError ?? undefined} />
            </div>
            <div className="flex justify-end gap-2">
              <Button
                type="button"
                variant="outline"
                onClick={() => setRenameOpen(false)}
                disabled={busy}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={busy}>
                {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Pencil className="h-4 w-4" />}
                Rename
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
      <Dialog open={deleteConfirmOpen} onOpenChange={setDeleteConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Trash2 className="h-4 w-4" />
              Delete profile?
            </DialogTitle>
            <DialogDescription>
              This deletes profile "{profile}" and removes its saved VPN password from the OS
              keyring. This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <label className="flex items-start gap-3 rounded-md bg-muted p-3 text-sm">
            <input
              type="checkbox"
              checked={deleteSyncTombstone}
              disabled={busy}
              onChange={(event) => setDeleteSyncTombstone(event.target.checked)}
              className="mt-1 h-4 w-4 shrink-0 accent-primary"
            />
            <span className="min-w-0">
              <span className="block font-semibold text-foreground">
                Upload Cloud Sync tombstone
              </span>
              <span className="mt-1 block text-muted-foreground">
                Also remove this profile from the remote manifest and write
                deleted/{profile}.json. No VPN password, OTP, cookie, or token is uploaded.
              </span>
            </span>
          </label>
          <div className="flex justify-end gap-2">
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                setDeleteConfirmOpen(false);
                setDeleteSyncTombstone(false);
              }}
              disabled={busy}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="destructive"
              disabled={busy}
              onClick={() => {
                setDeleteConfirmOpen(false);
                const syncTombstone = deleteSyncTombstone;
                setDeleteSyncTombstone(false);
                void onDelete(syncTombstone);
              }}
            >
              <Trash2 className="h-4 w-4" />
              Delete Profile
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function SecretsView({ profile }: { profile: string }) {
  return (
    <div className="responsive-two-panel workbench-surface grid gap-4">
      <section className="rounded-md bg-card p-4">
        <h2 className="mb-3 text-sm font-semibold text-foreground">Keyring</h2>
        <div className="space-y-3 text-sm">
          <SecretStatusRow label="Selected profile" value={profile || "unnamed"} />
          <SecretStatusRow label="VPN password" value="Read from OS keyring during connect" />
          <SecretStatusRow label="OTP" value="Always requested interactively" />
        </div>
      </section>

      <section className="rounded-md bg-card p-4">
        <h2 className="mb-3 text-sm font-semibold text-foreground">Storage boundary</h2>
        <div className="grid gap-3 text-sm">
          <div className="rounded-md bg-muted p-3">
            Passwords, OTP values, cookies, and private keys are not displayed here and are not
            written to profile TOML files.
          </div>
          <div className="rounded-md bg-muted p-3">
            Profile management can live in this workbench without moving privileged VPN work into
            the desktop process.
          </div>
        </div>
      </section>
    </div>
  );
}

function SecretStatusRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="responsive-description-list grid gap-3 rounded-md bg-muted p-3">
      <span className="text-muted-foreground">{label}</span>
      <span className="break-words font-medium">{value}</span>
    </div>
  );
}

function DiagnosticsView({
  diagnostics,
  error,
}: {
  diagnostics: DiagnosticsSnapshot | null;
  error: string | null;
}) {
  return (
    <section className="workbench-surface rounded-md bg-card p-4">
      <DiagnosticsPanel diagnostics={diagnostics} error={error} />
    </section>
  );
}

function LogsView({ logs }: { logs: LogEntry[] }) {
  return (
    <section className="flex min-h-[calc(100vh-8.5rem)] flex-col rounded-md bg-card p-4">
      <div className="mb-3 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-foreground">Events</h2>
          <div className="mt-1 flex flex-wrap items-center gap-2 text-xs font-semibold text-muted-foreground">
            <span>{logs.length} retained</span>
            <span className="h-1 w-1 rounded-full bg-[#bdc3c7]" />
            <span>Newest first</span>
          </div>
        </div>
        <Button type="button" variant="outline" onClick={() => exportLogs(logs)} disabled={logs.length === 0}>
          <Download className="h-4 w-4" />
          Export
        </Button>
      </div>
      <EventLog logs={logs} />
    </section>
  );
}

function SettingsView({
  profile,
  profileDir,
  githubSyncState,
  githubSyncHistoryState,
  githubSyncBusy,
  githubSyncOperation,
  onStartGithubSyncLogin,
  onInitGithubSyncManifest,
  onUploadGithubSyncProfiles,
  onDownloadGithubSyncProfiles,
}: {
  profile: string;
  profileDir: string | null;
  githubSyncState: GithubSyncState;
  githubSyncHistoryState: GithubSyncHistoryState;
  githubSyncBusy: boolean;
  githubSyncOperation: GithubSyncOperation;
  onStartGithubSyncLogin: () => Promise<void>;
  onInitGithubSyncManifest: () => Promise<void>;
  onUploadGithubSyncProfiles: () => void;
  onDownloadGithubSyncProfiles: () => void;
}) {
  return (
    <div className="workbench-surface grid gap-4">
      <GithubSyncSettings
        state={githubSyncState}
        busy={githubSyncBusy}
        operation={githubSyncOperation}
        onStartLogin={onStartGithubSyncLogin}
        onInitManifest={onInitGithubSyncManifest}
        onUploadProfiles={onUploadGithubSyncProfiles}
        onDownloadProfiles={onDownloadGithubSyncProfiles}
      />

      <GithubSyncHistoryPanel state={githubSyncHistoryState} />

      <section className="rounded-md bg-card p-4">
        <h2 className="mb-3 text-sm font-semibold text-foreground">General</h2>
        <div className="divide-y divide-border rounded-md bg-muted">
          <SettingItem
            label="Profile directory"
            description="Local directory searched for VPN profile TOML files."
            value={profileDir ?? "Unavailable"}
          />
          <SettingItem
            label="Selected profile"
            description="Current profile selection used by the connect workflow."
            value={profile || "None"}
          />
        </div>
      </section>

      <section className="rounded-md bg-card p-4">
        <h2 className="mb-3 text-sm font-semibold text-foreground">Security</h2>
        <div className="divide-y divide-border rounded-md bg-muted">
          <SettingItem
            label="VPN password storage"
            description="Saved passwords are stored in the OS keyring."
            value="OS keyring"
          />
          <SettingItem
            label="Profile file boundary"
            description="Profile TOML files hold connection configuration only."
            value="No secrets"
          />
        </div>
      </section>
    </div>
  );
}

function GithubSyncHistoryPanel({ state }: { state: GithubSyncHistoryState }) {
  const entries = state.entries.slice(0, 5);

  return (
    <section className="rounded-md bg-card p-4">
      <div className="mb-3 flex items-center justify-between gap-3">
        <h2 className="text-sm font-semibold text-foreground">Sync History</h2>
        <Badge variant={state.status === "error" ? "destructive" : "outline"}>
          {state.status === "checking" ? "checking" : `${entries.length} shown`}
        </Badge>
      </div>
      {state.status === "error" ? (
        <div className="rounded-md bg-destructive p-3 text-sm font-semibold text-white">
          {state.message}
        </div>
      ) : entries.length === 0 ? (
        <div className="rounded-md bg-muted p-3 text-sm font-medium text-muted-foreground">
          No sync operations recorded on this device.
        </div>
      ) : (
        <div className="divide-y divide-border rounded-md bg-muted">
          {entries.map((entry, index) => (
            <div key={`${entry.recordedAt}-${entry.operation}-${index}`} className="p-3 text-sm">
              <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                <div className="min-w-0">
                  <div className="font-semibold text-foreground">
                    {syncHistoryOperationLabel(entry.operation)} · {entry.outcome}
                  </div>
                  <div className="mt-1 break-words text-muted-foreground">{entry.message}</div>
                </div>
                <div className="shrink-0 text-xs font-semibold text-muted-foreground">
                  {entry.recordedAt}
                </div>
              </div>
              <div className="mt-2 flex flex-wrap gap-2 text-xs font-semibold text-muted-foreground">
                <span>{entry.repository}</span>
                {entry.manifestSha ? <span>SHA {entry.manifestSha}</span> : null}
                {entry.manifestBytes ? <span>{entry.manifestBytes} bytes</span> : null}
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function syncHistoryOperationLabel(operation: string) {
  switch (operation) {
    case "init":
      return "Init";
    case "upload":
      return "Upload";
    case "restore":
      return "Restore";
    case "delete":
      return "Delete";
    case "status":
      return "Status";
    default:
      return operation;
  }
}

function GithubSyncSettings({
  state,
  busy,
  operation,
  onStartLogin,
  onInitManifest,
  onUploadProfiles,
  onDownloadProfiles,
}: {
  state: GithubSyncState;
  busy: boolean;
  operation: GithubSyncOperation;
  onStartLogin: () => Promise<void>;
  onInitManifest: () => Promise<void>;
  onUploadProfiles: () => void;
  onDownloadProfiles: () => void;
}) {
  const detail = state.detail;
  const authorized = detail?.auth === "authorized";
  const manifestReady = detail?.manifest === "present" || detail?.manifest === "created";
  const canInit = authorized && !manifestReady && !busy;
  const canUpload = authorized && manifestReady && !busy;

  return (
    <section className="rounded-md bg-card p-4">
      <div className="mb-3 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <h2 className="flex items-center gap-2 text-sm font-semibold text-foreground">
            <Cloud className="h-4 w-4" />
            Cloud Sync
          </h2>
          <div className="mt-1 flex flex-wrap items-center gap-2 text-xs font-semibold text-muted-foreground">
            <span>{detail?.repository ?? "fudanglp/oc-oxide-sync"}</span>
            <span className="h-1 w-1 rounded-full bg-[#bdc3c7]" />
            <span>{detail?.keyringAccount ?? "fudanglp:oc-oxide-sync"}</span>
            <span className="h-1 w-1 rounded-full bg-[#bdc3c7]" />
            <span>{formatLastChecked(state.lastCheckedAt)}</span>
            <span className="h-1 w-1 rounded-full bg-[#bdc3c7]" />
            <span>{githubSyncCacheText(state)}</span>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <GithubSyncBadge state={state} />
        </div>
      </div>

      {state.status === "error" ? (
        <div className="mb-3 rounded-md bg-destructive p-3 text-sm font-semibold text-white">
          {state.message}
        </div>
      ) : null}
      {state.status === "checking" ? (
        <div className="mb-3 flex items-center gap-2 rounded-md bg-muted p-3 text-sm font-medium text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" />
          <span>
            Fetching latest from GitHub...
            {state.detail ? " Showing cached status until it finishes." : " No cached status yet."}
          </span>
        </div>
      ) : null}

      <div className="responsive-main-panel grid gap-4">
        <div className="rounded-md bg-muted p-3">
          <dl className="responsive-description-list grid gap-x-3 gap-y-3 text-sm">
            <dt className="text-muted-foreground">GitHub token</dt>
            <dd className="font-medium">{githubSyncAuthText(detail?.auth, state.status)}</dd>
            <dt className="text-muted-foreground">Remote manifest</dt>
            <dd className="font-medium">{githubSyncManifestText(detail?.manifest, state.status)}</dd>
            <dt className="text-muted-foreground">Bytes</dt>
            <dd className="font-medium">{detail?.manifestBytes ?? "-"}</dd>
            <dt className="text-muted-foreground">SHA</dt>
            <dd className="break-all font-medium">{detail?.manifestSha ?? "-"}</dd>
          </dl>
          {detail?.message ? (
            <div className="mt-3 rounded-md bg-white p-2 text-sm font-medium text-muted-foreground">
              {detail.message}
            </div>
          ) : null}
        </div>

        <div className="space-y-3">
          <div className="rounded-md bg-muted p-3">
            {authorized ? (
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex min-w-0 items-center gap-3 text-sm">
                  <CheckCircle2 className="h-4 w-4 shrink-0 text-primary" />
                  <div className="min-w-0">
                    <div className="font-semibold text-foreground">GitHub connected</div>
                    <div className="truncate text-muted-foreground">
                      {detail?.keyringAccount ?? "Token saved in keyring"}
                    </div>
                  </div>
                </div>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => void onStartLogin()}
                  disabled={busy}
                >
                  {operation === "signing_in" ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <LogIn className="h-4 w-4" />
                  )}
                  Reconnect
                </Button>
              </div>
            ) : (
              <div className="flex flex-wrap gap-2">
                <Button type="button" onClick={() => void onStartLogin()} disabled={busy}>
                  {operation === "signing_in" ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <LogIn className="h-4 w-4" />
                  )}
                  Sign In
                </Button>
              </div>
            )}
          </div>

          {manifestReady ? (
            <div className="rounded-md bg-muted p-3">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex min-w-0 items-center gap-3 text-sm">
                  <CheckCircle2 className="h-4 w-4 shrink-0 text-primary" />
                  <div className="min-w-0">
                    <div className="font-semibold text-foreground">Manifest ready</div>
                    <div className="truncate text-muted-foreground">
                      {detail?.manifestSha ? `SHA ${detail.manifestSha}` : "Remote profile store is initialized"}
                    </div>
                  </div>
                </div>
                <div className="flex flex-wrap justify-end gap-2">
                  <Button type="button" variant="outline" disabled={!canUpload} onClick={onDownloadProfiles}>
                    {operation === "downloading" ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Download className="h-4 w-4" />
                    )}
                    Restore
                  </Button>
                  <Button type="button" disabled={!canUpload} onClick={onUploadProfiles}>
                    {operation === "uploading" ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Upload className="h-4 w-4" />
                    )}
                    Upload
                  </Button>
                </div>
              </div>
            </div>
          ) : authorized ? (
            <div className="rounded-md bg-muted p-3">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex min-w-0 items-center gap-3 text-sm">
                  <Cloud className="h-4 w-4 shrink-0 text-muted-foreground" />
                  <div className="min-w-0">
                    <div className="font-semibold text-foreground">Remote profile store</div>
                    <div className="truncate text-muted-foreground">
                      Initialize manifest.json in the selected private repo.
                    </div>
                  </div>
                </div>
                <Button type="button" disabled={!canInit} onClick={() => void onInitManifest()}>
                  {operation === "initializing" ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <CheckCircle2 className="h-4 w-4" />
                  )}
                  Init
                </Button>
              </div>
              {operation === "initializing" ? (
                <div className="mt-3 rounded-md bg-white p-2 text-sm font-medium text-muted-foreground">
                  Writing manifest to GitHub...
                </div>
              ) : null}
            </div>
          ) : null}
        </div>
      </div>
    </section>
  );
}

function GithubSyncLoginDialog({
  open,
  flow,
  busy,
  operation,
  onPoll,
  onCancel,
}: {
  open: boolean;
  flow: GithubDeviceFlowState | null;
  busy: boolean;
  operation: GithubSyncOperation;
  onPoll: () => Promise<void>;
  onCancel: () => void;
}) {
  const canCheck =
    Boolean(flow) && !busy && flow?.pollStatus !== "access_denied" && flow?.pollStatus !== "expired";

  return (
    <Dialog open={open} onOpenChange={(nextOpen) => (!nextOpen ? onCancel() : undefined)}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <LogIn className="h-4 w-4" />
            GitHub Sign In
          </DialogTitle>
          <DialogDescription>
            Authorize oc-oxide-sync in GitHub, then return here.
          </DialogDescription>
        </DialogHeader>

        {flow ? (
          <GithubDeviceFlowPanel flow={flow} />
        ) : (
          <div className="rounded-md bg-muted p-3 text-sm font-medium text-muted-foreground">
            Preparing GitHub device authorization...
          </div>
        )}

        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={onCancel}>
            Cancel
          </Button>
          <Button type="button" onClick={() => void onPoll()} disabled={!canCheck}>
            {operation === "polling" ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <RefreshCw className="h-4 w-4" />
            )}
            Check
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function GithubSyncUploadDialog({
  open,
  busy,
  operation,
  error,
  onUpload,
  onCancel,
}: {
  open: boolean;
  busy: boolean;
  operation: GithubSyncOperation;
  error: string | null;
  onUpload: () => Promise<void>;
  onCancel: () => void;
}) {
  const uploading = busy && operation === "uploading";
  const canUpload = !busy;

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (canUpload) {
      void onUpload();
    }
  }

  return (
    <Dialog open={open} onOpenChange={(nextOpen) => (!nextOpen && !busy ? onCancel() : undefined)}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Upload className="h-4 w-4" />
            Upload Profiles
          </DialogTitle>
          <DialogDescription>
            Write local non-secret profile configuration to the selected private GitHub repo.
          </DialogDescription>
        </DialogHeader>

        <form className="space-y-3" onSubmit={submit}>
          {error ? (
            <div className="rounded-md bg-destructive p-3 text-sm font-semibold text-white">
              {error}
            </div>
          ) : null}

          {uploading ? (
            <div className="flex items-center gap-2 rounded-md bg-muted p-3 text-sm font-medium text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              <span>Uploading profiles to GitHub...</span>
            </div>
          ) : null}

          {!uploading ? (
            <div className="rounded-md bg-muted p-3 text-sm font-medium text-muted-foreground">
              GitHub will store profile server, username, routing, and domain configuration. VPN
              passwords, OTP values, cookies, and private keys are not uploaded.
            </div>
          ) : null}

          <div className="flex justify-end gap-2">
            <Button type="button" variant="outline" onClick={onCancel} disabled={busy}>
              Cancel
            </Button>
            <Button type="submit" disabled={!canUpload}>
              {uploading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Upload className="h-4 w-4" />
              )}
              Upload
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function GithubSyncDownloadDialog({
  open,
  busy,
  operation,
  error,
  onDownload,
  onCancel,
}: {
  open: boolean;
  busy: boolean;
  operation: GithubSyncOperation;
  error: string | null;
  onDownload: () => Promise<void>;
  onCancel: () => void;
}) {
  const downloading = busy && operation === "downloading";
  const canDownload = !busy;

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (canDownload) {
      void onDownload();
    }
  }

  return (
    <Dialog open={open} onOpenChange={(nextOpen) => (!nextOpen && !busy ? onCancel() : undefined)}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Download className="h-4 w-4" />
            Restore Profiles
          </DialogTitle>
          <DialogDescription>
            Import remote profiles without overwriting local files.
          </DialogDescription>
        </DialogHeader>

        <form className="space-y-3" onSubmit={submit}>
          {error ? (
            <div className="rounded-md bg-destructive p-3 text-sm font-semibold text-white">
              {error}
            </div>
          ) : null}

          {downloading ? (
            <div className="flex items-center gap-2 rounded-md bg-muted p-3 text-sm font-medium text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              <span>Restoring profiles from GitHub...</span>
            </div>
          ) : (
            <div className="rounded-md bg-muted p-3 text-sm font-medium text-muted-foreground">
              Existing local profiles are preserved. Same-name remote profiles are imported as
              local copies with a remote suffix.
            </div>
          )}

          <div className="flex justify-end gap-2">
            <Button type="button" variant="outline" onClick={onCancel} disabled={busy}>
              Cancel
            </Button>
            <Button type="submit" disabled={!canDownload}>
              {downloading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Download className="h-4 w-4" />
              )}
              Restore
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function GithubDeviceFlowPanel({ flow }: { flow: GithubDeviceFlowState }) {
  const expired = flow.pollStatus === "expired" || Date.now() >= flow.expiresAtMs;

  return (
    <div className="rounded-md bg-white p-3 text-sm">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Badge variant={expired ? "destructive" : "outline"}>{flow.pollStatus}</Badge>
        <span className="text-muted-foreground">{expired ? "expired" : `${flow.nextIntervalSecs}s poll`}</span>
      </div>
      <div className="responsive-description-list grid gap-3">
        <div>
          <div className="text-muted-foreground">Code</div>
          <button
            type="button"
            title="Copy code"
            onClick={() => void copyText(flow.userCode)}
            className="mt-1 flex min-h-10 w-full items-center justify-between gap-2 rounded-md border-2 border-input bg-muted px-3 text-left font-mono text-lg font-bold text-foreground"
          >
            <span>{flow.userCode}</span>
            <Copy className="h-4 w-4 text-muted-foreground" />
          </button>
        </div>
        <div>
          <div className="text-muted-foreground">URL</div>
          <button
            type="button"
            title="Copy URL"
            onClick={() => void copyText(flow.verificationUri)}
            className="mt-1 flex min-h-10 w-full items-center justify-between gap-2 rounded-md border-2 border-input bg-muted px-3 text-left font-medium text-foreground"
          >
            <span className="min-w-0 break-all">{flow.verificationUri}</span>
            <ExternalLink className="h-4 w-4 shrink-0 text-muted-foreground" />
          </button>
        </div>
      </div>
    </div>
  );
}

function GithubSyncBadge({ state }: { state: GithubSyncState }) {
  if (state.status === "checking") {
    return <Badge variant="warning">checking</Badge>;
  }

  if (state.status === "error") {
    return <Badge variant="destructive">error</Badge>;
  }

  if (state.status === "ready") {
    if (!state.detail) {
      return <Badge variant="outline">unknown</Badge>;
    }
    if (state.detail.auth === "authorized") {
      return <Badge variant="outline">authorized</Badge>;
    }
    if (state.detail.auth === "refresh_failed") {
      return <Badge variant="destructive">refresh failed</Badge>;
    }
    return <Badge variant="secondary">not signed in</Badge>;
  }

  return <Badge variant="outline">unknown</Badge>;
}

function githubSyncAuthText(auth: GithubSyncAuthState | undefined, status: GithubSyncState["status"]) {
  if (status === "checking") {
    return auth ? `${githubSyncAuthLabel(auth)} (refreshing...)` : "Checking keyring...";
  }

  if (status === "unknown") {
    return "Not checked";
  }

  return auth ? githubSyncAuthLabel(auth) : "Unknown";
}

function githubSyncAuthLabel(auth: GithubSyncAuthState) {
  switch (auth) {
    case "authorized":
      return "Authorized";
    case "refresh_failed":
      return "Refresh failed";
    case "not_authorized":
      return "Not signed in";
  }
}

function githubSyncManifestText(
  manifest: GithubSyncManifestState | undefined,
  status: GithubSyncState["status"],
) {
  if (status === "checking") {
    return manifest ? `${githubSyncManifestLabel(manifest)} (refreshing...)` : "Checking GitHub...";
  }

  if (status === "unknown") {
    return "Not checked";
  }

  return manifest ? githubSyncManifestLabel(manifest) : "Unknown";
}

function githubSyncManifestLabel(manifest: GithubSyncManifestState) {
  switch (manifest) {
    case "created":
      return "Created";
    case "present":
      return "Present";
    case "missing":
      return "Missing";
    case "unknown":
      return "Unknown";
  }
}

function formatLastChecked(value: number | null) {
  if (!value) {
    return "Not checked";
  }

  return `Last checked ${new Date(value).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  })}`;
}

function githubSyncCacheText(state: GithubSyncState) {
  if (state.status === "checking") {
    return state.detail ? "cached" : "not checked";
  }

  if (state.detail) {
    return "latest";
  }

  return "not checked";
}

function SettingItem({
  label,
  description,
  value,
}: {
  label: string;
  description: string;
  value: string;
}) {
  return (
    <div className="responsive-description-list grid gap-3 px-3 py-3 text-sm">
      <div className="min-w-0">
        <div className="font-semibold text-foreground">{label}</div>
        <div className="mt-1 text-muted-foreground">{description}</div>
      </div>
      <div className="min-w-0 break-words font-medium text-foreground">{value}</div>
    </div>
  );
}

function CreateProfileForm({
  draft,
  error,
  fieldErrors,
  setDraft,
  setFieldErrors,
  busy,
  onCancel,
  onCreate,
}: {
  draft: CreateProfileDraft;
  error: string | null;
  fieldErrors: CreateProfileFieldErrors;
  setDraft: React.Dispatch<React.SetStateAction<CreateProfileDraft>>;
  setFieldErrors: React.Dispatch<React.SetStateAction<CreateProfileFieldErrors>>;
  busy: boolean;
  onCancel: () => void;
  onCreate: (input: CreateProfileInput) => Promise<void>;
}) {
  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    const nextFieldErrors = validateCreateProfileDraft(draft);
    setFieldErrors(nextFieldErrors);
    if (Object.keys(nextFieldErrors).length > 0) {
      return;
    }

    await onCreate({
      name: draft.name,
      server: draft.server,
      reportedOs: emptyToNull(draft.reportedOs),
      username: emptyToNull(draft.username),
      authgroup: emptyToNull(draft.authgroup),
      companyDomains: splitList(draft.companyDomains),
      localBypass: splitList(draft.localBypass),
      vpnPassword: draft.savePassword ? emptyToNull(draft.vpnPassword) : null,
    });
  }

  function updateDraft(field: keyof CreateProfileDraft, value: string | boolean) {
    setDraft((current) => ({ ...current, [field]: value }));
    setFieldErrors((current) => {
      if (!current[field]) {
        return current;
      }
      const { [field]: _removed, ...rest } = current;
      return rest;
    });
  }

  return (
    <form className="grid gap-4" noValidate onSubmit={handleSubmit}>
      {error ? (
        <div className="rounded-md bg-destructive p-3 text-sm font-semibold text-white">
          {error}
        </div>
      ) : null}
      <div className="responsive-form-panel grid gap-4">
        <section className="rounded-md bg-muted p-4">
          <h2 className="mb-4 text-sm font-semibold text-foreground">Connection</h2>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="new-profile-name">Name</Label>
              <Input
                id="new-profile-name"
                value={draft.name}
                onChange={(event) => updateDraft("name", event.target.value)}
                autoComplete="off"
                className={fieldErrors.name ? "border-destructive focus-visible:border-destructive" : undefined}
              />
              <FieldError message={fieldErrors.name} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="new-profile-server">Server URL</Label>
              <Input
                id="new-profile-server"
                value={draft.server}
                onChange={(event) => updateDraft("server", event.target.value)}
                autoComplete="off"
                placeholder="https://vpn.example.test:555/"
                className={fieldErrors.server ? "border-destructive focus-visible:border-destructive" : undefined}
              />
              <FieldError message={fieldErrors.server} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="new-profile-username">Username</Label>
              <Input
                id="new-profile-username"
                value={draft.username}
                onChange={(event) => updateDraft("username", event.target.value)}
                autoComplete="username"
                className={fieldErrors.username ? "border-destructive focus-visible:border-destructive" : undefined}
              />
              <FieldError message={fieldErrors.username} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="new-profile-authgroup">Auth group</Label>
              <Input
                id="new-profile-authgroup"
                value={draft.authgroup}
                onChange={(event) => updateDraft("authgroup", event.target.value)}
                autoComplete="off"
                className={fieldErrors.authgroup ? "border-destructive focus-visible:border-destructive" : undefined}
              />
              <FieldError message={fieldErrors.authgroup} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="new-profile-reported-os">Reported OS</Label>
              <Input
                id="new-profile-reported-os"
                value={draft.reportedOs}
                onChange={(event) => updateDraft("reportedOs", event.target.value)}
                autoComplete="off"
                placeholder="linux"
                className={fieldErrors.reportedOs ? "border-destructive focus-visible:border-destructive" : undefined}
              />
              <FieldError message={fieldErrors.reportedOs} />
            </div>
          </div>
        </section>

        <section className="rounded-md bg-muted p-4">
          <h2 className="mb-4 text-sm font-semibold text-foreground">Keyring</h2>
          <label className="mb-3 flex items-center gap-2 text-sm font-semibold">
            <input
              type="checkbox"
              checked={draft.savePassword}
              onChange={(event) => updateDraft("savePassword", event.target.checked)}
              className="h-4 w-4 accent-primary"
            />
            Save VPN password
          </label>
          <div className="space-y-2">
            <Label htmlFor="new-profile-password">VPN password</Label>
            <Input
              id="new-profile-password"
              type="password"
              value={draft.vpnPassword}
              onChange={(event) => updateDraft("vpnPassword", event.target.value)}
              autoComplete="current-password"
              disabled={!draft.savePassword}
              className={fieldErrors.vpnPassword ? "border-destructive focus-visible:border-destructive" : undefined}
            />
            <FieldError message={fieldErrors.vpnPassword} />
          </div>
        </section>
      </div>

      <section className="rounded-md bg-muted p-4">
        <h2 className="mb-4 text-sm font-semibold text-foreground">Policy</h2>
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-2">
            <Label htmlFor="new-profile-domains">Company domains</Label>
            <textarea
              id="new-profile-domains"
              value={draft.companyDomains}
              onChange={(event) => updateDraft("companyDomains", event.target.value)}
              className={`min-h-24 w-full rounded-md border-2 bg-white px-3 py-2 text-[15px] text-foreground shadow-none focus-visible:outline-none ${
                fieldErrors.companyDomains
                  ? "border-destructive focus-visible:border-destructive"
                  : "border-input focus-visible:border-primary"
              }`}
            />
            <FieldError message={fieldErrors.companyDomains} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="new-profile-bypass">Local bypass CIDRs</Label>
            <textarea
              id="new-profile-bypass"
              value={draft.localBypass}
              onChange={(event) => updateDraft("localBypass", event.target.value)}
              className={`min-h-24 w-full rounded-md border-2 bg-white px-3 py-2 text-[15px] text-foreground shadow-none focus-visible:outline-none ${
                fieldErrors.localBypass
                  ? "border-destructive focus-visible:border-destructive"
                  : "border-input focus-visible:border-primary"
              }`}
            />
            <FieldError message={fieldErrors.localBypass} />
          </div>
        </div>
      </section>

      <div className="flex justify-end gap-2">
        <Button type="button" variant="outline" onClick={onCancel} disabled={busy}>
          Cancel
        </Button>
        <Button type="submit" disabled={busy}>
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
          Create
        </Button>
      </div>
    </form>
  );
}

function FieldError({ message }: { message?: string }) {
  if (!message) {
    return null;
  }

  return <p className="text-sm font-semibold text-destructive">{message}</p>;
}

function AppTitleBar() {
  async function runWindowAction(action: "minimize" | "maximize" | "close") {
    try {
      const appWindow = getCurrentWindow();
      if (action === "minimize") {
        await appWindow.hide();
      } else if (action === "maximize") {
        await appWindow.toggleMaximize();
      } else {
        await appWindow.close();
      }
    } catch (error) {
      console.error(`window ${action} failed`, error);
    }
  }

  return (
    <div className="flex h-9 shrink-0 select-none items-center bg-[#34495e] text-[#ecf0f1]">
      <div
        className="flex h-full min-w-0 flex-1 items-center gap-2 px-3"
        data-tauri-drag-region
        onDoubleClick={() => void runWindowAction("maximize")}
      >
        <img
          src={appIconUrl}
          alt=""
          className="h-5 w-5 shrink-0 object-contain"
          data-tauri-drag-region
        />
        <span className="truncate text-[13px] font-medium" data-tauri-drag-region>
          oc-oxide
        </span>
      </div>
      <div className="flex h-full">
        <button
          type="button"
          className="flex h-full w-11 items-center justify-center text-[#bdc3c7] hover:bg-[#2c3e50] hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-inset"
          aria-label="Minimize window"
          title="Minimize"
          onClick={() => void runWindowAction("minimize")}
        >
          <Minus className="h-4 w-4" />
        </button>
        <button
          type="button"
          className="flex h-full w-11 items-center justify-center text-[#bdc3c7] hover:bg-[#2c3e50] hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-inset"
          aria-label="Maximize window"
          title="Maximize"
          onClick={() => void runWindowAction("maximize")}
        >
          <Square className="h-3.5 w-3.5" />
        </button>
        <button
          type="button"
          className="flex h-full w-11 items-center justify-center text-zinc-300 hover:bg-red-600 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-300 focus-visible:ring-inset"
          aria-label="Close window"
          title="Close"
          onClick={() => void runWindowAction("close")}
        >
          <X className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}

function StateBadge({ state }: { state: DaemonState }) {
  const variant =
    state === "connected"
      ? "default"
      : state === "error"
        ? "destructive"
        : state === "awaiting_auth" || state === "connecting" || state === "configuring"
          ? "warning"
          : "secondary";
  const Icon =
    state === "connected"
      ? CheckCircle2
      : state === "error"
        ? AlertTriangle
        : state === "idle" || state === "disconnected"
          ? WifiOff
          : CircleDot;

  return (
    <Badge variant={variant} className="gap-1.5">
      <Icon className="h-3.5 w-3.5" />
      {state}
    </Badge>
  );
}

function DiagnosticsPanel({
  diagnostics,
  error,
}: {
  diagnostics: DiagnosticsSnapshot | null;
  error: string | null;
}) {
  return (
    <div className="grid gap-3">
      {error ? (
        <div className="rounded-md bg-destructive p-3 text-sm font-semibold text-white">
          {error}
        </div>
      ) : null}
      <dl className="responsive-description-list grid gap-x-3 gap-y-3 text-sm">
        <dt className="text-muted-foreground">Daemon</dt>
        <dd className="font-medium">{diagnostics?.state ?? "-"}</dd>
        <dt className="text-muted-foreground">Route policy</dt>
        <dd>{diagnostics?.route_policy ?? "-"}</dd>
        <dt className="text-muted-foreground">DNS policy</dt>
        <dd>{diagnostics?.dns_policy ?? "-"}</dd>
        <dt className="text-muted-foreground">Last error</dt>
        <dd>
          {diagnostics?.last_error
            ? `${diagnostics.last_error.code}: ${diagnostics.last_error.message}`
            : "-"}
        </dd>
      </dl>
    </div>
  );
}

function EventLog({ logs }: { logs: LogEntry[] }) {
  if (logs.length === 0) {
    return (
      <div className="flex min-h-0 flex-1 items-center justify-center rounded-md bg-muted text-sm font-semibold text-muted-foreground">
        No events
      </div>
    );
  }

  const newestFirst = [...logs].reverse();

  return (
    <div className="min-h-0 flex-1 overflow-auto rounded-md bg-muted">
      <ul className="divide-y divide-white">
        {newestFirst.map((entry, index) => (
          <li
            key={entry.id}
            className={`grid grid-cols-[76px_1fr] gap-3 px-3 py-2 text-sm ${
              index === 0 ? "border-l-4 border-primary bg-[#fff4e8]" : "border-l-4 border-transparent"
            }`}
          >
            <span className={logLevelClass(entry.level)}>{entry.level}</span>
            <span className="break-words">{entry.message}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function exportLogs(logs: LogEntry[]) {
  const content = logs
    .map((entry) => `${formatLogTimestamp(entry.id)} ${entry.level.toUpperCase()} ${entry.message}`)
    .join("\n");
  const blob = new Blob([content, "\n"], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `oc-oxide-events-${new Date().toISOString().replace(/[:.]/g, "-")}.log`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

async function copyText(value: string) {
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    // Clipboard access can be denied by the host environment.
  }
}

function formatLogTimestamp(id: number) {
  const date = new Date(id);
  return Number.isNaN(date.getTime()) ? "-" : date.toISOString();
}

function AuthDialog({
  prompt,
  profile,
  busy,
  onSubmit,
  onCancel,
}: {
  prompt: AuthPrompt | null;
  profile: string;
  busy: boolean;
  onSubmit: (fields: AuthSubmittedField[], saveRequest: AuthSaveRequest | null) => Promise<void>;
  onCancel: () => Promise<void>;
}) {
  const [answers, setAnswers] = useState<Record<string, string>>({});
  const [saveVpnPassword, setSaveVpnPassword] = useState(false);

  useEffect(() => {
    setAnswers({});
    setSaveVpnPassword(false);
  }, [prompt?.form_id]);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (!prompt) {
      return;
    }

    const fields = prompt.fields.map((field) => ({
        id: field.id,
        value: answers[field.id] ?? defaultFieldValue(field),
        secret: fieldIsSecret(field),
      }));
    const passwordField = vpnPasswordPromptField(prompt);
    const password = passwordField ? fields.find((field) => field.id === passwordField.id)?.value : null;

    await onSubmit(
      fields,
      saveVpnPassword && profile && password ? { profile, password } : null,
    );
  }

  const passwordField = prompt ? vpnPasswordPromptField(prompt) : null;

  return (
    <Dialog
      open={Boolean(prompt)}
      onOpenChange={(open) => {
        if (!open && prompt && !busy) {
          void onCancel();
        }
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <KeyRound className="h-4 w-4" />
            {prompt?.title ?? "Authentication"}
          </DialogTitle>
          {prompt?.message ? <DialogDescription>{prompt.message}</DialogDescription> : null}
        </DialogHeader>
        {prompt ? (
          <form className="space-y-4" onSubmit={handleSubmit}>
            {prompt.error ? (
              <div className="rounded-md bg-[#f39c12] p-3 text-sm font-semibold text-white">
                {prompt.error}
              </div>
            ) : null}
            {prompt.fields.map((field) => (
              <AuthFieldInput
                key={field.id}
                field={field}
                value={answers[field.id] ?? defaultFieldValue(field)}
                onChange={(value) => setAnswers((current) => ({ ...current, [field.id]: value }))}
              />
            ))}
            {passwordField ? (
              <label className="flex items-center gap-2 text-sm font-semibold">
                <input
                  type="checkbox"
                  checked={saveVpnPassword}
                  onChange={(event) => setSaveVpnPassword(event.target.checked)}
                  className="h-4 w-4 accent-primary"
                />
                Save VPN password to OS keyring
              </label>
            ) : null}
            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" onClick={onCancel} disabled={busy}>
                Cancel
              </Button>
              <Button type="submit" disabled={busy}>
                {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Activity className="h-4 w-4" />}
                Submit
              </Button>
            </div>
          </form>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

function AuthFieldInput({
  field,
  value,
  onChange,
}: {
  field: AuthPromptField;
  value: string;
  onChange: (value: string) => void;
}) {
  if (field.kind.type === "select") {
    return (
      <div className="space-y-2">
        <Label htmlFor={field.id}>{field.label}</Label>
        <select
          id={field.id}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          className="flex h-[42px] w-full rounded-md border-2 border-input bg-white px-3 py-2 text-[15px] text-foreground shadow-none transition-colors focus-visible:border-primary focus-visible:outline-none focus-visible:ring-0"
          required={field.required}
        >
          {field.kind.choices.map((choice) => (
            <option key={choice.value} value={choice.value}>
              {choice.label}
            </option>
          ))}
        </select>
      </div>
    );
  }

  const type =
    field.kind.type === "password" || field.kind.type === "otp" || field.kind.secret
      ? "password"
      : "text";

  return (
    <div className="space-y-2">
      <Label htmlFor={field.id}>{field.label}</Label>
      <Input
        id={field.id}
        type={type}
        value={value}
        autoComplete="off"
        required={field.required}
        onChange={(event) => onChange(event.target.value)}
      />
    </div>
  );
}

function fieldIsSecret(field: AuthPromptField) {
  if (field.kind.type === "password" || field.kind.type === "otp") {
    return true;
  }

  if (field.kind.type === "text") {
    return field.kind.secret;
  }

  return false;
}

function vpnPasswordPromptField(prompt: AuthPrompt) {
  return prompt.fields.find((field) => {
    const isPasswordId = field.id.toLowerCase() === "password";
    const isSecret =
      field.kind.type === "password" || (field.kind.type === "text" && field.kind.secret);
    return isPasswordId && isSecret;
  });
}

function defaultFieldValue(field: AuthPromptField) {
  if (field.kind.type === "select") {
    return field.kind.choices[0]?.value ?? "";
  }

  return "";
}

function emptyToNull(value: string) {
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function splitList(value: string) {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function validateCreateProfileDraft(draft: CreateProfileDraft): CreateProfileFieldErrors {
  const errors: CreateProfileFieldErrors = {};
  const name = draft.name.trim();
  const server = draft.server.trim();

  if (!name) {
    errors.name = "Profile name is required.";
  } else if (!/^[A-Za-z0-9_-]+$/.test(name)) {
    errors.name = "Use letters, numbers, dash, or underscore only.";
  }

  if (!server) {
    errors.server = "Server URL is required.";
  } else {
    try {
      const url = new URL(server);
      if (url.protocol !== "https:") {
        errors.server = "Server URL must use https.";
      } else if (!url.hostname) {
        errors.server = "Server URL must include a host.";
      } else if (url.username || url.password) {
        errors.server = "Server URL must not include username or password.";
      } else if (url.search || url.hash) {
        errors.server = "Server URL must not include query or fragment.";
      }
    } catch {
      errors.server = "Enter a valid https URL.";
    }
  }

  if (draft.savePassword && !draft.vpnPassword.trim()) {
    errors.vpnPassword = "Enter a password or turn off keyring save.";
  }

  const badBypass = splitList(draft.localBypass).find((value) => !isIpv4Cidr(value));
  if (badBypass) {
    errors.localBypass = `${badBypass} is not a valid IPv4 CIDR.`;
  }

  return errors;
}

function isIpv4Cidr(value: string) {
  const [address, prefix] = value.split("/");
  if (!address || !prefix || value.split("/").length !== 2) {
    return false;
  }

  const octets = address.split(".");
  if (octets.length !== 4) {
    return false;
  }

  const validAddress = octets.every((octet) => {
    if (!/^\d+$/.test(octet)) {
      return false;
    }
    const number = Number(octet);
    return number >= 0 && number <= 255;
  });

  if (!validAddress || !/^\d+$/.test(prefix)) {
    return false;
  }

  const prefixLength = Number(prefix);
  return prefixLength >= 0 && prefixLength <= 32;
}

function mapCreateProfileError(message: string): CreateProfileErrorMap {
  const lower = message.toLowerCase();

  if (lower.includes("invalid profile name")) {
    return { formError: null, fieldErrors: { name: message } };
  }

  if (lower.includes("file exists") || lower.includes("already exists")) {
    return { formError: null, fieldErrors: { name: "A profile with this name already exists." } };
  }

  if (lower.includes("server url") || lower.includes("server is required")) {
    return { formError: null, fieldErrors: { server: message } };
  }

  if (lower.includes("reported os")) {
    return { formError: null, fieldErrors: { reportedOs: message } };
  }

  if (lower.includes("username")) {
    return { formError: null, fieldErrors: { username: message } };
  }

  if (lower.includes("authgroup") || lower.includes("auth group")) {
    return { formError: null, fieldErrors: { authgroup: message } };
  }

  if (lower.includes("company domain")) {
    return { formError: null, fieldErrors: { companyDomains: message } };
  }

  if (lower.includes("network policy") || lower.includes("cidr")) {
    return { formError: null, fieldErrors: { localBypass: message } };
  }

  return { formError: message, fieldErrors: {} };
}

function isDaemonSocketError(message: string) {
  const lower = message.toLowerCase();
  return lower.includes("failed to connect daemon socket") || lower.includes("connection refused");
}

async function refreshStatus(dispatch: React.Dispatch<Action>) {
  const exchange = await invoke<IpcExchange>("daemon_status");
  applyExchange(exchange, dispatch);
}

async function refreshDiagnostics(dispatch: React.Dispatch<Action>) {
  const exchange = await invoke<IpcExchange>("daemon_diagnostics");
  applyExchange(exchange, dispatch);
}

function applyExchange(exchange: IpcExchange, dispatch: React.Dispatch<Action>) {
  applyResponse(exchange.response, dispatch);
  for (const event of exchange.events) {
    dispatch({ type: "event", event });
  }
}

function applyResponse(response: IpcResponse, dispatch: React.Dispatch<Action>) {
  switch (response.type) {
    case "status":
      dispatch({
        type: "status",
        status: {
          state: response.state,
          active_profile: response.active_profile,
          interface: response.interface,
        },
      });
      break;
    case "diagnostics":
      dispatch({
        type: "diagnostics",
        diagnostics: {
          state: response.state,
          route_policy: response.route_policy,
          dns_policy: response.dns_policy,
          last_error: response.last_error,
        },
      });
      break;
    case "error":
      dispatch({ type: "error", message: `${response.code}: ${response.message}` });
      break;
    case "accepted":
      dispatch({ type: "log", level: "info", message: "request accepted" });
      break;
  }
}

function spinnerClass(active: boolean) {
  return active ? "h-4 w-4 animate-spin" : "h-4 w-4";
}

function appMarkClass(state: DaemonState) {
  if (state === "connected") {
    return "app-mark-on";
  }

  if (state === "awaiting_auth" || state === "connecting" || state === "configuring") {
    return "animate-app-mark-blink";
  }

  return "app-mark-off";
}

function statusDotClass(state: DaemonState) {
  if (state === "connected") {
    return "bg-primary";
  }

  if (state === "error") {
    return "bg-destructive";
  }

  if (state === "awaiting_auth" || state === "connecting" || state === "configuring") {
    return "bg-[#f39c12]";
  }

  return "bg-[#95a5a6]";
}

function logLevelClass(level: LogEntry["level"]) {
  switch (level) {
    case "error":
      return "font-medium text-red-700";
    case "warn":
      return "font-medium text-amber-700";
    case "info":
      return "font-medium text-muted-foreground";
  }
}

function isTauriRuntime() {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

function invoke<T = unknown>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (!isTauriRuntime()) {
    return Promise.reject(
      new Error("Tauri runtime is unavailable. Start the desktop app with npm run tauri dev."),
    );
  }

  return tauriInvoke<T>(command, args);
}

function formatError(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}
