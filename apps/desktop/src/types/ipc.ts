export type DaemonState =
  | "idle"
  | "configuring"
  | "awaiting_auth"
  | "connecting"
  | "connected"
  | "disconnecting"
  | "disconnected"
  | "error";

export type DaemonStatus = {
  state: DaemonState;
  active_profile: string | null;
  interface: string | null;
};

export type IpcErrorResponse = {
  code: string;
  message: string;
};

export type DiagnosticsSnapshot = {
  state: DaemonState;
  route_policy: string | null;
  dns_policy: string | null;
  last_error: IpcErrorResponse | null;
};

export type AuthChoice = {
  value: string;
  label: string;
};

export type AuthPromptFieldKind =
  | { type: "text"; secret: boolean }
  | { type: "password" }
  | { type: "otp" }
  | { type: "select"; choices: AuthChoice[] };

export type AuthPromptField = {
  id: string;
  label: string;
  kind: AuthPromptFieldKind;
  required: boolean;
};

export type AuthPrompt = {
  form_id: string;
  title: string;
  message: string | null;
  error?: string | null;
  fields: AuthPromptField[];
};

export type AuthSubmittedField = {
  id: string;
  value: string;
  secret: boolean;
};

export type NetworkApplied = {
  route_commands: number;
  dns_commands: number;
};

export type ProgressUpdate = {
  level: number;
  message: string;
};

export type DisconnectReason =
  | "user_requested"
  | "server_requested"
  | "auth_failed"
  | "network_error"
  | "unknown";

export type IpcEvent =
  | { type: "progress"; level: number; message: string }
  | { type: "auth_prompt"; form_id: string; title: string; message: string | null; error?: string | null; fields: AuthPromptField[] }
  | { type: "auth_rejected"; form_id: string | null; message: string }
  | { type: "connected"; interface: string }
  | { type: "network_applied"; route_commands: number; dns_commands: number }
  | { type: "stats"; rx_bytes: number; tx_bytes: number }
  | { type: "disconnecting" }
  | { type: "disconnected"; reason: DisconnectReason }
  | { type: "event_error"; code: string; message: string };

export type IpcResponse =
  | { type: "accepted" }
  | { type: "status"; state: DaemonState; active_profile: string | null; interface: string | null }
  | { type: "diagnostics"; state: DaemonState; route_policy: string | null; dns_policy: string | null; last_error: IpcErrorResponse | null }
  | { type: "error"; code: string; message: string };

export type IpcExchange = {
  response: IpcResponse;
  events: IpcEvent[];
};
