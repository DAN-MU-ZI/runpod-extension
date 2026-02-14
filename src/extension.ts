import * as vscode from "vscode";
import * as os from "os";
import * as fs from "fs";
import * as path from "path";
import { execFile } from "child_process";

interface RunpodSettings {
  apiKey: string;
  apiBase: string;
  sshAliasPrefix: string;
  sshUser: string;
  remotePath: string;
  pollIntervalMs: number;
  pollTimeoutMs: number;
  autoStartStoppedPod: boolean;
  createPodRequestJson: string;
}

interface RunpodPod extends Record<string, unknown> {
  id?: string;
  name?: string;
  desiredStatus?: string;
  status?: string;
  publicIp?: string;
  portMappings?: unknown;
}

interface PodQuickPickItem extends vscode.QuickPickItem {
  pod: RunpodPod;
}

type OpenWindowMode = "current" | "new";
type HttpMethod = "GET" | "POST" | "DELETE";
const RUNPOD_API_KEY_SECRET_KEY = "runpod.apiKey";

export function activate(context: vscode.ExtensionContext): void {
  const output = vscode.window.createOutputChannel("RunPod");
  context.subscriptions.push(output);

  context.subscriptions.push(
    vscode.commands.registerCommand("runpod.setApiKey", async () => {
      await setApiKeyCommand(context);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("runpod.connectPod", async () => {
      await runCommandWithErrors("connect", context, output, connectPodCommand);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("runpod.createPod", async () => {
      await runCommandWithErrors("create", context, output, createPodCommand);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("runpod.stopPod", async () => {
      await runCommandWithErrors("stop", context, output, stopPodCommand);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("runpod.terminatePod", async () => {
      await runCommandWithErrors("terminate", context, output, terminatePodCommand);
    })
  );
}

export function deactivate(): void {
  // no-op
}

async function runCommandWithErrors(
  commandName: string,
  context: vscode.ExtensionContext,
  output: vscode.OutputChannel,
  operation: (settings: RunpodSettings, output: vscode.OutputChannel) => Promise<void>
): Promise<void> {
  const settings = readSettings();
  settings.apiKey = await resolveApiKey(context, settings.apiKey);
  const apiKeyPresent = await ensureApiKey(settings.apiKey, context);
  if (!apiKeyPresent) {
    return;
  }

  try {
    await operation(settings, output);
  } catch (error) {
    const message = `RunPod ${commandName} failed: ${toErrorMessage(error)}`;
    output.appendLine(`[error] ${message}`);
    vscode.window.showErrorMessage(message);
  }
}

async function setApiKeyCommand(context: vscode.ExtensionContext): Promise<void> {
  const hasExisting = Boolean(await context.secrets.get(RUNPOD_API_KEY_SECRET_KEY));
  const value = await vscode.window.showInputBox({
    prompt: hasExisting
      ? "Enter RunPod API Key (existing key will be replaced)"
      : "Enter RunPod API Key",
    placeHolder: "rpa_...",
    password: true,
    ignoreFocusOut: true
  });

  if (value === undefined) {
    return;
  }

  const trimmed = value.trim();
  if (!trimmed) {
    vscode.window.showErrorMessage("API key cannot be empty.");
    return;
  }

  await context.secrets.store(RUNPOD_API_KEY_SECRET_KEY, trimmed);
  vscode.window.showInformationMessage("RunPod API key saved in SecretStorage.");
}

async function connectPodCommand(
  settings: RunpodSettings,
  output: vscode.OutputChannel
): Promise<void> {
  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "RunPod: Connect Pod",
      cancellable: true
    },
    async (progress, token) => {
      progress.report({ message: "Fetching pods..." });
      const pods = await listPods(settings, token, output);

      if (pods.length === 0) {
        vscode.window.showWarningMessage("No pods found in your RunPod account.");
        return;
      }

      const pick = await vscode.window.showQuickPick(
        pods
          .slice()
          .sort(comparePodsForConnect)
          .map((pod) => toConnectQuickPickItem(pod)),
        { placeHolder: "Select pod to connect" }
      );

      if (!pick) {
        return;
      }

      const selectedPodId = getPodId(pick.pod);
      const selectedStatus = getPodStatus(pick.pod);
      if (isStoppedStatus(selectedStatus)) {
        if (!settings.autoStartStoppedPod) {
          throw new Error(
            "Selected pod is stopped. Enable runpod.autoStartStoppedPod or start it manually."
          );
        }
        progress.report({ message: "Selected pod is stopped. Start will be requested while polling." });
      }

      progress.report({ message: "Waiting for SSH endpoint..." });
      const readyPod = await pollSshReady(
        settings,
        selectedPodId,
        token,
        (message) => progress.report({ message }),
        output
      );

      const endpoint = extractSshEndpoint(readyPod);
      if (!endpoint.host || !endpoint.sshPort) {
        throw new Error("Could not resolve SSH host/port from pod detail response.");
      }

      const alias = buildAlias(
        settings.sshAliasPrefix,
        getPodName(readyPod),
        endpoint.host,
        selectedPodId
      );

      const openMode = await pickOpenWindowMode();
      if (!openMode) {
        return;
      }

      ensureSshAlias(alias, endpoint.host, endpoint.sshPort, settings.sshUser, output);
      await openVsCodeRemote(alias, settings.remotePath, openMode, output);

      output.appendLine(
        `[connect] ${alias} -> ${endpoint.host}:${endpoint.sshPort} podId=${selectedPodId} mode=${openMode}`
      );
      vscode.window.showInformationMessage(
        `Connected: ${alias} (${endpoint.host}:${endpoint.sshPort})`
      );
    }
  );
}

async function pickOpenWindowMode(): Promise<OpenWindowMode | undefined> {
  const pick = await vscode.window.showQuickPick(
    [
      {
        label: "Current Window",
        description: "Replace current workspace with this remote connection",
        mode: "current" as OpenWindowMode
      },
      {
        label: "New Window",
        description: "Open the remote connection in a new VS Code window",
        mode: "new" as OpenWindowMode
      }
    ],
    {
      placeHolder: "Choose where to open the remote pod"
    }
  );

  return pick?.mode;
}

async function createPodCommand(
  settings: RunpodSettings,
  output: vscode.OutputChannel
): Promise<void> {
  const rawJson = settings.createPodRequestJson.trim();
  if (!rawJson) {
    const choice = await vscode.window.showErrorMessage(
      "Set runpod.createPodRequestJson with a valid create-pod JSON body first.",
      "Open Settings"
    );
    if (choice === "Open Settings") {
      await vscode.commands.executeCommand(
        "workbench.action.openSettings",
        "runpod.createPodRequestJson"
      );
    }
    return;
  }

  const payload = parseJsonObject(rawJson, "runpod.createPodRequestJson");
  const overrideName = await vscode.window.showInputBox({
    prompt: "Pod name override (optional)",
    placeHolder: "Leave empty to use name from runpod.createPodRequestJson"
  });
  if (typeof overrideName === "string" && overrideName.trim()) {
    payload.name = overrideName.trim();
  }

  const created = (await httpJson(
    "POST",
    buildApiUrl(settings.apiBase, "/pods"),
    settings.apiKey,
    undefined,
    payload
  )) as unknown;
  const createdPod = parsePodDetail(created);
  const createdId = getPodId(createdPod);
  output.appendLine(`[create] podId=${createdId}`);
  vscode.window.showInformationMessage(`Pod created: ${createdId}`);
}

async function stopPodCommand(
  settings: RunpodSettings,
  output: vscode.OutputChannel
): Promise<void> {
  const pod = await pickPod(settings, output, "Select pod to stop");
  if (!pod) {
    return;
  }

  const podId = getPodId(pod);
  const status = getPodStatus(pod);
  if (isStoppedStatus(status)) {
    vscode.window.showInformationMessage(`Pod is already stopped: ${getPodName(pod)}`);
    return;
  }

  const confirm = await vscode.window.showWarningMessage(
    `Stop pod "${getPodName(pod)}"?`,
    { modal: true },
    "Stop"
  );
  if (confirm !== "Stop") {
    return;
  }

  await postPodAction(settings, podId, "stop", undefined, output);
  output.appendLine(`[stop] podId=${podId}`);
  vscode.window.showInformationMessage(`Stop requested: ${getPodName(pod)}`);
}

async function terminatePodCommand(
  settings: RunpodSettings,
  output: vscode.OutputChannel
): Promise<void> {
  const pod = await pickPod(settings, output, "Select pod to terminate");
  if (!pod) {
    return;
  }

  const podId = getPodId(pod);
  const confirm = await vscode.window.showWarningMessage(
    `Terminate pod "${getPodName(pod)}"? This cannot be undone.`,
    { modal: true },
    "Terminate"
  );
  if (confirm !== "Terminate") {
    return;
  }

  await httpJson(
    "DELETE",
    buildApiUrl(settings.apiBase, `/pods/${encodeURIComponent(podId)}`),
    settings.apiKey
  );
  output.appendLine(`[terminate] podId=${podId}`);
  vscode.window.showInformationMessage(`Terminate requested: ${getPodName(pod)}`);
}

async function pickPod(
  settings: RunpodSettings,
  output: vscode.OutputChannel,
  placeHolder: string
): Promise<RunpodPod | undefined> {
  const pods = await listPods(settings, undefined, output);
  if (pods.length === 0) {
    vscode.window.showWarningMessage("No pods found.");
    return undefined;
  }

  const pick = await vscode.window.showQuickPick(
    pods
      .slice()
      .sort(comparePodsForConnect)
      .map((pod) => toConnectQuickPickItem(pod)),
    { placeHolder }
  );
  return pick?.pod;
}

async function listPods(
  settings: RunpodSettings,
  token: vscode.CancellationToken | undefined,
  output: vscode.OutputChannel
): Promise<RunpodPod[]> {
  const raw = await httpJson(
    "GET",
    buildApiUrl(settings.apiBase, "/pods"),
    settings.apiKey,
    token
  );
  const pods = parsePodList(raw);
  output.appendLine(`[api] pods fetched: ${pods.length}`);
  return pods;
}

async function postPodAction(
  settings: RunpodSettings,
  podId: string,
  action: "start" | "stop",
  token: vscode.CancellationToken | undefined,
  output: vscode.OutputChannel
): Promise<void> {
  const url = buildApiUrl(
    settings.apiBase,
    `/pods/${encodeURIComponent(podId)}/${action}`
  );
  await httpJson("POST", url, settings.apiKey, token);
  output.appendLine(`[api] ${action} requested for podId=${podId}`);
}

async function pollSshReady(
  settings: RunpodSettings,
  podId: string,
  token: vscode.CancellationToken,
  onMessage: (message: string) => void,
  output: vscode.OutputChannel
): Promise<RunpodPod> {
  const startTime = Date.now();
  let startRequestedByPoll = false;

  while (Date.now() - startTime < settings.pollTimeoutMs) {
    if (token.isCancellationRequested) {
      throw new Error("Cancelled by user.");
    }

    const podRaw = await httpJson(
      "GET",
      buildApiUrl(settings.apiBase, `/pods/${encodeURIComponent(podId)}`),
      settings.apiKey,
      token
    );
    const pod = parsePodDetail(podRaw);
    const status = getPodStatus(pod);
    const endpoint = extractSshEndpoint(pod);

    onMessage(`status=${status} host=${endpoint.host ?? "-"} ssh=${endpoint.sshPort ?? "-"}`);
    output.appendLine(
      `[poll] podId=${podId} status=${status} host=${endpoint.host ?? "-"} ssh=${endpoint.sshPort ?? "-"}`
    );

    if (isRunningStatus(status) && endpoint.host && endpoint.sshPort) {
      return pod;
    }

    if (
      isStoppedStatus(status) &&
      settings.autoStartStoppedPod &&
      !startRequestedByPoll
    ) {
      await postPodAction(settings, podId, "start", token, output);
      startRequestedByPoll = true;
      onMessage("Pod was stopped, start requested.");
    }

    await sleep(settings.pollIntervalMs, token);
  }

  throw new Error(`Timed out waiting for SSH readiness after ${settings.pollTimeoutMs}ms.`);
}

function toConnectQuickPickItem(pod: RunpodPod): PodQuickPickItem {
  const status = getPodStatus(pod);
  const gpu = getGpuLabel(pod);
  const region = getRegionLabel(pod);
  const cloudType = getCloudTypeLabel(pod);
  const cost = getCostLabel(pod);
  const podId = getPodId(pod);

  return {
    label: getPodName(pod),
    description: `${status} | ${gpu}`,
    detail: `${region} | ${cloudType} | ${cost} | ${podId}`,
    pod
  };
}

function comparePodsForConnect(a: RunpodPod, b: RunpodPod): number {
  const score = (pod: RunpodPod): number => {
    const status = getPodStatus(pod);
    if (isRunningStatus(status)) {
      return 0;
    }
    if (isStoppedStatus(status)) {
      return 2;
    }
    return 1;
  };
  const delta = score(a) - score(b);
  if (delta !== 0) {
    return delta;
  }
  return getPodName(a).localeCompare(getPodName(b));
}

function extractSshEndpoint(pod: RunpodPod): { host?: string; sshPort?: number } {
  const host =
    pickString(pod.publicIp) ??
    pickString(getPath(pod, ["machine", "publicIp"])) ??
    pickString(getPath(pod, ["runtime", "publicIp"])) ??
    pickString(getPath(pod, ["network", "publicIp"]));
  const sshPort = parseSshPort(pod.portMappings ?? getPath(pod, ["runtime", "portMappings"]));
  return { host, sshPort };
}

function parseSshPort(portMappings: unknown): number | undefined {
  if (typeof portMappings === "number") {
    return normalizePort(portMappings);
  }

  if (typeof portMappings === "string") {
    return normalizePort(Number(portMappings));
  }

  if (Array.isArray(portMappings)) {
    for (const entry of portMappings) {
      if (!isRecord(entry)) {
        continue;
      }
      const privatePort = pickNumber(
        entry.privatePort,
        entry.containerPort,
        entry.internalPort,
        entry.port
      );
      const publicPort = pickNumber(
        entry.publicPort,
        entry.hostPort,
        entry.externalPort,
        entry.exposedPort
      );
      if (privatePort === 22 && publicPort) {
        return normalizePort(publicPort);
      }
      if (privatePort === undefined && publicPort) {
        const guessed = parseSshPort(entry);
        if (guessed) {
          return guessed;
        }
      }
    }
    return undefined;
  }

  if (!isRecord(portMappings)) {
    return undefined;
  }

  const direct = pickNumber(
    portMappings["22"],
    portMappings["22/tcp"],
    portMappings.ssh,
    portMappings.sshPort
  );
  if (direct) {
    return normalizePort(direct);
  }

  for (const [key, value] of Object.entries(portMappings)) {
    if (!key.includes("22")) {
      continue;
    }

    const port = pickNumber(value);
    if (port) {
      return normalizePort(port);
    }

    if (Array.isArray(value)) {
      for (const nested of value) {
        const nestedPort = pickNumber(nested);
        if (nestedPort) {
          return normalizePort(nestedPort);
        }
      }
    }

    if (isRecord(value)) {
      const nestedPort = pickNumber(
        value.publicPort,
        value.hostPort,
        value.externalPort,
        value.port
      );
      if (nestedPort) {
        return normalizePort(nestedPort);
      }
    }
  }

  return undefined;
}

function ensureSshAlias(
  alias: string,
  host: string,
  port: number,
  user: string,
  output: vscode.OutputChannel
): void {
  const sshDir = path.join(os.homedir(), ".ssh");
  const sshConfigPath = path.join(sshDir, "config");
  const knownHostsPath = path.join(sshDir, "known_hosts_runpod");

  fs.mkdirSync(sshDir, { recursive: true });
  const existing = fs.existsSync(sshConfigPath)
    ? fs.readFileSync(sshConfigPath, "utf8")
    : "";

  const beginMarker = `# >>> runpod-extension ${alias} >>>`;
  const endMarker = `# <<< runpod-extension ${alias} <<<`;
  const block = [
    beginMarker,
    `Host ${alias}`,
    `  HostName ${host}`,
    `  User ${user}`,
    `  Port ${port}`,
    "  ServerAliveInterval 30",
    "  ServerAliveCountMax 6",
    "  StrictHostKeyChecking accept-new",
    `  UserKnownHostsFile ${toSshPath(knownHostsPath)}`,
    endMarker,
    ""
  ].join("\n");

  const escapedBegin = escapeRegExp(beginMarker);
  const escapedEnd = escapeRegExp(endMarker);
  const managedBlockPattern = new RegExp(
    `${escapedBegin}[\\s\\S]*?${escapedEnd}\\n?`,
    "g"
  );
  const hostAliasPattern = new RegExp(
    `^Host\\s+${escapeRegExp(alias)}\\b[\\s\\S]*?(?=^Host\\s+|\\Z)`,
    "gm"
  );
  const withoutManagedBlocks = existing.replace(managedBlockPattern, "");
  const stripped = withoutManagedBlocks.replace(hostAliasPattern, "").trimEnd();
  const next = (stripped ? `${stripped}\n\n` : "") + block;
  fs.writeFileSync(sshConfigPath, next, "utf8");
  output.appendLine(`[ssh] updated alias ${alias} in ${sshConfigPath}`);
}

async function openVsCodeRemote(
  alias: string,
  remotePath: string,
  openMode: OpenWindowMode,
  output: vscode.OutputChannel
): Promise<void> {
  const normalizedPath = remotePath.startsWith("/") ? remotePath : `/${remotePath}`;
  const folderUri = `vscode-remote://ssh-remote+${alias}${normalizedPath}`;
  const cliWindowArg = openMode === "new" ? "--new-window" : "--reuse-window";
  const forceNewWindow = openMode === "new";

  try {
    const executable = process.platform === "win32" ? "code.cmd" : "code";
    await execFileAsync(executable, [cliWindowArg, "--folder-uri", folderUri]);
    output.appendLine(`[open] launched via CLI: ${folderUri}`);
    return;
  } catch (error) {
    output.appendLine(`[open] CLI failed, fallback to vscode.openFolder: ${toErrorMessage(error)}`);
  }

  await vscode.commands.executeCommand(
    "vscode.openFolder",
    vscode.Uri.parse(folderUri),
    forceNewWindow
  );
  output.appendLine(`[open] launched via vscode.openFolder: ${folderUri}`);
}

function parsePodList(raw: unknown): RunpodPod[] {
  if (Array.isArray(raw)) {
    return raw.filter(isRecord).map(parsePodDetail);
  }

  if (!isRecord(raw)) {
    throw new Error("Unexpected pod list response shape.");
  }

  const candidates = [raw.pods, raw.data, raw.items, getPath(raw, ["data", "pods"])];
  for (const candidate of candidates) {
    if (!Array.isArray(candidate)) {
      continue;
    }
    return candidate.filter(isRecord).map(parsePodDetail);
  }

  throw new Error("Could not find pod list in API response.");
}

function parsePodDetail(raw: unknown): RunpodPod {
  if (!isRecord(raw)) {
    throw new Error("Unexpected pod detail response shape.");
  }

  if (looksLikePodRecord(raw)) {
    return raw as RunpodPod;
  }

  const candidates = [
    raw.pod,
    raw.item,
    raw.data,
    getPath(raw, ["data", "pod"]),
    getPath(raw, ["data", "item"]),
    getPath(raw, ["pod", "data"])
  ];

  for (const candidate of candidates) {
    if (!isRecord(candidate)) {
      continue;
    }
    if (looksLikePodRecord(candidate)) {
      return candidate as RunpodPod;
    }
  }

  throw new Error("Could not locate pod object in detail response.");
}

async function ensureApiKey(
  apiKey: string,
  context: vscode.ExtensionContext
): Promise<boolean> {
  if (apiKey.trim()) {
    return true;
  }

  const choice = await vscode.window.showErrorMessage(
    "RunPod API key is not set.",
    "Set API Key",
    "Open Settings"
  );
  if (choice === "Set API Key") {
    await setApiKeyCommand(context);
    const refreshed = await resolveApiKey(context, readSettings().apiKey);
    return refreshed.trim().length > 0;
  }
  if (choice === "Open Settings") {
    await vscode.commands.executeCommand("workbench.action.openSettings", "runpod.apiKey");
  }
  return false;
}

async function resolveApiKey(
  context: vscode.ExtensionContext,
  fallbackApiKey: string
): Promise<string> {
  const secret = await context.secrets.get(RUNPOD_API_KEY_SECRET_KEY);
  if (secret?.trim()) {
    return secret.trim();
  }
  return fallbackApiKey.trim();
}

function readSettings(): RunpodSettings {
  const config = vscode.workspace.getConfiguration();
  return {
    apiKey: config.get<string>("runpod.apiKey", ""),
    apiBase: config.get<string>("runpod.apiBase", "https://rest.runpod.io/v1"),
    sshAliasPrefix: config.get<string>("runpod.sshAliasPrefix", "runpod-"),
    sshUser: config.get<string>("runpod.sshUser", "root"),
    remotePath: config.get<string>("runpod.remotePath", "/workspace"),
    pollIntervalMs: config.get<number>("runpod.pollIntervalMs", 3000),
    pollTimeoutMs: config.get<number>("runpod.pollTimeoutMs", 600000),
    autoStartStoppedPod: config.get<boolean>("runpod.autoStartStoppedPod", true),
    createPodRequestJson: config.get<string>("runpod.createPodRequestJson", "")
  };
}

function buildApiUrl(apiBase: string, endpoint: string): string {
  const base = apiBase.replace(/\/+$/, "");
  const suffix = endpoint.startsWith("/") ? endpoint : `/${endpoint}`;
  return `${base}${suffix}`;
}

async function httpJson(
  method: HttpMethod,
  url: string,
  apiKey: string,
  token?: vscode.CancellationToken,
  body?: unknown
): Promise<unknown> {
  const controller = new AbortController();
  const cancellation = token?.onCancellationRequested(() => controller.abort());

  try {
    const response = await fetch(url, {
      method,
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json"
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal
    });

    const rawText = await response.text();
    const payload = rawText ? safeJsonParse(rawText) : null;
    if (!response.ok) {
      const details =
        typeof payload === "string"
          ? payload
          : JSON.stringify(payload ?? {});
      throw new Error(`HTTP ${response.status}: ${details}`);
    }
    return payload;
  } catch (error) {
    if (isAbortError(error)) {
      throw new Error("Request cancelled.");
    }
    throw error;
  } finally {
    cancellation?.dispose();
  }
}

async function execFileAsync(command: string, args: string[]): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    execFile(command, args, (error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}

async function sleep(ms: number, token?: vscode.CancellationToken): Promise<void> {
  if (token?.isCancellationRequested) {
    throw new Error("Cancelled by user.");
  }

  await new Promise<void>((resolve, reject) => {
    let cancellation: vscode.Disposable | undefined;
    const timer = setTimeout(() => {
      cancellation?.dispose();
      resolve();
    }, ms);

    cancellation = token?.onCancellationRequested(() => {
      clearTimeout(timer);
      cancellation?.dispose();
      reject(new Error("Cancelled by user."));
    });
  });
}

function buildAlias(
  prefix: string,
  podName: string,
  host: string,
  podId: string
): string {
  const namePart = sanitizeAliasSegment(podName);
  const fallback = sanitizeAliasSegment(host) || "pod";
  const compactId = podId.toLowerCase().replace(/[^a-z0-9]/g, "");
  const idSuffix = compactId.slice(-8) || "00000000";
  return `${prefix}${namePart || fallback}-${idSuffix}`;
}

function getPodId(pod: RunpodPod): string {
  const value = pickString(pod.id, pod.podId, getPath(pod, ["pod", "id"]));
  if (!value) {
    throw new Error("Pod id is missing in API response.");
  }
  return value;
}

function getPodName(pod: RunpodPod): string {
  return (
    pickString(pod.name, getPath(pod, ["pod", "name"])) ??
    getPodId(pod)
  );
}

function getPodStatus(pod: RunpodPod): string {
  return (
    pickString(pod.desiredStatus, pod.status, getPath(pod, ["runtime", "status"])) ??
    "UNKNOWN"
  ).toUpperCase();
}

function getGpuLabel(pod: RunpodPod): string {
  return (
    pickString(
      pod.gpuTypeId,
      getPath(pod, ["machine", "gpuType", "displayName"]),
      getPath(pod, ["machine", "gpuDisplayName"]),
      getPath(pod, ["machine", "gpuTypeId"])
    ) ?? "GPU?"
  );
}

function getRegionLabel(pod: RunpodPod): string {
  return (
    pickString(
      pod.region,
      pod.dataCenterId,
      getPath(pod, ["machine", "location"]),
      getPath(pod, ["machine", "region"])
    ) ?? "Region?"
  );
}

function getCloudTypeLabel(pod: RunpodPod): string {
  if (typeof pod.secureCloud === "boolean") {
    return pod.secureCloud ? "SECURE" : "COMMUNITY";
  }
  return pickString(pod.cloudType, getPath(pod, ["machine", "cloudType"])) ?? "Cloud?";
}

function getCostLabel(pod: RunpodPod): string {
  const value = pickNumber(
    pod.adjustedCostPerHr,
    pod.costPerHr,
    getPath(pod, ["machine", "costPerHr"])
  );
  if (!value) {
    return "Cost?";
  }
  return `$${value.toFixed(3)}/hr`;
}

function isRunningStatus(status: string): boolean {
  return status.includes("RUNNING");
}

function isStoppedStatus(status: string): boolean {
  return (
    status.includes("STOPPED") ||
    status.includes("EXITED") ||
    status.includes("PAUSED")
  );
}

function parseJsonObject(raw: string, sourceLabel: string): Record<string, unknown> {
  const parsed = safeJsonParse(raw);
  if (!isRecord(parsed)) {
    throw new Error(`${sourceLabel} must be a JSON object.`);
  }
  return parsed;
}

function safeJsonParse(raw: string): unknown {
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

function toSshPath(rawPath: string): string {
  return rawPath.replace(/\\/g, "/");
}

function sanitizeAliasSegment(raw: string): string {
  return raw
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-+/, "")
    .replace(/-+$/, "");
}

function pickString(...values: unknown[]): string | undefined {
  for (const value of values) {
    if (typeof value === "string") {
      const trimmed = value.trim();
      if (trimmed) {
        return trimmed;
      }
    }
  }
  return undefined;
}

function pickNumber(...values: unknown[]): number | undefined {
  for (const value of values) {
    if (typeof value === "number" && Number.isFinite(value)) {
      return value;
    }
    if (typeof value === "string" && value.trim()) {
      const parsed = Number(value);
      if (Number.isFinite(parsed)) {
        return parsed;
      }
    }
    if (isRecord(value)) {
      const nested = pickNumber(
        value.publicPort,
        value.hostPort,
        value.externalPort,
        value.port,
        value.value
      );
      if (nested !== undefined) {
        return nested;
      }
    }
    if (Array.isArray(value)) {
      for (const item of value) {
        const nested = pickNumber(item);
        if (nested !== undefined) {
          return nested;
        }
      }
    }
  }
  return undefined;
}

function normalizePort(value: number): number | undefined {
  if (!Number.isInteger(value)) {
    return undefined;
  }
  if (value < 1 || value > 65535) {
    return undefined;
  }
  return value;
}

function getPath(value: unknown, segments: string[]): unknown {
  let cursor: unknown = value;
  for (const segment of segments) {
    if (!isRecord(cursor)) {
      return undefined;
    }
    cursor = cursor[segment];
  }
  return cursor;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isAbortError(error: unknown): boolean {
  if (error instanceof Error) {
    return error.name === "AbortError";
  }
  return false;
}

function escapeRegExp(raw: string): string {
  return raw.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function looksLikePodRecord(value: Record<string, unknown>): boolean {
  return Boolean(
    pickString(
      value.id,
      value.name,
      value.status,
      value.desiredStatus,
      getPath(value, ["pod", "id"])
    ) ||
      value.publicIp !== undefined ||
      value.portMappings !== undefined ||
      getPath(value, ["runtime", "publicIp"]) !== undefined ||
      getPath(value, ["runtime", "portMappings"]) !== undefined
  );
}

function toErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}
