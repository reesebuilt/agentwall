import { isAbsolute, basename, relative, resolve } from "path";
import { z } from "zod";

const SHELL_SYNTAX = /[\0\r\n;&|`$<>]/;
const EXECUTABLE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

export const TypedCommandActionSchema = z.object({
  command: z.string().min(1).max(128),
  args: z.array(z.string().max(8_192)).max(256),
  confirm: z.boolean(),
  workingDirectory: z.string().min(1).max(4_096).optional(),
}).strict();

export type TypedCommandAction = z.infer<typeof TypedCommandActionSchema>;

export interface CommandAllowlistOptions {
  workingDirectoryRoot: string;
  agentwallBinary?: string;
  sandboxLauncher?: string;
  mcpBinaries?: Readonly<Record<string, string>>;
}

export interface ResolvedTypedCommandAction extends Omit<TypedCommandAction, "workingDirectory"> {
  command: string;
  workingDirectory: string;
}

function declaredBinaries(options: CommandAllowlistOptions): Map<string, string> {
  const declared = new Map<string, string>();
  if (options.agentwallBinary) declared.set("agentwall", options.agentwallBinary);
  if (options.sandboxLauncher) {
    declared.set(basename(options.sandboxLauncher), options.sandboxLauncher);
  }
  for (const [name, executable] of Object.entries(options.mcpBinaries ?? {})) {
    declared.set(name, executable);
  }
  return declared;
}

export function resolveTypedCommandAction(
  input: unknown,
  options: CommandAllowlistOptions,
): ResolvedTypedCommandAction {
  const parsed = TypedCommandActionSchema.safeParse(input);
  if (!parsed.success) {
    throw new Error("Typed command fields are invalid.");
  }

  const action = parsed.data;
  if (SHELL_SYNTAX.test(action.command)) {
    throw new Error("The command contains shell syntax.");
  }
  if (!EXECUTABLE_NAME.test(action.command)) {
    throw new Error("The command must be a declared executable name, not a path.");
  }
  for (const arg of action.args) {
    if (SHELL_SYNTAX.test(arg)) {
      throw new Error("A command argument contains shell syntax.");
    }
    if (arg.split(/[\\/]+/).includes("..")) {
      throw new Error("A command argument contains path traversal.");
    }
  }

  const executable = declaredBinaries(options).get(action.command);
  if (!executable) {
    throw new Error(`The executable "${action.command}" is not declared.`);
  }
  if (!isAbsolute(executable)) {
    throw new Error(`The declared executable "${action.command}" must resolve to an absolute path.`);
  }

  const root = resolve(options.workingDirectoryRoot);
  const requestedDirectory = action.workingDirectory ?? ".";
  if (isAbsolute(requestedDirectory) || requestedDirectory.split(/[\\/]+/).includes("..")) {
    throw new Error("The working directory must stay inside the configured root.");
  }
  const workingDirectory = resolve(root, requestedDirectory);
  const fromRoot = relative(root, workingDirectory);
  if (fromRoot.startsWith("..") || isAbsolute(fromRoot)) {
    throw new Error("The working directory must stay inside the configured root.");
  }

  return {
    command: executable,
    args: [...action.args],
    confirm: action.confirm,
    workingDirectory,
  };
}

export const validateTypedCommandAction = resolveTypedCommandAction;
