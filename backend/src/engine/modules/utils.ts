import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

const HOSTNAME_LABEL_REGEX = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
const IPV4_REGEX =
  /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

function isValidHostname(value: string): boolean {
  if (IPV4_REGEX.test(value)) {
    return true;
  }

  const normalized = value.trim().toLowerCase();
  if (!normalized || normalized.length > 253 || normalized.includes('..')) {
    return false;
  }

  return normalized.split('.').every((label) => HOSTNAME_LABEL_REGEX.test(label));
}

export class InvalidScanHostnameError extends Error {
  constructor(public readonly hostname: string) {
    super(`Unsafe or invalid scan hostname: ${hostname}`);
    this.name = 'InvalidScanHostnameError';
  }
}

export function assertSafeScanHostname(hostname: string): string {
  const normalized = hostname.trim().toLowerCase();
  if (!isValidHostname(normalized)) {
    throw new InvalidScanHostnameError(hostname);
  }
  return normalized;
}

export async function safeExecFile(
  command: string,
  args: string[],
  timeoutMs: number = 20000,
): Promise<{ stdout: string; stderr: string; exitCode: number | null }> {
  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      timeout: timeoutMs,
      maxBuffer: 1024 * 1024,
    });
    return { stdout, stderr, exitCode: 0 };
  } catch (err: unknown) {
    const e = err as { stdout?: string; stderr?: string; code?: number | string };
    if (typeof e.stdout === 'string' || typeof e.stderr === 'string') {
      return {
        stdout: e.stdout ?? '',
        stderr: e.stderr ?? '',
        exitCode: typeof e.code === 'number' ? e.code : null,
      };
    }
    throw err;
  }
}
