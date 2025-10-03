import { runPromise } from "socket-function/src/runPromise";

export interface ProcessConnection {
    pid: number;
    processName: string;
    foreignAddress: string;
    foreignPort: number;
    localAddress: string;
    localPort: number;
    state: string;
}

/**
 * Parse ss -tanp output to extract connections to a specific IP with process info
 */
export function parseConnectionsToTarget(ssOutput: string, targetIp: string): ProcessConnection[] {
    const lines = ssOutput.split('\n');
    const connections: ProcessConnection[] = [];

    for (const line of lines) {
        // Skip empty lines and headers
        if (!line.trim() || line.includes('Peer Address') || line.includes('State')) {
            continue;
        }

        // ss -tanp output: State Recv-Q Send-Q Local-Address:Port Peer-Address:Port Process
        const parts = line.trim().split(/\s+/);

        if (parts.length >= 5) {
            const state = parts[0];
            const localAddrPort = parts[3];
            const foreignAddrPort = parts[4];
            const processInfo = parts.slice(5).join(' ');

            if (localAddrPort && localAddrPort.includes(':') && foreignAddrPort && foreignAddrPort.includes(':')) {
                // Parse local address and port
                const localColonIndex = localAddrPort.lastIndexOf(':');
                const localAddress = localAddrPort.substring(0, localColonIndex);
                const localPort = parseInt(localAddrPort.substring(localColonIndex + 1), 10);

                // Parse foreign address and port
                const foreignColonIndex = foreignAddrPort.lastIndexOf(':');
                const foreignAddress = foreignAddrPort.substring(0, foreignColonIndex);
                const foreignPort = parseInt(foreignAddrPort.substring(foreignColonIndex + 1), 10);

                // Check if this connection is to our target IP
                if (foreignAddress === targetIp) {
                    // Extract PID and process name from process info
                    // Format is typically: users:(("processname",pid=1234,fd=5))
                    let pid = 0;
                    let processName = 'unknown';

                    const pidMatch = processInfo.match(/pid=(\d+)/);
                    if (pidMatch) {
                        pid = parseInt(pidMatch[1], 10);
                    }

                    const nameMatch = processInfo.match(/\("([^"]+)"/);
                    if (nameMatch) {
                        processName = nameMatch[1];
                    }

                    connections.push({
                        pid,
                        processName,
                        foreignAddress,
                        foreignPort,
                        localAddress,
                        localPort,
                        state
                    });
                }
            }
        }
    }

    return connections;
}

/**
 * Get command line arguments for a process by PID
 */
export async function getProcessCmdline(remote: string, pid: number): Promise<string[]> {
    const cmdlineCommand = `ssh ${remote} "sudo cat /proc/${pid}/cmdline"`;
    const cmdline = await runPromise(cmdlineCommand, { quiet: true });
    // Split by null terminators and filter out empty strings
    return cmdline.split('\0').filter(arg => arg.length > 0);
}

/**
 * Get all process information for connections to a target IP
 */
export async function getProcessInfoForTarget(remote: string, targetIp: string): Promise<void> {
    // Run SSH command to get ss output with process info (only established connections)
    const sshCommand = `ssh ${remote} "sudo ss -tanp"`;
    const result = await runPromise(sshCommand, { quiet: true });

    // Parse and extract connections to target IP
    const connections = parseConnectionsToTarget(result, targetIp);

    if (connections.length === 0) {
        return;
    }

    // Get unique PIDs
    const uniquePids = [...new Set(connections.map(c => c.pid).filter(pid => pid > 0))];

    // For each PID, get the command line arguments
    for (const pid of uniquePids) {
        try {
            const args = await getProcessCmdline(remote, pid);
            console.log(pid, JSON.stringify(args));
        } catch (e) {
            // Skip processes that have ended
        }
    }
}

