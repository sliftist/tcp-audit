import { magenta } from "socket-function/src/formatting/logColors";
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

export interface ProcessInfo {
    pid: number;
    processName: string;
    args: string[];
}

export interface AddressProcessMap {
    [address: string]: ProcessInfo[];
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
 * Get all command line arguments for all processes on a remote
 * Returns a map of PID -> args[]
 */
export async function getAllCmdlines(remote: string): Promise<Map<number, string[]>> {
    const cmd = `find /proc -maxdepth 2 -name cmdline -type f 2>/dev/null | while read f; do pid=$(echo $f | cut -d/ -f3); echo -n "$pid:"; cat "$f" 2>/dev/null; echo; done`;

    try {
        const result = await runPromise(`ssh ${remote} "${cmd}"`, { quiet: true });

        const pidMap = new Map<number, string[]>();
        const lines = result.split('\n');

        for (const line of lines) {
            if (!line.trim()) continue;

            const colonIdx = line.indexOf(':');
            if (colonIdx === -1) continue;

            const pidStr = line.substring(0, colonIdx);
            const pid = parseInt(pidStr, 10);
            if (isNaN(pid)) continue;

            const cmdlineData = line.substring(colonIdx + 1);
            const args = cmdlineData.split('\0').filter(arg => arg.length > 0);
            pidMap.set(pid, args);
        }

        return pidMap;
    } catch (e) {
        console.error(e);
        return new Map();
    }
}

/**
 * Get all process information for all connections
 */
export async function getAllProcessInfo(remote: string, addresses: string[]): Promise<AddressProcessMap> {
    const result: AddressProcessMap = {};
    console.log(`Getting process info for ${addresses.length} addresses`);

    // Get all cmdlines once
    const cmdlineMap = await getAllCmdlines(remote);

    // Get listening sockets with process info
    const listenResult = await runPromise(`ssh ${remote} "sudo ss -tlnp"`, { quiet: true });
    // Get established connections with process info
    const establishedResult = await runPromise(`ssh ${remote} "sudo ss -tanp"`, { quiet: true });

    // NOTE: If we run in parallel, the remote server often gives us issues and never responds. 
    await Promise.all(addresses.map(async (address) => {
        result[address] = [];

        if (address.startsWith(":")) {
            // Handle listening ports
            const port = address.substring(1);
            const lines = listenResult.split('\n');
            const pidsProcessed = new Set<number>();

            await Promise.all(lines.map(async (line) => {
                if (!line.trim() || line.includes('Peer Address') || line.includes('State')) {
                    return;
                }

                if (line.includes(`:${port} `) || line.includes(`:${port}\t`)) {
                    const parts = line.trim().split(/\s+/);

                    if (parts.length >= 4) {
                        const processInfo = parts.slice(4).join(' ');
                        const pidMatch = processInfo.match(/pid=(\d+)/);

                        if (pidMatch) {
                            const pid = parseInt(pidMatch[1], 10);

                            if (!pidsProcessed.has(pid)) {
                                pidsProcessed.add(pid);
                                const nameMatch = processInfo.match(/\("([^"]+)"/);
                                const processName = nameMatch ? nameMatch[1] : 'unknown';

                                const args = cmdlineMap.get(pid) || [];
                                result[address].push({ pid, processName, args });
                            }
                        }
                    }
                }
            }));
        } else {
            // Handle regular IP addresses (established connections)
            const connections = parseConnectionsToTarget(establishedResult, address);
            const uniquePids = [...new Set(connections.map(c => c.pid).filter(pid => pid > 0))];

            await Promise.all(uniquePids.map(async (pid) => {
                const conn = connections.find(c => c.pid === pid);
                const processName = conn ? conn.processName : 'unknown';

                const args = cmdlineMap.get(pid) || [];
                result[address].push({ pid, processName, args });
            }));
        }
    }));

    return result;
}
