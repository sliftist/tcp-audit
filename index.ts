import { runPromise } from "socket-function/src/runPromise";
import dns from "dns";
import yargs from "yargs";
import prompts from "prompts";
import { getProcessInfoForTarget } from "./parser";
import { sort } from "socket-function/src/misc";
import { blue, green } from "socket-function/src/formatting/logColors";
import fs from "fs";
import os from "os";

let yargObj = yargs(global.process.argv.slice(2))
    .demandCommand(1, "Please provide a remote address (user@host)")
    .argv || {}
    ;

const remote = yargObj._[0] as string;

let ipinfoKey = "";
let keyPath = os.homedir() + "/ipinfo_token.txt";
if (fs.existsSync(keyPath)) {
    ipinfoKey = fs.readFileSync(keyPath, "utf8").trim();
} else {
    console.error(`No ipinfo token found, so detailed IP info will not be available. Populate the API key at ${JSON.stringify(keyPath)}`);
}

interface ConnectionInfo {
    foreignAddress: string;
    isOutgoing: boolean;
}

interface IPInfoResponse {
    ip: string;
    city?: string;
    region?: string;
    country?: string;
    loc?: string;
    org?: string;
    timezone?: string;
}

const ipInfoCache = new Map<string, string>();

async function getIPInfo(ip: string): Promise<string> {
    if (!ipinfoKey) {
        return "";
    }

    if (ipInfoCache.has(ip)) {
        return ipInfoCache.get(ip)!;
    }

    try {
        const response = await fetch(`https://ipinfo.io/${ip}?token=${ipinfoKey}`);
        if (!response.ok) {
            ipInfoCache.set(ip, "");
            return "";
        }
        const data: IPInfoResponse = await response.json();

        let location = "";
        if (data.city && data.country) {
            location = `${data.country} (${data.city})`;
        } else if (data.country) {
            location = data.country;
        }

        ipInfoCache.set(ip, location);
        return location;
    } catch (e) {
        ipInfoCache.set(ip, "");
        return "";
    }
}

/**
 * Parse ss output to extract unique foreign addresses (without ports)
 */
function parseForeignAddresses(ssOutput: string): ConnectionInfo[] {
    const lines = ssOutput.split('\n');
    const connectionsMap = new Map<string, boolean>();

    for (const line of lines) {
        // Skip empty lines and headers
        if (!line.trim() || line.includes('Peer Address') || line.includes('State')) {
            continue;
        }
        if (line.includes("TIME-WAIT")) continue;
        console.log(line);

        // Split by whitespace
        const parts = line.trim().split(/\s+/);

        // ss output typically has: State Recv-Q Send-Q Local-Address:Port Peer-Address:Port
        let foreignAddress = '';
        let localPort = 0;
        let foreignPort = 0;

        if (parts.length >= 5) {
            // Standard ss format: State Recv-Q Send-Q Local-Address:Port Peer-Address:Port
            const localAddrPort = parts[3];
            const foreignAddrPort = parts[4];

            if (localAddrPort && localAddrPort.includes(':')) {
                const colonIndex = localAddrPort.lastIndexOf(':');
                localPort = parseInt(localAddrPort.substring(colonIndex + 1), 10);
            }

            if (foreignAddrPort && foreignAddrPort.includes(':')) {
                const colonIndex = foreignAddrPort.lastIndexOf(':');
                foreignAddress = foreignAddrPort.substring(0, colonIndex);
                foreignPort = parseInt(foreignAddrPort.substring(colonIndex + 1), 10);
            }
        }

        // Add to map if it's a valid foreign address (not local/wildcard)
        if (foreignAddress && foreignAddress !== '0.0.0.0' && foreignAddress !== '*' && foreignAddress !== '127.0.0.1') {
            // Determine direction: if local port is ephemeral (> 32768), we likely initiated
            const isOutgoing = localPort > 32768;

            // If we've seen this address before, prefer marking it as outgoing if either connection is outgoing
            if (connectionsMap.has(foreignAddress)) {
                const existing = connectionsMap.get(foreignAddress)!;
                connectionsMap.set(foreignAddress, existing || isOutgoing);
            } else {
                connectionsMap.set(foreignAddress, isOutgoing);
            }
        }
    }

    return Array.from(connectionsMap.entries()).map(([addr, isOutgoing]) => ({
        foreignAddress: addr,
        isOutgoing
    }));
}

// Ah, we didn't update the servicer script, so it might be connecting to the old Atlas. 
/*

cd ~/servicer
git add --all
git stash
git pull
git checkout db2-webapp
yarn install
bash ~/startup.sh


*/
// 45.62.209.66
//     old server
// 45.62.209.67
//     old server 2
// 178.128.234.75
//     s.planquickly.com
// 65.108.70.179
//     h1.planquickly.com
// 135.181.183.214
//     h2.planquickly.com

async function main() {
    let addrLookup: {
        regex: RegExp;
        name: string;
    }[] = [
            { regex: /^20\.96\./, name: "azure", },
            { regex: /^20\.81\./, name: "azure", },
            { regex: /^20\.97\./, name: "azure", },
            { regex: /^45\.140\.17\.124$/, name: "proton66 (malicious scanner)", },
            { regex: /^10\.61/, name: "wireguard vpn", },
            // 104.192.142
            { regex: /^104\.192\.142\./, name: "atlassian", },
            // 45.62.209.67
            { regex: /^45\.62\.209\.67$/, name: "old server 2", },
            // 45.62.209.66
            { regex: /^45\.62\.209\.66$/, name: "old server", },
            // 99.250.124.91 = quentin
            { regex: /^99\.250\.124\.91$/, name: "quentin", },
        ];
    for (let domain of ["h1.planquickly.com", "h2.planquickly.com", "s.planquickly.com"]) {
        const addresses = await dns.promises.resolve4(domain);
        for (let addr of addresses) {
            const escapedAddr = addr.replace(/\./g, '\\.');
            addrLookup.push({ regex: new RegExp(`^${escapedAddr}`), name: domain });
        }
    }
    function getName(addr: string) {
        for (let lookup of addrLookup) {
            if (lookup.regex.test(addr)) {
                return lookup.name;
            }
        }
        return addr;
    }

    // Run SSH command to get ss output
    const sshCommand = `ssh ${remote} "ss -tan"`;
    const result = await runPromise(sshCommand, { quiet: true });

    // Parse and extract foreign addresses
    const connections = parseForeignAddresses(result);
    sort(connections, x => x.isOutgoing ? 0 : 1);

    // Fetch IP info for all connections if token is available
    if (ipinfoKey) {
        await Promise.all(connections.map(conn => getIPInfo(conn.foreignAddress)));
    }

    // Create choices for interactive selection
    const choices = connections.map((conn, index) => {
        let direction = conn.isOutgoing ? green("OUT") : blue("IN ");
        const name = getName(conn.foreignAddress);
        const location = ipInfoCache.get(conn.foreignAddress) || "";
        const locationStr = location ? ` [${location}]` : "";
        const title = `${index + 1}. ${direction} ${name.padEnd(30)} ${conn.foreignAddress}${locationStr}`;
        return {
            title,
            value: conn.foreignAddress,
            index: index + 1
        };
    });

    // Display all connections
    for (let choice of choices) {
        console.log(choice.title);
    }
    console.log('');

    // Interactive selection
    const response = await prompts({
        type: 'autocomplete',
        name: 'selectedIp',
        message: 'Type to filter, enter to select (arrow keys to navigate):',
        choices: choices,
        suggest: (input, choices) => {
            const inputLower = input.toLowerCase();
            return Promise.resolve(
                choices.filter(choice =>
                    choice.title.toLowerCase().includes(inputLower) ||
                    choice.value.toString() === input
                )
            );
        }
    });

    if (response.selectedIp) {
        console.log(`\nInvestigating connections to ${response.selectedIp}...\n`);
        await getProcessInfoForTarget(remote, response.selectedIp);
    }
}

main().catch(console.error).finally(() => process.exit());