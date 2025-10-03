import yargs from "yargs";
import { getProcessInfoForTarget } from "./parser";

let yargObj = yargs(global.process.argv.slice(2))
    .demandCommand(2, "Please provide a remote address (user@host) and a target IP to investigate")
    .argv || {}
    ;

const remote = yargObj._[0] as string;
const targetIp = yargObj._[1] as string;

async function main() {
    await getProcessInfoForTarget(remote, targetIp);
}

main().catch(console.error).finally(() => process.exit());
