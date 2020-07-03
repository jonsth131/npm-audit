import * as tl from "azure-pipelines-task-lib/task";
import * as path from "path";
import { ToolRunner, IExecSyncResult } from "azure-pipelines-task-lib/toolrunner";

async function run(): Promise<void> {
    try {
        tl.setResourcePath(path.join(__dirname, "task.json"));
        const cwd: string = tl.getPathInput("path", true, true) || __dirname;
        const level: string = tl.getInput("level", true) || "high";
        const productionOnly: boolean = tl.getBoolInput("productionOnly", false);
        const registry: string = tl.getInput("registry", false) as string;
        const toolPath: string = tl.which("npm", true);
        const toolRunner: ToolRunner = tl.tool(toolPath).arg("audit");

        if (productionOnly) toolRunner.arg("--production");
        if (registry) toolRunner.arg(`--registry=${registry}`);

        tl.cd(cwd);
        const result: IExecSyncResult = toolRunner.execSync();

        if (result.code !== 0) {
            const regexp: RegExp = await getLevelRegexp(level);

            const shouldBreak: boolean = regexp.test(result.stdout);

            if (shouldBreak) {
                console.log(tl.loc("VulnerabilitiesFound"));
                tl.setResult(tl.TaskResult.Failed, "Vulnerabilities found");
            } else {
                console.log(tl.loc("VulnerabilitiesFoundButLowerLevel"));
            }
        }
    } catch (err) {
        tl.setResult(tl.TaskResult.Failed, err.message);
    }
}

async function getLevelRegexp(level: string): Promise<RegExp> {
    if (level === "low") {
        return new RegExp(/\d+ (low|moderate|high|critical)+/gm);
    }
    if (level === "moderate") {
        return new RegExp(/\d+ (moderate|high|critical)+/gm);
    }
    if (level === "high") {
        return new RegExp(/\d+ (high|critical)+/gm);
    }
    if (level === "critical") {
        return new RegExp(/\d+ critical/gm);
    }

    throw new Error("Unexpected level");
}

run();