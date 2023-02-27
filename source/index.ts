import * as tl from "azure-pipelines-task-lib/task";
import * as path from "path";
import {
    ToolRunner,
    IExecSyncResult,
} from "azure-pipelines-task-lib/toolrunner";
import * as glob from "glob";

async function run(): Promise<void> {
    try {
        tl.setResourcePath(path.join(__dirname, "task.json"));
        const cwd: string = tl.getPathInput("path", true, true) || __dirname;
        const level: string = tl.getInput("level", true) || "high";
        const toolPath: string = tl.which("npm", true);
        const toolRunner: ToolRunner = tl.tool(toolPath).arg("audit");

        setProductionOnlyFlag(toolRunner);
        setRegistry(toolRunner);

        runNpmAudit(cwd, toolRunner, level);
    } catch (err: any) {
        tl.setResult(tl.TaskResult.Failed, err.message);
    }
}

function runNpmAudit(cwd: string, toolRunner: ToolRunner, level: string) {
    const recursive: boolean = tl.getBoolInput("recursive", false) || false;

    if (recursive === true) {
        const packageLockFiles: string[] = getAllPackageLockFiles(cwd);
        let resultCode: number = 0;
        let result: string = "";

        for (const packageLockFile of packageLockFiles) {
            const res: IExecSyncResult = executeAudit(
                toolRunner,
                path.join(cwd, packageLockFile)
            );
            result += res.stdout;
            resultCode += res.code;
        }

        checkForVulnerabilities(result, resultCode, level);
    } else {
        const result: IExecSyncResult = executeAudit(toolRunner, path.join(cwd));
        checkForVulnerabilities(result.stdout, result.code, level);
    }
}

function checkForVulnerabilities(
    result: string,
    resultCode: number,
    level: string
) {
    if (resultCode === 0) return;

    const regexp: RegExp = getLevelRegexp(level);

    const shouldBreak: boolean = regexp.test(result);

    if (shouldBreak) {
        console.log(tl.loc("VulnerabilitiesFound"));
        tl.setResult(tl.TaskResult.Failed, "Vulnerabilities found");
    } else {
        console.log(tl.loc("VulnerabilitiesFoundButLowerLevel"));
    }
}

function executeAudit(
    toolRunner: ToolRunner,
    packageLockFile: string
): IExecSyncResult {
    const cwd: string = tl.cwd();
    const pwd: string = path.dirname(packageLockFile);

    tl.cd(pwd);

    const result = toolRunner.execSync();

    tl.cd(cwd);

    return result;
}

function getAllPackageLockFiles(cwd: string): string[] {
    return glob.sync("**/package-lock.json", { cwd });
}

function setProductionOnlyFlag(toolRunner: ToolRunner) {
    const productionOnly: boolean = tl.getBoolInput("productionOnly", false);
    if (productionOnly) toolRunner.arg("--production");
}

function setRegistry(toolRunner: ToolRunner) {
    const registry: string = tl.getInput("registry", false) as string;
    if (registry) toolRunner.arg(`--registry=${registry}`);
}

function getLevelRegexp(level: string): RegExp {
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
