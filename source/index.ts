import * as tl from "azure-pipelines-task-lib/task";
import * as path from "path";
import {
    ToolRunner,
    IExecSyncResult,
} from "azure-pipelines-task-lib/toolrunner";
import * as glob from "glob";
import { checkOutputForVulnerabilities, OutputType } from "./vulnerability-check";

async function run(): Promise<void> {
    try {
        tl.setResourcePath(path.join(__dirname, "task.json"));
        const cwd: string = tl.getPathInput("path", true, true) || __dirname;
        const level: string = tl.getInput("level", true) || "high";
        const toolPath: string = tl.which("npm", true);
        const toolRunner: ToolRunner = tl.tool(toolPath).arg("audit");

        setProductionOnlyFlag(toolRunner);
        setRegistry(toolRunner);
        setJsonFlag(toolRunner);

        runNpmAudit(cwd, toolRunner, level);
    } catch (err: any) {
        tl.setResult(tl.TaskResult.Failed, err.message);
    }
}

function runNpmAudit(
    cwd: string,
    toolRunner: ToolRunner,
    level: string
) {
    const recursive: boolean = tl.getBoolInput("recursive", false) || false;
    const jsonOutput: boolean = tl.getBoolInput("jsonOutput", false);

    if (recursive === true) {
        const packageLockFiles: string[] = getAllPackageLockFiles(cwd);
        let result: string = "";

        for (const packageLockFile of packageLockFiles) {
            const res: IExecSyncResult = executeAudit(
                toolRunner,
                path.join(cwd, packageLockFile)
            );

            if (jsonOutput) {
                const jsonFileName = createJsonFileName(packageLockFile);
                writeJsonOutput(jsonFileName, res.stdout);
                checkForVulnerabilities(res.stdout, level);
            } else {
                result += res.stdout;
            }
        }

        checkForVulnerabilities(result, level);
    } else {
        const result: IExecSyncResult = executeAudit(toolRunner, path.join(cwd, "package-lock.json"));

        if (jsonOutput) {
            writeJsonOutput("audit.json", result.stdout);
        }

        checkForVulnerabilities(result.stdout, level);
    }
}

function createJsonFileName(packageLockFile: string): string {
    const filename: string = path
        .dirname(packageLockFile)
        .replace(/\//g, "-")
        .replace(/\\/g, "-");
    if (filename === ".") return "audit.json";
    return filename + ".json";
}

function writeJsonOutput(jsonOutputFile: string, result: string) {
    const jsonOutputPath: string = tl.getPathInput("jsonOutputPath", false, true) || "";
    if (jsonOutputFile !== "" && jsonOutputPath !== "") {
        tl.writeFile(path.join(jsonOutputPath, jsonOutputFile), result);
    }
}

function checkForVulnerabilities(
    result: string,
    level: string
) {
    const jsonOutput: boolean = tl.getBoolInput("jsonOutput");
    const breakBuildInput: string | undefined = tl.getInput("breakBuild");
    const breakBuild: boolean = breakBuildInput === undefined ? true : breakBuildInput.toLowerCase() === "true";

    const outputType: OutputType = jsonOutput === true ? OutputType.Json : OutputType.Standard;

    const vulnerabilityResult = checkOutputForVulnerabilities(result, level, outputType);

    if (vulnerabilityResult.breakBuild === true) {
        console.log(tl.loc("VulnerabilitiesFound"));
        if (breakBuild === true) {
            tl.setResult(tl.TaskResult.Failed, "Vulnerabilities found");
        } else {
            tl.setResult(tl.TaskResult.SucceededWithIssues, "Vulnerabilities found");
        }
    } else if (vulnerabilityResult.hasVulnerabilities === true) {
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

function setJsonFlag(toolRunner: ToolRunner) {
    const jsonOutput: boolean = tl.getBoolInput("jsonOutput", false) || false;
    if (jsonOutput) toolRunner.arg("--json");
}

run();
