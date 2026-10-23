import * as tl from "azure-pipelines-task-lib/task";
import * as path from "path";
import { ToolRunner, IExecSyncResult } from "azure-pipelines-task-lib/toolrunner";
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
  } catch (err: unknown) {
    tl.setResult(tl.TaskResult.Failed, err instanceof Error ? err.message : String(err));
  }
}

function runNpmAudit(cwd: string, toolRunner: ToolRunner, level: string) {
  const recursive: boolean = tl.getBoolInput("recursive", false) || false;
  const jsonOutput: boolean = tl.getBoolInput("jsonOutput", false);

  if (recursive === true) {
    const packageLockFiles: string[] = getAllPackageLockFiles(cwd);
    if (packageLockFiles.length === 0) {
      throw new Error("No package-lock.json files found for recursive audit");
    }

    let result: string = "";

    for (const packageLockFile of packageLockFiles) {
      const res: IExecSyncResult = executeAudit(toolRunner, path.join(cwd, packageLockFile));
      validateAuditResult(res, jsonOutput);

      if (jsonOutput) {
        const jsonFileName = createJsonFileName(packageLockFile);
        writeJsonOutput(jsonFileName, res.stdout);
        checkForVulnerabilities(res.stdout, level);
      } else {
        result += res.stdout;
      }
    }

    if (!jsonOutput) {
      checkForVulnerabilities(result, level);
    }
  } else {
    const result: IExecSyncResult = executeAudit(toolRunner, path.join(cwd, "package-lock.json"));
    validateAuditResult(result, jsonOutput);

    if (jsonOutput) {
      writeJsonOutput("audit.json", result.stdout);
    }

    checkForVulnerabilities(result.stdout, level);
  }
}

function validateAuditResult(result: IExecSyncResult, jsonOutput: boolean): void {
  let isValidAuditResult: boolean;
  let hasVulnerabilities: boolean;

  if (jsonOutput) {
    const auditResult = parseJsonAuditResult(result.stdout);
    isValidAuditResult = auditResult !== undefined;
    hasVulnerabilities = auditResult?.hasVulnerabilities ?? false;
  } else {
    hasVulnerabilities = /\b\d{1,6}\s+(low|moderate|high|critical)\b/i.test(result.stdout);
    isValidAuditResult =
      hasVulnerabilities ||
      /\bno vulnerabilities found\b|\bfound\s+0\s+vulnerabilities?\b/i.test(result.stdout);
  }

  if (!isValidAuditResult) {
    throw new Error("npm audit did not return a valid audit result");
  }

  if (result.code !== 0 && !hasVulnerabilities) {
    throw new Error(`npm audit failed with exit code ${result.code}`);
  }
}

function parseJsonAuditResult(result: string): { hasVulnerabilities: boolean } | undefined {
  let parsed: unknown;

  try {
    parsed = JSON.parse(result) as unknown;
  } catch {
    return undefined;
  }

  if (
    !isRecord(parsed) ||
    !isRecord(parsed.metadata) ||
    !isRecord(parsed.metadata.vulnerabilities)
  ) {
    return undefined;
  }

  const vulnerabilities = parsed.metadata.vulnerabilities;
  const counts = ["info", "low", "moderate", "high", "critical", "total"];

  if (counts.some((count) => typeof vulnerabilities[count] !== "number")) {
    return undefined;
  }

  const total = vulnerabilities.total;
  if (typeof total !== "number") {
    return undefined;
  }

  return { hasVulnerabilities: total > 0 };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function createJsonFileName(packageLockFile: string): string {
  const filename: string = path.dirname(packageLockFile).replaceAll("/", "-").replaceAll("\\", "-");
  if (filename === ".") return "audit.json";
  return filename + ".json";
}

function writeJsonOutput(jsonOutputFile: string, result: string) {
  const jsonOutputPath: string = tl.getPathInput("jsonOutputPath", false, true) || "";
  if (jsonOutputFile !== "" && jsonOutputPath !== "") {
    tl.writeFile(path.join(jsonOutputPath, jsonOutputFile), result);
  }
}

function checkForVulnerabilities(result: string, level: string) {
  const jsonOutput: boolean = tl.getBoolInput("jsonOutput");
  const breakBuildInput: string | undefined = tl.getInput("breakBuild");
  const breakBuild: boolean =
    breakBuildInput === undefined ? true : breakBuildInput.toLowerCase() === "true";

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

function executeAudit(toolRunner: ToolRunner, packageLockFile: string): IExecSyncResult {
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
