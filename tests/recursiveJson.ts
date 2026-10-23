import * as tmrm from "azure-pipelines-task-lib/mock-run";
import * as path from "node:path";

const taskPath = path.join(__dirname, "..", "source", "index.js");
const auditPath = path.join(__dirname, "fixtures", "with-lockfile");
const jsonOutput = JSON.stringify({
  auditReportVersion: 2,
  vulnerabilities: {},
  metadata: {
    vulnerabilities: {
      info: 0,
      low: 0,
      moderate: 0,
      high: 0,
      critical: 0,
      total: 0,
    },
  },
});

const tmr: tmrm.TaskMockRunner = new tmrm.TaskMockRunner(taskPath);
tmr.setAnswers({
  which: { ["npm"]: "npm" },
  checkPath: {
    ["npm"]: true,
    [auditPath]: true,
  },
  exec: {
    ["npm audit --json"]: { stdout: jsonOutput, stderr: "", code: 0 },
  },
});

tmr.setInput("path", auditPath);
tmr.setInput("level", "high");
tmr.setInput("recursive", "true");
tmr.setInput("jsonOutput", "true");

tmr.run();
