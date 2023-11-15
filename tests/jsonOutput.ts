import tmrm = require("azure-pipelines-task-lib/mock-run");
import path = require("path");

let taskPath = path.join(__dirname, "..", "source", "index.js");
let tmr: tmrm.TaskMockRunner = new tmrm.TaskMockRunner(taskPath);


const jsonOutput = `{
  "auditReportVersion": 2,
  "vulnerabilities": {},
  "metadata": {
    "vulnerabilities": {
      "info": 0,
      "low": 0,
      "moderate": 0,
      "high": 0,
      "critical": 0,
      "total": 0
    },
    "dependencies": {
      "prod": 45,
      "dev": 355,
      "optional": 0,
      "peer": 0,
      "peerOptional": 0,
      "total": 399
    }
  }
}`

tmr.setAnswers({
  which: { ["npm"]: "npm" },
  checkPath: {
    ["npm"]: true,
    ["testpath"]: true,
  },
  exec: {
    ["npm audit --json"]: { stdout: jsonOutput, stderr: "", code: 0 },
  },
});

tmr.setInput("path", "testpath");
tmr.setInput("level", "low");
tmr.setInput("jsonOutput", "true");

tmr.run();
