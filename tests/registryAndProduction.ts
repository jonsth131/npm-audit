import * as tmrm from "azure-pipelines-task-lib/mock-run";
import * as path from "node:path";

const taskPath = path.join(__dirname, "..", "source", "index.js");
const tmr: tmrm.TaskMockRunner = new tmrm.TaskMockRunner(taskPath);
tmr.setAnswers({
  which: { ["npm"]: "npm" },
  checkPath: {
    ["npm"]: true,
    ["testpath"]: true,
  },
  exec: {
    ["npm audit --production --registry=https://registry.npmjs.org"]: {
      stdout: "No vulnerabilities found",
      stderr: "",
      code: 0,
    },
  },
});

tmr.setInput("path", "testpath");
tmr.setInput("level", "high");
tmr.setInput("productionOnly", "true");
tmr.setInput("registry", "https://registry.npmjs.org");

tmr.run();
