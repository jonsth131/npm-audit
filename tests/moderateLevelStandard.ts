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
    ["npm audit"]: {
      stdout: "5 moderate",
      stderr: "",
      code: 10,
    },
  },
});

tmr.setInput("path", "testpath");
tmr.setInput("level", "moderate");
tmr.setInput("breakBuild", "true");

tmr.run();
