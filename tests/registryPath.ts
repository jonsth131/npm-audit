import * as tmrm from "azure-pipelines-task-lib/mock-run";
import * as path from "path";

const taskPath = path.join(__dirname, "..", "source", "index.js");
const tmr: tmrm.TaskMockRunner = new tmrm.TaskMockRunner(taskPath);
tmr.setAnswers({
  which: { ["npm"]: "npm" },
  checkPath: {
    ["npm"]: true,
    ["testpath"]: true,
  },
  exec: {
    ["npm audit --registry=test"]: {
      stdout: "No vunlerabilities found",
      stderr: "",
      code: 0,
    },
  },
});

tmr.setInput("path", "testpath");
tmr.setInput("level", "low");
tmr.setInput("registry", "test");

tmr.run();
