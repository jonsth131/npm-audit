import tmrm = require("azure-pipelines-task-lib/mock-run");
import path = require("path");

let taskPath = path.join(__dirname, "..", "source", "index.js");
let tmr: tmrm.TaskMockRunner = new tmrm.TaskMockRunner(taskPath);
tmr.setAnswers({
  which: { ["npm"]: "npm" },
  checkPath: {
    ["npm"]: true,
    ["testpath"]: true,
  },
  exec: {
    ["npm audit"]: {
      stdout: "1 low, 2 moderate, 3 high, 4 critical",
      stderr: "",
      code: 10,
    },
  },
});

tmr.setInput("path", "testpath");
tmr.setInput("level", "low");
tmr.setInput("breakBuild", "true");

tmr.run();
