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
    ["npm audit"]: { stdout: "No vunlerabilities found", stderr: "", code: 1 },
  },
});

tmr.setInput("path", "testpath");
tmr.setInput("level", "invalid");

tmr.run();
