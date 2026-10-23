import * as tmrm from "azure-pipelines-task-lib/mock-run";
import * as path from "node:path";

const taskPath = path.join(__dirname, "..", "source", "index.js");
const noLockfilesPath = path.join(__dirname, "fixtures", "no-lockfiles");
const tmr: tmrm.TaskMockRunner = new tmrm.TaskMockRunner(taskPath);
tmr.setAnswers({
  which: { ["npm"]: "npm" },
  checkPath: {
    ["npm"]: true,
    [noLockfilesPath]: true,
  },
});

tmr.setInput("path", noLockfilesPath);
tmr.setInput("level", "high");
tmr.setInput("recursive", "true");

tmr.run();
