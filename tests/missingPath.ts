import * as tmrm from "azure-pipelines-task-lib/mock-run";
import * as path from "node:path";

const taskPath = path.join(__dirname, "..", "source", "index.js");
const tmr: tmrm.TaskMockRunner = new tmrm.TaskMockRunner(taskPath);

tmr.setInput("level", "low");

tmr.run();
