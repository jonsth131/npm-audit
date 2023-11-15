import tmrm = require("azure-pipelines-task-lib/mock-run");
import path = require("path");

let taskPath = path.join(__dirname, "..", "source", "index.js");
let tmr: tmrm.TaskMockRunner = new tmrm.TaskMockRunner(taskPath);

const jsonOutput = `{
  "auditReportVersion": 2,
  "vulnerabilities": {
    "minimatch": {
      "name": "minimatch",
      "severity": "high",
      "isDirect": false,
      "via": [
        {
          "source": 1094009,
          "name": "minimatch",
          "dependency": "minimatch",
          "title": "minimatch ReDoS vulnerability",
          "url": "https://github.com/advisories/GHSA-f8q6-p94x-37v3",
          "severity": "high",
          "cwe": [
            "CWE-400",
            "CWE-1333"
          ],
          "cvss": {
            "score": 7.5,
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
          },
          "range": "<3.0.5"
        }
      ],
      "effects": [
        "mocha"
      ],
      "range": "<3.0.5",
      "nodes": [
        "node_modules/mocha/node_modules/minimatch"
      ],
      "fixAvailable": {
        "name": "vscode",
        "version": "1.1.34",
        "isSemVerMajor": true
      }
    },
    "minimist": {
      "name": "minimist",
      "severity": "critical",
      "isDirect": false,
      "via": [
        {
          "source": 1092422,
          "name": "minimist",
          "dependency": "minimist",
          "title": "Prototype Pollution in minimist",
          "url": "https://github.com/advisories/GHSA-vh95-rmgr-6w4m",
          "severity": "moderate",
          "cwe": [
            "CWE-1321"
          ],
          "cvss": {
            "score": 5.6,
            "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L"
          },
          "range": "<0.2.1"
        },
        {
          "source": 1094872,
          "name": "minimist",
          "dependency": "minimist",
          "title": "Prototype Pollution in minimist",
          "url": "https://github.com/advisories/GHSA-xvch-5gv4-984h",
          "severity": "critical",
          "cwe": [
            "CWE-1321"
          ],
          "cvss": {
            "score": 9.8,
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "range": "<0.2.4"
        }
      ],
      "effects": [
        "mkdirp"
      ],
      "range": "<=0.2.3",
      "nodes": [
        "node_modules/minimist"
      ],
      "fixAvailable": {
        "name": "vscode",
        "version": "1.1.34",
        "isSemVerMajor": true
      }
    },
    "mkdirp": {
      "name": "mkdirp",
      "severity": "critical",
      "isDirect": false,
      "via": [
        "minimist"
      ],
      "effects": [
        "mocha"
      ],
      "range": "0.4.1 - 0.5.1",
      "nodes": [
        "node_modules/mkdirp"
      ],
      "fixAvailable": {
        "name": "vscode",
        "version": "1.1.34",
        "isSemVerMajor": true
      }
    },
    "mocha": {
      "name": "mocha",
      "severity": "critical",
      "isDirect": false,
      "via": [
        "minimatch",
        "mkdirp"
      ],
      "effects": [
        "vscode"
      ],
      "range": "1.21.5 - 9.2.1",
      "nodes": [
        "node_modules/mocha"
      ],
      "fixAvailable": {
        "name": "vscode",
        "version": "1.1.34",
        "isSemVerMajor": true
      }
    },
    "semver": {
      "name": "semver",
      "severity": "moderate",
      "isDirect": false,
      "via": [
        {
          "source": 1094554,
          "name": "semver",
          "dependency": "semver",
          "title": "semver vulnerable to Regular Expression Denial of Service",
          "url": "https://github.com/advisories/GHSA-c2qf-rxjj-qqgw",
          "severity": "moderate",
          "cwe": [
            "CWE-1333"
          ],
          "cvss": {
            "score": 5.3,
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
          },
          "range": "<5.7.2"
        }
      ],
      "effects": [],
      "range": "<5.7.2",
      "nodes": [
        "node_modules/semver"
      ],
      "fixAvailable": true
    },
    "vscode": {
      "name": "vscode",
      "severity": "high",
      "isDirect": true,
      "via": [
        "mocha"
      ],
      "effects": [],
      "range": ">=1.1.35",
      "nodes": [
        "node_modules/vscode"
      ],
      "fixAvailable": {
        "name": "vscode",
        "version": "1.1.34",
        "isSemVerMajor": true
      }
    }
  },
  "metadata": {
    "vulnerabilities": {
      "info": 0,
      "low": 0,
      "moderate": 1,
      "high": 2,
      "critical": 3,
      "total": 6
    },
    "dependencies": {
      "prod": 1,
      "dev": 48,
      "optional": 0,
      "peer": 0,
      "peerOptional": 0,
      "total": 48
    }
  }
}`;

tmr.setAnswers({
    which: { ["npm"]: "npm" },
    checkPath: {
        ["npm"]: true,
        ["testpath"]: true,
    },
    exec: { ["npm audit --json"]: { stdout: jsonOutput, stderr: "", code: 0 } },
});

tmr.setInput("path", "testpath");
tmr.setInput("level", "low");
tmr.setInput("jsonOutput", "true");

tmr.run();
