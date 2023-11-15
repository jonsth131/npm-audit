import * as path from "path";
import * as assert from "assert";
import * as ttm from "azure-pipelines-task-lib/mock-test";
import { checkOutputForVulnerabilities, JsonOutput, OutputType } from "../source/vulnerability-check";

describe("npm-audit task tests", function() {
    before(() => { });

    after(() => { });

    it("should succeed with required inputs", (done: Mocha.Done) => {
        this.timeout(10000);

        let tp = path.join(__dirname, "requiredInputs.js");
        let tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

        tr.runAsync().then(() => {
            assert.strictEqual(
                tr.succeeded,
                true,
                "should have succeeded" + tr.stdout
            );
            assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
            assert.strictEqual(tr.errorIssues.length, 0, "should have no errors");
            done();
        });
    });

    it("should fail if missing path", (done: Mocha.Done) => {
        this.timeout(10000);

        let tp = path.join(__dirname, "missingPath.js");
        let tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

        tr.runAsync().then(() => {
            assert.strictEqual(tr.succeeded, false, "should have failed");
            assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
            assert.strictEqual(tr.errorIssues.length, 1, "should have 1 error issue");
            assert.strictEqual(
                tr.errorIssues[0],
                "Input required: path",
                "error issue output"
            );
            done();
        });
    });

    it("should fail if missing level", (done: Mocha.Done) => {
        this.timeout(10000);

        let tp = path.join(__dirname, "missingLevel.js");
        let tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

        tr.runAsync().then(() => {
            assert.strictEqual(tr.succeeded, false, "should have failed");
            assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
            assert.strictEqual(tr.errorIssues.length, 1, "should have 1 error issue");
            assert.strictEqual(
                tr.errorIssues[0],
                "Input required: level",
                "error issue output"
            );
            done();
        });
    });

    it("should fail if invalid level", (done: Mocha.Done) => {
        this.timeout(10000);

        let tp = path.join(__dirname, "invalidLevel.js");
        let tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

        tr.runAsync().then(() => {
            assert.strictEqual(tr.succeeded, false, "should have failed");
            assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
            assert.strictEqual(tr.errorIssues.length, 1, "should have 1 error issue");
            assert.strictEqual(
                tr.errorIssues[0],
                "Unexpected level",
                "error issue output"
            );
            done();
        });
    });

    it("should fail if vulnerabilites are found", (done: Mocha.Done) => {
        this.timeout(10000);

        let tp = path.join(__dirname, "failOnFoundLevel.js");
        let tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

        tr.runAsync().then(() => {
            assert.strictEqual(tr.succeeded, false, "should have failed");
            assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
            assert.strictEqual(tr.errorIssues.length, 1, "should have 1 error issue");
            assert.strictEqual(
                tr.errorIssues[0],
                "Vulnerabilities found",
                "error issue output"
            );
            done();
        });
    });

    it("should warn if vulnerabilites are found", (done: Mocha.Done) => {
        this.timeout(10000);

        let tp = path.join(__dirname, "warnOnFoundLevel.js");
        let tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

        tr.runAsync().then(() => {
            assert.strictEqual(tr.succeeded, true, "should have succeeded");
            assert.strictEqual(tr.warningIssues.length, 1, "should have one warning");
            assert.strictEqual(tr.errorIssues.length, 0, "should have no errors");
            assert.strictEqual(
                tr.warningIssues[0],
                "Vulnerabilities found",
                "warning issue output"
            );
            done();
        });
    });

    it("should fail if vulnerabilites are found in json output", (done: Mocha.Done) => {
        this.timeout(10000);

        let tp = path.join(__dirname, "failOnFoundLevelJson.js");
        let tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

        tr.runAsync().then(() => {
            assert.strictEqual(tr.succeeded, false, "should have failed");
            assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
            assert.strictEqual(tr.errorIssues.length, 1, "should have 1 error issue");
            assert.strictEqual(
                tr.errorIssues[0],
                "Vulnerabilities found",
                "error issue output"
            );
            done();
        });
    });

    it("should warn if vulnerabilites are found in json output", (done: Mocha.Done) => {
        this.timeout(10000);

        let tp = path.join(__dirname, "warnOnFoundLevelJson.js");
        let tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

        tr.runAsync().then(() => {
            assert.strictEqual(tr.succeeded, true, "should have succeeded");
            assert.strictEqual(tr.warningIssues.length, 1, "should have one warning");
            assert.strictEqual(tr.errorIssues.length, 0, "should have no errors");
            assert.strictEqual(
                tr.warningIssues[0],
                "Vulnerabilities found",
                "warning issue output"
            );
            done();
        });
    });

    it("should append --production if only production flag is set", (done: Mocha.Done) => {
        this.timeout(10000);

        let tp = path.join(__dirname, "productionFlag.js");
        let tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

        tr.runAsync().then(() => {
            assert.strictEqual(tr.succeeded, true, "should have succeeded");
            assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
            assert.strictEqual(tr.errorIssues.length, 0, "should have no errors");
            done();
        });
    });

    it("should append --registry if registry is set", (done: Mocha.Done) => {
        this.timeout(10000);

        let tp = path.join(__dirname, "registryPath.js");
        let tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

        tr.runAsync().then(() => {
            assert.strictEqual(tr.succeeded, true, "should have succeeded");
            assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
            assert.strictEqual(tr.errorIssues.length, 0, "should have no errors");
            done();
        });
    });

    it("should append --json if jsonOutput is set", (done: Mocha.Done) => {
        this.timeout(10000);

        let tp = path.join(__dirname, "jsonOutput.js");
        let tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

        tr.runAsync().then(() => {
            assert.strictEqual(tr.succeeded, true, "should have succeeded");
            assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
            assert.strictEqual(tr.errorIssues.length, 0, "should have no errors");
            done();
        });
    });
});

describe("checkForVulnerabilities tests", function() {
    it("should return false if no vulnerabilities are found", (done: Mocha.Done) => {
        let actual = checkOutputForVulnerabilities("0 vulnerabilities", "high", OutputType.Standard);
        assert.strictEqual(actual.hasVulnerabilities, false, "No vulnerabilities should be found");
        assert.strictEqual(actual.breakBuild, false, "Should not break the build");
        done();
    });

    it("should break the build if vulnerabilities are found", (done: Mocha.Done) => {
        let actual = checkOutputForVulnerabilities("6 vulnerabilities (1 moderate, 2 high, 3 critical)", "high", OutputType.Standard);
        assert.strictEqual(actual.hasVulnerabilities, true, "Vulnerabilities should be found");
        assert.strictEqual(actual.breakBuild, true, "Should break the build");
        done();
    });

    it("should not break the build if vulnerabilities are found but breakBuild is false", (done: Mocha.Done) => {
        let actual = checkOutputForVulnerabilities("3 vulnerabilities (1 moderate, 2 high)", "critical", OutputType.Standard);
        assert.strictEqual(actual.hasVulnerabilities, true, "Vulnerabilities should be found");
        assert.strictEqual(actual.breakBuild, false, "Should not break the build");
        done();
    });

    it("should return false if no vulnerabilities are found with json output", (done: Mocha.Done) => {
        const jsonOutput: JsonOutput = {
            metadata: {
                vulnerabilities: {
                    info: 0,
                    low: 0,
                    moderate: 0,
                    high: 0,
                    critical: 0,
                    total: 0
                }
            }
        };

        let actual = checkOutputForVulnerabilities(JSON.stringify(jsonOutput), "high", OutputType.Json);
        assert.strictEqual(actual.hasVulnerabilities, false, "No vulnerabilities should be found");
        assert.strictEqual(actual.breakBuild, false, "Should not break the build");
        done();
    });

    it("should break the build if vulnerabilities are found with json output", (done: Mocha.Done) => {
        const jsonOutput: JsonOutput = {
            metadata: {
                vulnerabilities: {
                    info: 0,
                    low: 0,
                    moderate: 0,
                    high: 10,
                    critical: 0,
                    total: 10
                }
            }
        };

        let actual = checkOutputForVulnerabilities(JSON.stringify(jsonOutput), "high", OutputType.Json);
        assert.strictEqual(actual.hasVulnerabilities, true, "Vulnerabilities should be found");
        assert.strictEqual(actual.breakBuild, true, "Should break the build");
        done();
    });

    it("should not break the build if vulnerabilities are found but breakBuild is false with json output", (done: Mocha.Done) => {
        const jsonOutput: JsonOutput = {
            metadata: {
                vulnerabilities: {
                    info: 0,
                    low: 0,
                    moderate: 0,
                    high: 10,
                    critical: 0,
                    total: 10
                }
            }
        };

        let actual = checkOutputForVulnerabilities(JSON.stringify(jsonOutput), "critical", OutputType.Json);
        assert.strictEqual(actual.hasVulnerabilities, true, "Vulnerabilities should be found");
        assert.strictEqual(actual.breakBuild, false, "Should not break the build");
        done();
    });
});

describe("JsonOutput tests", function() {
    it("should parse json output with no vulnerabilites", (done: Mocha.Done) => {
        const jsonOutput = `{
  "auditReportVersion": 2,
  "vulnerabilities": {},
  "metadata": {
    "vulnerabilities": {
      "info": 1,
      "low": 2,
      "moderate": 3,
      "high": 4,
      "critical": 5,
      "total": 15
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
        const expected: JsonOutput = {
            metadata: {
                vulnerabilities: {
                    info: 1,
                    low: 2,
                    moderate: 3,
                    high: 4,
                    critical: 5,
                    total: 15
                }
            }
        };

        let actual: JsonOutput = JSON.parse(jsonOutput);

        assert.equal(actual.metadata.vulnerabilities.info, expected.metadata.vulnerabilities.info, "info should match");
        assert.equal(actual.metadata.vulnerabilities.low, expected.metadata.vulnerabilities.low, "low should match");
        assert.equal(actual.metadata.vulnerabilities.moderate, expected.metadata.vulnerabilities.moderate, "moderate should match");
        assert.equal(actual.metadata.vulnerabilities.high, expected.metadata.vulnerabilities.high, "high should match");
        assert.equal(actual.metadata.vulnerabilities.critical, expected.metadata.vulnerabilities.critical, "critical should match");
        assert.equal(actual.metadata.vulnerabilities.total, expected.metadata.vulnerabilities.total, "total should match");
        done();
    });

    it("should parse json output with vulnerabilites", (done: Mocha.Done) => {
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

        let actual: JsonOutput = JSON.parse(jsonOutput);

        assert.equal(actual.metadata.vulnerabilities.info, 0, "info should match");
        assert.equal(actual.metadata.vulnerabilities.low, 0, "low should match");
        assert.equal(actual.metadata.vulnerabilities.moderate, 1, "moderate should match");
        assert.equal(actual.metadata.vulnerabilities.high, 2, "high should match");
        assert.equal(actual.metadata.vulnerabilities.critical, 3, "critical should match");
        assert.equal(actual.metadata.vulnerabilities.total, 6, "total should match");
        done();
    });
});
