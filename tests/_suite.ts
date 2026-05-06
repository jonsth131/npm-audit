import * as path from "node:path";
import * as assert from "assert";
import * as ttm from "azure-pipelines-task-lib/mock-test";
import {
  checkOutputForVulnerabilities,
  JsonOutput,
  OutputType,
} from "../source/vulnerability-check";

describe("npm-audit task tests", function () {
  before(() => {});

  after(() => {});

  it("should succeed with required inputs", (done: Mocha.Done) => {
    this.timeout(10000);

    const tp = path.join(__dirname, "requiredInputs.js");
    const tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

    tr.runAsync().then(() => {
      assert.strictEqual(tr.succeeded, true, "should have succeeded" + tr.stdout);
      assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
      assert.strictEqual(tr.errorIssues.length, 0, "should have no errors");
      done();
    });
  });

  it("should fail if missing path", (done: Mocha.Done) => {
    this.timeout(10000);

    const tp = path.join(__dirname, "missingPath.js");
    const tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

    tr.runAsync().then(() => {
      assert.strictEqual(tr.succeeded, false, "should have failed");
      assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
      assert.strictEqual(tr.errorIssues.length, 1, "should have 1 error issue");
      assert.strictEqual(tr.errorIssues[0], "Input required: path", "error issue output");
      done();
    });
  });

  it("should fail if missing level", (done: Mocha.Done) => {
    this.timeout(10000);

    const tp = path.join(__dirname, "missingLevel.js");
    const tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

    tr.runAsync().then(() => {
      assert.strictEqual(tr.succeeded, false, "should have failed");
      assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
      assert.strictEqual(tr.errorIssues.length, 1, "should have 1 error issue");
      assert.strictEqual(tr.errorIssues[0], "Input required: level", "error issue output");
      done();
    });
  });

  it("should fail if invalid level", (done: Mocha.Done) => {
    this.timeout(10000);

    const tp = path.join(__dirname, "invalidLevel.js");
    const tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

    tr.runAsync().then(() => {
      assert.strictEqual(tr.succeeded, false, "should have failed");
      assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
      assert.strictEqual(tr.errorIssues.length, 1, "should have 1 error issue");
      assert.strictEqual(tr.errorIssues[0], "Unexpected level", "error issue output");
      done();
    });
  });

  it("should fail if vulnerabilites are found", (done: Mocha.Done) => {
    this.timeout(10000);

    const tp = path.join(__dirname, "failOnFoundLevel.js");
    const tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

    tr.runAsync().then(() => {
      assert.strictEqual(tr.succeeded, false, "should have failed");
      assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
      assert.strictEqual(tr.errorIssues.length, 1, "should have 1 error issue");
      assert.strictEqual(tr.errorIssues[0], "Vulnerabilities found", "error issue output");
      done();
    });
  });

  it("should warn if vulnerabilites are found", (done: Mocha.Done) => {
    this.timeout(10000);

    const tp = path.join(__dirname, "warnOnFoundLevel.js");
    const tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

    tr.runAsync().then(() => {
      assert.strictEqual(tr.succeeded, true, "should have succeeded");
      assert.strictEqual(tr.warningIssues.length, 1, "should have one warning");
      assert.strictEqual(tr.errorIssues.length, 0, "should have no errors");
      assert.strictEqual(tr.warningIssues[0], "Vulnerabilities found", "warning issue output");
      done();
    });
  });

  it("should fail if vulnerabilites are found in json output", (done: Mocha.Done) => {
    this.timeout(10000);

    const tp = path.join(__dirname, "failOnFoundLevelJson.js");
    const tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

    tr.runAsync().then(() => {
      assert.strictEqual(tr.succeeded, false, "should have failed");
      assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
      assert.strictEqual(tr.errorIssues.length, 1, "should have 1 error issue");
      assert.strictEqual(tr.errorIssues[0], "Vulnerabilities found", "error issue output");
      done();
    });
  });

  it("should warn if vulnerabilites are found in json output", (done: Mocha.Done) => {
    this.timeout(10000);

    const tp = path.join(__dirname, "warnOnFoundLevelJson.js");
    const tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

    tr.runAsync().then(() => {
      assert.strictEqual(tr.succeeded, true, "should have succeeded");
      assert.strictEqual(tr.warningIssues.length, 1, "should have one warning");
      assert.strictEqual(tr.errorIssues.length, 0, "should have no errors");
      assert.strictEqual(tr.warningIssues[0], "Vulnerabilities found", "warning issue output");
      done();
    });
  });

  it("should append --production if only production flag is set", (done: Mocha.Done) => {
    this.timeout(10000);

    const tp = path.join(__dirname, "productionFlag.js");
    const tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

    tr.runAsync().then(() => {
      assert.strictEqual(tr.succeeded, true, "should have succeeded");
      assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
      assert.strictEqual(tr.errorIssues.length, 0, "should have no errors");
      done();
    });
  });

  it("should append --registry if registry is set", (done: Mocha.Done) => {
    this.timeout(10000);

    const tp = path.join(__dirname, "registryPath.js");
    const tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

    tr.runAsync().then(() => {
      assert.strictEqual(tr.succeeded, true, "should have succeeded");
      assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
      assert.strictEqual(tr.errorIssues.length, 0, "should have no errors");
      done();
    });
  });

  it("should append --json if jsonOutput is set", (done: Mocha.Done) => {
    this.timeout(10000);

    const tp = path.join(__dirname, "jsonOutput.js");
    const tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

    tr.runAsync().then(() => {
      assert.strictEqual(tr.succeeded, true, "should have succeeded");
      assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
      assert.strictEqual(tr.errorIssues.length, 0, "should have no errors");
      done();
    });
  });

  it("should fail with moderate level vulnerabilities", (done: Mocha.Done) => {
    this.timeout(10000);

    const tp = path.join(__dirname, "moderateLevelStandard.js");
    const tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

    tr.runAsync().then(() => {
      assert.strictEqual(tr.succeeded, false, "should have failed");
      assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
      assert.strictEqual(tr.errorIssues.length, 1, "should have 1 error issue");
      assert.strictEqual(tr.errorIssues[0], "Vulnerabilities found", "error issue output");
      done();
    });
  });

  it("should fail with critical level vulnerabilities", (done: Mocha.Done) => {
    this.timeout(10000);

    const tp = path.join(__dirname, "criticalLevelStandard.js");
    const tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

    tr.runAsync().then(() => {
      assert.strictEqual(tr.succeeded, false, "should have failed");
      assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
      assert.strictEqual(tr.errorIssues.length, 1, "should have 1 error issue");
      assert.strictEqual(tr.errorIssues[0], "Vulnerabilities found", "error issue output");
      done();
    });
  });

  it("should fail with moderate level vulnerabilities in json output", (done: Mocha.Done) => {
    this.timeout(10000);

    const tp = path.join(__dirname, "moderateLevelJson.js");
    const tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

    tr.runAsync().then(() => {
      assert.strictEqual(tr.succeeded, false, "should have failed");
      assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
      assert.strictEqual(tr.errorIssues.length, 1, "should have 1 error issue");
      assert.strictEqual(tr.errorIssues[0], "Vulnerabilities found", "error issue output");
      done();
    });
  });

  it("should fail with critical level vulnerabilities in json output", (done: Mocha.Done) => {
    this.timeout(10000);

    const tp = path.join(__dirname, "criticalLevelJson.js");
    const tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

    tr.runAsync().then(() => {
      assert.strictEqual(tr.succeeded, false, "should have failed");
      assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
      assert.strictEqual(tr.errorIssues.length, 1, "should have 1 error issue");
      assert.strictEqual(tr.errorIssues[0], "Vulnerabilities found", "error issue output");
      done();
    });
  });

  it("should fail when low level catches all vulnerabilities", (done: Mocha.Done) => {
    this.timeout(10000);

    const tp = path.join(__dirname, "lowLevelCatchesAll.js");
    const tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

    tr.runAsync().then(() => {
      assert.strictEqual(tr.succeeded, false, "should have failed");
      assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
      assert.strictEqual(tr.errorIssues.length, 1, "should have 1 error issue");
      assert.strictEqual(tr.errorIssues[0], "Vulnerabilities found", "error issue output");
      done();
    });
  });

  it("should succeed when moderate level ignores low vulnerabilities", (done: Mocha.Done) => {
    this.timeout(10000);

    const tp = path.join(__dirname, "moderateLevelIgnoresLow.js");
    const tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

    tr.runAsync().then(() => {
      assert.strictEqual(tr.succeeded, true, "should have succeeded");
      assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
      assert.strictEqual(tr.errorIssues.length, 0, "should have no errors");
      done();
    });
  });

  it("should handle single vulnerability", (done: Mocha.Done) => {
    this.timeout(10000);

    const tp = path.join(__dirname, "singleVulnerability.js");
    const tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

    tr.runAsync().then(() => {
      assert.strictEqual(tr.succeeded, false, "should have failed");
      assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
      assert.strictEqual(tr.errorIssues.length, 1, "should have 1 error issue");
      assert.strictEqual(tr.errorIssues[0], "Vulnerabilities found", "error issue output");
      done();
    });
  });

  it("should handle large vulnerability counts", (done: Mocha.Done) => {
    this.timeout(10000);

    const tp = path.join(__dirname, "largeVulnerabilityCounts.js");
    const tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

    tr.runAsync().then(() => {
      assert.strictEqual(tr.succeeded, false, "should have failed");
      assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
      assert.strictEqual(tr.errorIssues.length, 1, "should have 1 error issue");
      assert.strictEqual(tr.errorIssues[0], "Vulnerabilities found", "error issue output");
      done();
    });
  });

  it("should handle production and json flags together", (done: Mocha.Done) => {
    this.timeout(10000);

    const tp = path.join(__dirname, "productionAndJson.js");
    const tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

    tr.runAsync().then(() => {
      assert.strictEqual(tr.succeeded, true, "should have succeeded");
      assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
      assert.strictEqual(tr.errorIssues.length, 0, "should have no errors");
      done();
    });
  });

  it("should handle registry and production flags together", (done: Mocha.Done) => {
    this.timeout(10000);

    const tp = path.join(__dirname, "registryAndProduction.js");
    const tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

    tr.runAsync().then(() => {
      assert.strictEqual(tr.succeeded, true, "should have succeeded");
      assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
      assert.strictEqual(tr.errorIssues.length, 0, "should have no errors");
      done();
    });
  });
});

describe("checkForVulnerabilities tests", function () {
  it("should return false if no vulnerabilities are found", (done: Mocha.Done) => {
    const actual = checkOutputForVulnerabilities("0 vulnerabilities", "high", OutputType.Standard);
    assert.strictEqual(actual.hasVulnerabilities, false, "No vulnerabilities should be found");
    assert.strictEqual(actual.breakBuild, false, "Should not break the build");
    done();
  });

  it("should break the build if vulnerabilities are found", (done: Mocha.Done) => {
    const actual = checkOutputForVulnerabilities(
      "6 vulnerabilities (1 moderate, 2 high, 3 critical)",
      "high",
      OutputType.Standard,
    );
    assert.strictEqual(actual.hasVulnerabilities, true, "Vulnerabilities should be found");
    assert.strictEqual(actual.breakBuild, true, "Should break the build");
    done();
  });

  it("should not break the build if vulnerabilities are found but breakBuild is false", (done: Mocha.Done) => {
    const actual = checkOutputForVulnerabilities(
      "3 vulnerabilities (1 moderate, 2 high)",
      "critical",
      OutputType.Standard,
    );
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
          total: 0,
        },
      },
    };

    const actual = checkOutputForVulnerabilities(
      JSON.stringify(jsonOutput),
      "high",
      OutputType.Json,
    );
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
          total: 10,
        },
      },
    };

    const actual = checkOutputForVulnerabilities(
      JSON.stringify(jsonOutput),
      "high",
      OutputType.Json,
    );
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
          total: 10,
        },
      },
    };

    const actual = checkOutputForVulnerabilities(
      JSON.stringify(jsonOutput),
      "critical",
      OutputType.Json,
    );
    assert.strictEqual(actual.hasVulnerabilities, true, "Vulnerabilities should be found");
    assert.strictEqual(actual.breakBuild, false, "Should not break the build");
    done();
  });

  it("should detect moderate level vulnerabilities in standard output", (done: Mocha.Done) => {
    const actual = checkOutputForVulnerabilities("5 moderate", "moderate", OutputType.Standard);
    assert.strictEqual(actual.hasVulnerabilities, true, "Vulnerabilities should be found");
    assert.strictEqual(actual.breakBuild, true, "Should break the build");
    done();
  });

  it("should detect critical level vulnerabilities in standard output", (done: Mocha.Done) => {
    const actual = checkOutputForVulnerabilities("2 critical", "critical", OutputType.Standard);
    assert.strictEqual(actual.hasVulnerabilities, true, "Vulnerabilities should be found");
    assert.strictEqual(actual.breakBuild, true, "Should break the build");
    done();
  });

  it("should handle low level catching all severities", (done: Mocha.Done) => {
    const actual = checkOutputForVulnerabilities(
      "1 low, 2 moderate, 3 high, 4 critical",
      "low",
      OutputType.Standard,
    );
    assert.strictEqual(actual.hasVulnerabilities, true, "Vulnerabilities should be found");
    assert.strictEqual(actual.breakBuild, true, "Should break the build");
    done();
  });

  it("should handle moderate level ignoring low vulnerabilities", (done: Mocha.Done) => {
    const actual = checkOutputForVulnerabilities("10 low", "moderate", OutputType.Standard);
    assert.strictEqual(actual.hasVulnerabilities, true, "Vulnerabilities should be found");
    assert.strictEqual(actual.breakBuild, false, "Should not break the build");
    done();
  });

  it("should handle high level ignoring low and moderate vulnerabilities", (done: Mocha.Done) => {
    const actual = checkOutputForVulnerabilities("5 low, 3 moderate", "high", OutputType.Standard);
    assert.strictEqual(actual.hasVulnerabilities, true, "Vulnerabilities should be found");
    assert.strictEqual(actual.breakBuild, false, "Should not break the build");
    done();
  });

  it("should handle single vulnerability", (done: Mocha.Done) => {
    const actual = checkOutputForVulnerabilities("1 critical", "critical", OutputType.Standard);
    assert.strictEqual(actual.hasVulnerabilities, true, "Vulnerabilities should be found");
    assert.strictEqual(actual.breakBuild, true, "Should break the build");
    done();
  });

  it("should handle large vulnerability counts", (done: Mocha.Done) => {
    const actual = checkOutputForVulnerabilities("999 high", "high", OutputType.Standard);
    assert.strictEqual(actual.hasVulnerabilities, true, "Vulnerabilities should be found");
    assert.strictEqual(actual.breakBuild, true, "Should break the build");
    done();
  });

  it("should detect moderate level vulnerabilities in JSON output", (done: Mocha.Done) => {
    const jsonOutput: JsonOutput = {
      metadata: {
        vulnerabilities: {
          info: 0,
          low: 0,
          moderate: 5,
          high: 0,
          critical: 0,
          total: 5,
        },
      },
    };

    const actual = checkOutputForVulnerabilities(
      JSON.stringify(jsonOutput),
      "moderate",
      OutputType.Json,
    );
    assert.strictEqual(actual.hasVulnerabilities, true, "Vulnerabilities should be found");
    assert.strictEqual(actual.breakBuild, true, "Should break the build");
    done();
  });

  it("should detect critical level vulnerabilities in JSON output", (done: Mocha.Done) => {
    const jsonOutput: JsonOutput = {
      metadata: {
        vulnerabilities: {
          info: 0,
          low: 0,
          moderate: 0,
          high: 0,
          critical: 2,
          total: 2,
        },
      },
    };

    const actual = checkOutputForVulnerabilities(
      JSON.stringify(jsonOutput),
      "critical",
      OutputType.Json,
    );
    assert.strictEqual(actual.hasVulnerabilities, true, "Vulnerabilities should be found");
    assert.strictEqual(actual.breakBuild, true, "Should break the build");
    done();
  });

  it("should handle moderate level ignoring low in JSON output", (done: Mocha.Done) => {
    const jsonOutput: JsonOutput = {
      metadata: {
        vulnerabilities: {
          info: 0,
          low: 10,
          moderate: 0,
          high: 0,
          critical: 0,
          total: 10,
        },
      },
    };

    const actual = checkOutputForVulnerabilities(
      JSON.stringify(jsonOutput),
      "moderate",
      OutputType.Json,
    );
    assert.strictEqual(actual.hasVulnerabilities, true, "Vulnerabilities should be found");
    assert.strictEqual(actual.breakBuild, false, "Should not break the build");
    done();
  });

  it("should handle low level catching all severities in JSON output", (done: Mocha.Done) => {
    const jsonOutput: JsonOutput = {
      metadata: {
        vulnerabilities: {
          info: 0,
          low: 1,
          moderate: 2,
          high: 3,
          critical: 4,
          total: 10,
        },
      },
    };

    const actual = checkOutputForVulnerabilities(
      JSON.stringify(jsonOutput),
      "low",
      OutputType.Json,
    );
    assert.strictEqual(actual.hasVulnerabilities, true, "Vulnerabilities should be found");
    assert.strictEqual(actual.breakBuild, true, "Should break the build");
    done();
  });
});

describe("JsonOutput tests", function () {
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
}`;
    const expected: JsonOutput = {
      metadata: {
        vulnerabilities: {
          info: 1,
          low: 2,
          moderate: 3,
          high: 4,
          critical: 5,
          total: 15,
        },
      },
    };

    const actual: JsonOutput = JSON.parse(jsonOutput);

    assert.equal(
      actual.metadata.vulnerabilities.info,
      expected.metadata.vulnerabilities.info,
      "info should match",
    );
    assert.equal(
      actual.metadata.vulnerabilities.low,
      expected.metadata.vulnerabilities.low,
      "low should match",
    );
    assert.equal(
      actual.metadata.vulnerabilities.moderate,
      expected.metadata.vulnerabilities.moderate,
      "moderate should match",
    );
    assert.equal(
      actual.metadata.vulnerabilities.high,
      expected.metadata.vulnerabilities.high,
      "high should match",
    );
    assert.equal(
      actual.metadata.vulnerabilities.critical,
      expected.metadata.vulnerabilities.critical,
      "critical should match",
    );
    assert.equal(
      actual.metadata.vulnerabilities.total,
      expected.metadata.vulnerabilities.total,
      "total should match",
    );
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

    const actual: JsonOutput = JSON.parse(jsonOutput);

    assert.equal(actual.metadata.vulnerabilities.info, 0, "info should match");
    assert.equal(actual.metadata.vulnerabilities.low, 0, "low should match");
    assert.equal(actual.metadata.vulnerabilities.moderate, 1, "moderate should match");
    assert.equal(actual.metadata.vulnerabilities.high, 2, "high should match");
    assert.equal(actual.metadata.vulnerabilities.critical, 3, "critical should match");
    assert.equal(actual.metadata.vulnerabilities.total, 6, "total should match");
    done();
  });
});

describe("Edge Cases and Error Handling", function () {
  it("should handle malformed JSON gracefully", (done: Mocha.Done) => {
    const malformedJson = `{ "metadata": { "vulnerabilities": invalid }`;

    try {
      checkOutputForVulnerabilities(malformedJson, "high", OutputType.Json);
      assert.fail("Should have thrown an error for malformed JSON");
    } catch (error) {
      assert.ok(error, "Should throw an error for malformed JSON");
      done();
    }
  });

  it("should handle info-only vulnerabilities (not break at any level)", (done: Mocha.Done) => {
    const jsonOutput: JsonOutput = {
      metadata: {
        vulnerabilities: {
          info: 5,
          low: 0,
          moderate: 0,
          high: 0,
          critical: 0,
          total: 5,
        },
      },
    };

    const actual = checkOutputForVulnerabilities(
      JSON.stringify(jsonOutput),
      "low",
      OutputType.Json,
    );
    assert.strictEqual(actual.hasVulnerabilities, true, "Should detect vulnerabilities");
    assert.strictEqual(
      actual.breakBuild,
      false,
      "Info-only should not break build even at low level",
    );
    done();
  });

  it("should handle output with no vulnerability pattern", (done: Mocha.Done) => {
    const output = "Scanned 100 packages. Everything looks good!";

    const actual = checkOutputForVulnerabilities(output, "high", OutputType.Standard);
    assert.strictEqual(actual.hasVulnerabilities, false, "Should not find vulnerabilities");
    assert.strictEqual(actual.breakBuild, false, "Should not break build");
    done();
  });

  it("should handle empty output", (done: Mocha.Done) => {
    const output = "";

    const actual = checkOutputForVulnerabilities(output, "high", OutputType.Standard);
    assert.strictEqual(
      actual.hasVulnerabilities,
      false,
      "Should not find vulnerabilities in empty output",
    );
    assert.strictEqual(actual.breakBuild, false, "Should not break build on empty output");
    done();
  });

  it("should handle high level with only low vulnerabilities", (done: Mocha.Done) => {
    const output = "found 10 low vulnerabilities";

    const actual = checkOutputForVulnerabilities(output, "high", OutputType.Standard);
    assert.strictEqual(actual.hasVulnerabilities, true, "Should detect vulnerabilities");
    assert.strictEqual(
      actual.breakBuild,
      false,
      "Should not break build on low vulns when level is high",
    );
    done();
  });

  it("should handle critical level with moderate vulnerabilities", (done: Mocha.Done) => {
    const output = "found 5 moderate vulnerabilities";

    const actual = checkOutputForVulnerabilities(output, "critical", OutputType.Standard);
    assert.strictEqual(actual.hasVulnerabilities, true, "Should detect vulnerabilities");
    assert.strictEqual(
      actual.breakBuild,
      false,
      "Should not break build on moderate vulns when level is critical",
    );
    done();
  });

  it("should handle mixed severity with plurals", (done: Mocha.Done) => {
    const output = "found 10 vulnerabilities (5 low, 3 moderate, 2 high) in 200 packages";

    const actual = checkOutputForVulnerabilities(output, "high", OutputType.Standard);
    assert.strictEqual(actual.hasVulnerabilities, true, "Should detect vulnerabilities");
    assert.strictEqual(actual.breakBuild, true, "Should break build when high vulns present");
    done();
  });

  it("should not break on only info in JSON", (done: Mocha.Done) => {
    const jsonOutput: JsonOutput = {
      metadata: {
        vulnerabilities: {
          info: 10,
          low: 0,
          moderate: 0,
          high: 0,
          critical: 0,
          total: 10,
        },
      },
    };

    ["low", "moderate", "high", "critical"].forEach((level) => {
      const actual = checkOutputForVulnerabilities(
        JSON.stringify(jsonOutput),
        level,
        OutputType.Json,
      );
      assert.strictEqual(
        actual.breakBuild,
        false,
        `Info-only should not break build at ${level} level`,
      );
    });
    done();
  });

  it("should handle zero total but non-zero counts (edge case)", (done: Mocha.Done) => {
    const jsonOutput = `{
      "metadata": {
        "vulnerabilities": {
          "info": 10,
          "low": 10,
          "moderate": 10,
          "high": 10,
          "critical": 10,
          "total": 0
        }
      }
    }`;

    const actual = checkOutputForVulnerabilities(jsonOutput, "high", OutputType.Json);
    assert.strictEqual(
      actual.hasVulnerabilities,
      false,
      "Should not find vulnerabilities when total is 0",
    );
    assert.strictEqual(actual.breakBuild, true, "Should break build even when total is 0");
    done();
  });

  it("should detect vulnerabilities with different number formats", (done: Mocha.Done) => {
    const actual1 = checkOutputForVulnerabilities("1 critical", "critical", OutputType.Standard);
    assert.strictEqual(actual1.breakBuild, true, "Should detect single digit");

    const actual2 = checkOutputForVulnerabilities("42 high", "high", OutputType.Standard);
    assert.strictEqual(actual2.breakBuild, true, "Should detect two digits");

    const actual3 = checkOutputForVulnerabilities("123 moderate", "moderate", OutputType.Standard);
    assert.strictEqual(actual3.breakBuild, true, "Should detect three digits");

    const actual4 = checkOutputForVulnerabilities("99999 low", "low", OutputType.Standard);
    assert.strictEqual(actual4.breakBuild, true, "Should detect large numbers");

    done();
  });
});
