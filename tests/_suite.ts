import * as path from "path";
import * as assert from "assert";
import * as ttm from "azure-pipelines-task-lib/mock-test";

describe("npm-audit task tests", function() {
    before(() => { });

    after(() => { });

    it("should succeed with required inputs", (done: () => void) => {
        this.timeout(10000);

        let tp = path.join(__dirname, "requiredInputs.js");
        let tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

        tr.run();
        assert.strictEqual(tr.succeeded, true, "should have succeeded" + tr.stdout);
        assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
        assert.strictEqual(tr.errorIssues.length, 0, "should have no errors");
        done();
    });

    it("should fail if missing path", (done: () => void) => {
        this.timeout(10000);

        let tp = path.join(__dirname, "missingPath.js");
        let tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

        tr.run();
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

    it("should fail if missing level", (done: () => void) => {
        this.timeout(10000);

        let tp = path.join(__dirname, "missingLevel.js");
        let tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

        tr.run();
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

    it("should fail if invalid level", (done: () => void) => {
        this.timeout(10000);

        let tp = path.join(__dirname, "invalidLevel.js");
        let tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

        tr.run();
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

    it("should fail if vulnerabilites are found", (done: () => void) => {
        this.timeout(10000);

        let tp = path.join(__dirname, "failOnFoundLevel.js");
        let tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

        tr.run();
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

    it("should append --production if only production flag is set", (done: () => void) => {
        this.timeout(10000);

        let tp = path.join(__dirname, "productionFlag.js");
        let tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

        tr.run();
        assert.strictEqual(tr.succeeded, true, "should have succeeded");
        assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
        assert.strictEqual(tr.errorIssues.length, 0, "should have no errors");
        done();
    });

    it("should append --registry if registry is set", (done: () => void) => {
        this.timeout(10000);

        let tp = path.join(__dirname, "registryPath.js");
        let tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

        tr.run();
        assert.strictEqual(tr.succeeded, true, "should have succeeded");
        assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
        assert.strictEqual(tr.errorIssues.length, 0, "should have no errors");
        done();
    });

    it("should append --json if jsonOutput is set", (done: () => void) => {
        this.timeout(10000);

        let tp = path.join(__dirname, "jsonOutput.js");
        let tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);

        tr.run();
        assert.strictEqual(tr.succeeded, true, "should have succeeded");
        assert.strictEqual(tr.warningIssues.length, 0, "should have no warnings");
        assert.strictEqual(tr.errorIssues.length, 0, "should have no errors");
        done();
    });
});
