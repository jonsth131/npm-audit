import * as path from 'path';
import * as assert from 'assert';
import * as ttm from 'azure-pipelines-task-lib/mock-test';

describe('npm-audit task tests', function () {

    before(() => {

    });

    after(() => {

    });

    it('should succeed with required inputs', (done: MochaDone) => {
        this.timeout(1000);
    
        let tp = path.join(__dirname, 'requiredInputs.js');
        let tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);
    
        tr.run();
        assert.equal(tr.succeeded, true, 'should have succeeded');
        assert.equal(tr.warningIssues.length, 0, "should have no warnings");
        assert.equal(tr.errorIssues.length, 0, "should have no errors");
        done();
    });

    it('it should fail if missing path', (done: MochaDone) => {
        this.timeout(1000);
    
        let tp = path.join(__dirname, 'missingPath.js');
        let tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);
    
        tr.run();
        assert.equal(tr.succeeded, false, 'should have failed');
        assert.equal(tr.warningIssues, 0, "should have no warnings");
        assert.equal(tr.errorIssues.length, 1, "should have 1 error issue");
        assert.equal(tr.errorIssues[0], 'Input required: path', 'error issue output');    
        done();
    });

    it('it should fail if missing level', (done: MochaDone) => {
        this.timeout(1000);
    
        let tp = path.join(__dirname, 'missingLevel.js');
        let tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);
    
        tr.run();
        assert.equal(tr.succeeded, false, 'should have failed');
        assert.equal(tr.warningIssues, 0, "should have no warnings");
        assert.equal(tr.errorIssues.length, 1, "should have 1 error issue");
        assert.equal(tr.errorIssues[0], 'Input required: level', 'error issue output');    
        done();
    });

    it('it should fail if invalid level', (done: MochaDone) => {
        this.timeout(1000);
    
        let tp = path.join(__dirname, 'invalidLevel.js');
        let tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);
    
        tr.run();
        assert.equal(tr.succeeded, false, 'should have failed');
        assert.equal(tr.warningIssues, 0, "should have no warnings");
        assert.equal(tr.errorIssues.length, 1, "should have 1 error issue");
        assert.equal(tr.errorIssues[0], 'Unexpected level', 'error issue output');    
        done();
    });

    it('it should fail if vulnerabilites are found', (done: MochaDone) => {
        this.timeout(1000);
    
        let tp = path.join(__dirname, 'failOnFoundLevel.js');
        let tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);
    
        tr.run();
        assert.equal(tr.succeeded, false, 'should have failed');
        assert.equal(tr.warningIssues, 0, "should have no warnings");
        assert.equal(tr.errorIssues.length, 1, "should have 1 error issue");
        assert.equal(tr.errorIssues[0], 'Vulnerabilities found', 'error issue output');    
        done();
    });

    it('should append --production if only production flag is set', (done: MochaDone) => {
        this.timeout(1000);
    
        let tp = path.join(__dirname, 'productionFlag.js');
        let tr: ttm.MockTestRunner = new ttm.MockTestRunner(tp);
    
        tr.run();
        assert.equal(tr.succeeded, true, 'should have succeeded');
        assert.equal(tr.warningIssues.length, 0, "should have no warnings");
        assert.equal(tr.errorIssues.length, 0, "should have no errors");
        done();
    });
});