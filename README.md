# npm-audit

[![Build Status](https://dev.azure.com/jonas1111/jonas1111/_apis/build/status/jonsth131.npm-audit?branchName=master)](https://dev.azure.com/jonas1111/jonas1111/_build/latest?definitionId=1&branchName=master) [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=jonsth131_npm-audit&metric=alert_status)](https://sonarcloud.io/dashboard?id=jonsth131_npm-audit)

Azure DevOps build task to run npm audit and fail if vulnerabilities are found

## How to use

After installing the extension it will be available as a build task to add to your build pipelines.

After adding the task to a build pipeline you have to configure the task by setting the working directory npm audit will be run from, and the minimum level the task will fail at. The default level is set to High.

To add the task to a pipeline, the following options exist.

```
- task: npm-audit@1
  inputs:
    path: '$(Build.SourcesDirectory)'
    productionOnly: true
    recursive: true
    level: 'high'
    registry: 'my-registry'
    jsonOutput: true
    jsonOutputPath: 'path to export results'
    breakBuild: true
```

| Variable         | Required | Description                                                                                                                                       |
| ---------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `path`           | Yes      | The path where to run the `dotnet list package` command                                                                                           |
| `productionOnly` | No       | Should the scan skip dev dependencies, default is `false`                                                                                         |
| `recursive`      | No       | If all recursive package-lock.json files should be scanned, default is `false`                                                                    |
| `level`          | Yes      | Which level a build will break on if vulnerabilities are found. Available options are `low`, `moderate`, `high` and `critical`, default is `high` |
| `registry`       | No       | Optional registry to use                                                                                                                          |
| `jsonOutput`     | No       | Output result as JSON                                                                                                                             |
| `jsonOutputPath` | No       | Output JSON result to files in selected directory                                                                                                 |
| `breakBuild`     | No       | If found vulnerabilities should break the build, otherwise it will emit a warning, default is `true`                                              |
