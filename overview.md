Build extension to run npm audit and fail the build on found vulnerabilities.

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
