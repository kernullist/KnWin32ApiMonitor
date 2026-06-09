import {
  buildCoverageReport,
  coverageReportToMarkdown,
  stableStringify,
  validateRepositoryDefinitions
} from "./definition-system.mjs";

const args = new Set(process.argv.slice(2));
const result = validateRepositoryDefinitions();

if (result.errors.length > 0) {
  console.error("Definition coverage report failed:");
  for (const error of result.errors) {
    console.error(`- ${error}`);
  }
  process.exit(1);
}

const report = buildCoverageReport(result.apiDocuments, result.metadataIndex);

if (args.has("--check")) {
  const requiredStatuses = ["definition_only", "hooked", "smoke_verified"];
  for (const status of requiredStatuses) {
    if ((report.summary.byCoverageStatus[status] ?? 0) <= 0) {
      console.error(`Definition coverage report has no APIs in status bucket ${status}`);
      process.exit(1);
    }
  }

  console.log("Definition coverage report check passed.");
} else if (args.has("--json")) {
  process.stdout.write(stableStringify(report));
} else {
  process.stdout.write(coverageReportToMarkdown(report));
}
