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
    if (!Object.prototype.hasOwnProperty.call(report.summary.byCoverageStatus, status)) {
      console.error(`Definition coverage report is missing status bucket ${status}`);
      process.exit(1);
    }
  }

  const coverageTotal = Object.values(report.summary.byCoverageStatus).reduce((sum, count) => sum + count, 0);
  if (coverageTotal !== report.summary.totalApis) {
    console.error(`Definition coverage report total mismatch: total=${report.summary.totalApis} buckets=${coverageTotal}`);
    process.exit(1);
  }

  const implementedCoverage = (report.summary.byCoverageStatus.hooked ?? 0) + (report.summary.byCoverageStatus.smoke_verified ?? 0);
  if (implementedCoverage <= 0) {
    console.error("Definition coverage report has no hooked or smoke_verified APIs.");
    process.exit(1);
  }

  console.log("Definition coverage report check passed.");
} else if (args.has("--json")) {
  process.stdout.write(stableStringify(report));
} else {
  process.stdout.write(coverageReportToMarkdown(report));
}
