import {
  buildCoverageReport,
  coverageReportToMarkdown,
  validateDefinitionFixtureSet,
  validateRepositoryDefinitions
} from "./definition-system.mjs";

const result = validateRepositoryDefinitions();
const fixtureErrors = validateDefinitionFixtureSet();
const errors = [...result.errors, ...fixtureErrors];

if (errors.length > 0) {
  console.error("Definition validation failed:");
  for (const error of errors) {
    console.error(`- ${error}`);
  }
  process.exit(1);
}

const report = buildCoverageReport(result.apiDocuments, result.metadataIndex);
const markdown = coverageReportToMarkdown(report);
const firstLine = markdown.split("\n").find((line) => line.startsWith("Total APIs:"));
console.log(`Definition validation passed. ${firstLine}`);
