import fs from "node:fs";
import process from "node:process";

import {
  stableStringify
} from "./definition-system.mjs";
import {
  buildTier2ProfileReviewManifest,
  generatedTier2ProfileReviewManifestPath,
  writeTier2ProfileReviewManifest
} from "./tier2-profile-review-system.mjs";

const args = new Set(process.argv.slice(2));

if (!args.has("--write") && !args.has("--check"))
{
  console.error("Usage: node tools/def-validator/generate-tier2-profile-review-manifest.mjs --write|--check");
  process.exit(2);
}

const manifest = buildTier2ProfileReviewManifest();
const expected = stableStringify(manifest);

if (args.has("--write"))
{
  writeTier2ProfileReviewManifest(manifest);
  console.log(`Generated Tier 2 profile review manifest. initial=${manifest.summary.initialCandidateBatches} reviewReady=${manifest.summary.reviewReadyBatches} allowlist=${manifest.summary.allowlistGatedBatches} blocked=${manifest.summary.blockedBatches}`);
}
else
{
  const actual = fs.existsSync(generatedTier2ProfileReviewManifestPath) ? fs.readFileSync(generatedTier2ProfileReviewManifestPath, "utf8") : "";
  if (actual !== expected)
  {
    console.error("Generated Tier 2 profile review manifest is stale; run npm run defs:tier2-profile-review:generate.");
    process.exit(1);
  }

  console.log(`Tier 2 profile review manifest generation check passed. batches=${manifest.summary.manifestBatches}`);
}
