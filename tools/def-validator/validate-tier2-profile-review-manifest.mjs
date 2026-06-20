import process from "node:process";

import {
  loadTier2ProfileBatchPlan
} from "./tier2-profile-batch-system.mjs";
import {
  loadTier2ProfileReviewManifest,
  validateTier2ProfileReviewManifest
} from "./tier2-profile-review-system.mjs";

const errors = validateTier2ProfileReviewManifest(loadTier2ProfileReviewManifest(), loadTier2ProfileBatchPlan());

if (errors.length > 0)
{
  console.error("Tier 2 profile review manifest validation failed:");
  for (const error of errors)
  {
    console.error(`- ${error}`);
  }
  process.exit(1);
}

const manifest = loadTier2ProfileReviewManifest();
console.log(`Tier 2 profile review manifest validation passed. initial=${manifest.summary.initialCandidateBatches} reviewReady=${manifest.summary.reviewReadyBatches} allowlist=${manifest.summary.allowlistGatedBatches} blocked=${manifest.summary.blockedBatches}`);
