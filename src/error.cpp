// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "brf/error.hpp"

namespace brf {

const char* to_string(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::kOk: return "OK";
    case ErrorCode::kInvalidArgument: return "INVALID_ARGUMENT";
    case ErrorCode::kInvalidInterval: return "INVALID_INTERVAL";
    case ErrorCode::kInvalidBandwidth: return "INVALID_BANDWIDTH";
    case ErrorCode::kInvalidIdentity: return "INVALID_IDENTITY";
    case ErrorCode::kInvalidName: return "INVALID_NAME";
    case ErrorCode::kOverflow: return "OVERFLOW";
    case ErrorCode::kNotFound: return "NOT_FOUND";
    case ErrorCode::kAlreadyExists: return "ALREADY_EXISTS";
    case ErrorCode::kGenerationMismatch: return "GENERATION_MISMATCH";
    case ErrorCode::kStaleEpoch: return "STALE_EPOCH";
    case ErrorCode::kStaleGeneration: return "STALE_GENERATION";
    case ErrorCode::kFencedClaimant: return "CLAIMANT_FENCED";
    case ErrorCode::kAuthorityRequired: return "AUTHORITY_REQUIRED";
    case ErrorCode::kPolicyRejected: return "POLICY_REJECTED";
    case ErrorCode::kInsufficientCapacity: return "INSUFFICIENT_CAPACITY";
    case ErrorCode::kCapacityOvercommit: return "CAPACITY_OVERCOMMIT";
    case ErrorCode::kIllegalTransition: return "ILLEGAL_TRANSITION";
    case ErrorCode::kIdempotentReplay: return "IDEMPOTENT_REPLAY";
    case ErrorCode::kConflict: return "CONFLICT";
    case ErrorCode::kCorrupt: return "CORRUPT";
    case ErrorCode::kTornTail: return "TORN_TAIL";
    case ErrorCode::kIo: return "IO";
    case ErrorCode::kUnsupported: return "UNSUPPORTED";
    case ErrorCode::kResourceExhausted: return "RESOURCE_EXHAUSTED";
    case ErrorCode::kCancelled: return "CANCELLED";
    case ErrorCode::kShuttingDown: return "SHUTTING_DOWN";
    case ErrorCode::kInternal: return "INTERNAL";
  }
  return "UNKNOWN";
}

bool is_authority_refusal(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::kStaleEpoch:
    case ErrorCode::kStaleGeneration:
    case ErrorCode::kGenerationMismatch:
    case ErrorCode::kFencedClaimant:
    case ErrorCode::kAuthorityRequired:
      return true;
    default:
      return false;
  }
}

}  // namespace brf
