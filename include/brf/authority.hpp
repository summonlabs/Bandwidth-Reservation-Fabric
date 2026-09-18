// Bandwidth Reservation Fabric - provenance, bindings, and the authority vector.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef BRF_AUTHORITY_HPP
#define BRF_AUTHORITY_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "brf/bandwidth.hpp"
#include "brf/clock.hpp"
#include "brf/error.hpp"
#include "brf/identity.hpp"
#include "brf/time.hpp"

namespace brf {

using FailureDomainGeneration = Counter<struct FailureDomainGenerationTag>;

/// Maximum width of a single reservation binding: the number of exact resource
/// references one commitment may cover.
inline constexpr std::size_t kMaxBindingResources = 64;

/// Maximum number of provenance reason characters retained. Longer reasons are
/// truncated deterministically at a character boundary, never rejected, so an
/// over-long explanation can never fail an authority-bearing operation.
inline constexpr std::size_t kMaxProvenanceReasonBytes = 512;

/// Replaces any byte outside printable ASCII with '.', collapses repeats of '.',
/// and truncates to the bound. Deterministic: identical input yields identical
/// output on every platform.
[[nodiscard]] std::string sanitize_reason(std::string_view text, std::size_t max_bytes = kMaxProvenanceReasonBytes);

/// Exact resource reference: a resource name pinned to one generation. A
/// reference to "the resource by name" is never sufficient authority.
struct ResourceRef {
  ResourceName resource;
  ResourceGeneration generation;

  friend bool operator==(const ResourceRef& a, const ResourceRef& b) noexcept {
    return a.resource == b.resource && a.generation == b.generation;
  }
  friend std::strong_ordering operator<=>(const ResourceRef& a, const ResourceRef& b) noexcept {
    if (a.resource != b.resource) return a.resource <=> b.resource;
    return a.generation <=> b.generation;
  }
};

struct FailureDomainRef {
  FailureDomainName domain;
  FailureDomainGeneration generation;

  friend bool operator==(const FailureDomainRef& a, const FailureDomainRef& b) noexcept {
    return a.domain == b.domain && a.generation == b.generation;
  }
  friend std::strong_ordering operator<=>(const FailureDomainRef& a, const FailureDomainRef& b) noexcept {
    if (a.domain != b.domain) return a.domain <=> b.domain;
    return a.generation <=> b.generation;
  }
};

/// How a reservation reaches its resources.
enum class BindingKind : std::uint8_t {
  kResources = 0,  ///< Direct, explicit resource set.
  kPath = 1,       ///< Path-bound: components are the expansion of a path authority generation.
};

[[nodiscard]] const char* to_string(BindingKind kind) noexcept;

/// Durable provenance of a single authority-bearing decision.
struct Provenance {
  ActorName actor;                 ///< Software component that issued the request.
  PublisherId publisher;           ///< Stable publisher identity.
  PublisherBootId publisher_boot;  ///< Boot incarnation of the publisher process.
  SessionId session;               ///< Transient session identity (never durable authority).
  AttemptId attempt;               ///< Attempt identity for idempotent retry/reconciliation.
  FabricEpoch fabric_epoch;        ///< Coordinator epoch the decision was made under.
  Identity128 coordinator_boot;    ///< Coordinator boot incarnation.
  Timestamp recorded_at;           ///< Wall-clock instant the decision was recorded.
  DurableSequence sequence;        ///< Durable audit sequence assigned at commit.
  std::string reason;              ///< Bounded, sanitized reason text.

  friend bool operator==(const Provenance& a, const Provenance& b) noexcept;
};

/// The exact set of generations that justified a decision. Revalidation
/// compares a stored vector against the current ledger: any difference is a
/// staleness signal, never a silent upgrade.
struct AuthorityVector {
  FabricEpoch fabric_epoch;
  ReservationGeneration reservation_generation;
  ClaimantId claimant;
  ClaimantGeneration claimant_generation;
  CapacitySnapshotId capacity_snapshot;
  CapacitySnapshotGeneration capacity_generation;
  PolicyName policy;
  PolicyGeneration policy_generation;
  PathAuthorityGeneration path_generation;  ///< Zero when the binding is not path-authorised.
  std::vector<ResourceRef> resources;       ///< Canonical order, unique names.
  std::vector<FailureDomainRef> failure_domains;  ///< Canonical order, unique names.

  friend bool operator==(const AuthorityVector& a, const AuthorityVector& b) noexcept;
  friend bool operator!=(const AuthorityVector& a, const AuthorityVector& b) noexcept { return !(a == b); }
};

/// Canonical ordering and de-duplication of resource references. Two references
/// to the same resource name with different generations are a contradiction and
/// are rejected rather than silently resolved.
[[nodiscard]] Result<std::vector<ResourceRef>> canonicalize_resources(std::vector<ResourceRef> refs);
[[nodiscard]] Result<std::vector<FailureDomainRef>> canonicalize_failure_domains(std::vector<FailureDomainRef> refs);

/// Canonical byte encoding of an authority vector, used as the binding
/// fingerprint for idempotency and for durable integrity comparison.
[[nodiscard]] std::string authority_fingerprint_bytes(const AuthorityVector& authority);

}  // namespace brf

#endif  // BRF_AUTHORITY_HPP
