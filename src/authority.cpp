// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "brf/authority.hpp"

#include <algorithm>
#include <array>

#include "brf/hash.hpp"
#include "brf/wire.hpp"

namespace brf {
namespace {

[[nodiscard]] bool is_printable(char ch) noexcept {
  const unsigned char raw = static_cast<unsigned char>(ch);
  return raw >= 0x20U && raw <= 0x7EU;
}

}  // namespace

std::string sanitize_reason(std::string_view text, std::size_t max_bytes) {
  std::string out;
  out.reserve(std::min(text.size(), max_bytes));
  bool last_was_dot = false;
  for (char ch : text) {
    if (out.size() >= max_bytes) break;
    char normalized = is_printable(ch) ? ch : '.';
    if (normalized == '.') {
      if (last_was_dot) continue;
      last_was_dot = true;
    } else {
      last_was_dot = false;
    }
    out.push_back(normalized);
  }
  while (!out.empty() && out.back() == '.') {
    out.pop_back();
  }
  return out;
}

const char* to_string(BindingKind kind) noexcept {
  switch (kind) {
    case BindingKind::kResources: return "RESOURCES";
    case BindingKind::kPath: return "PATH";
  }
  return "UNKNOWN";
}

bool operator==(const Provenance& a, const Provenance& b) noexcept {
  return a.actor == b.actor && a.publisher == b.publisher && a.publisher_boot == b.publisher_boot &&
         a.session == b.session && a.attempt == b.attempt && a.fabric_epoch == b.fabric_epoch &&
         a.coordinator_boot == b.coordinator_boot && a.recorded_at == b.recorded_at &&
         a.sequence == b.sequence && a.reason == b.reason;
}

bool operator==(const AuthorityVector& a, const AuthorityVector& b) noexcept {
  return a.fabric_epoch == b.fabric_epoch && a.reservation_generation == b.reservation_generation &&
         a.claimant == b.claimant && a.claimant_generation == b.claimant_generation &&
         a.capacity_snapshot == b.capacity_snapshot && a.capacity_generation == b.capacity_generation &&
         a.policy == b.policy && a.policy_generation == b.policy_generation &&
         a.path_generation == b.path_generation && a.resources == b.resources &&
         a.failure_domains == b.failure_domains;
}

Result<std::vector<ResourceRef>> canonicalize_resources(std::vector<ResourceRef> refs) {
  if (refs.size() > kMaxBindingResources) {
    return make_error(ErrorCode::kResourceExhausted, "resource set exceeds the maximum binding width");
  }
  std::sort(refs.begin(), refs.end());
  for (std::size_t i = 1; i < refs.size(); ++i) {
    if (refs[i].resource == refs[i - 1].resource) {
      if (refs[i].generation == refs[i - 1].generation) {
        refs.erase(refs.begin() + static_cast<std::ptrdiff_t>(i));
        --i;
        continue;
      }
      return make_error(ErrorCode::kConflict,
                        "resource '" + refs[i].resource.str() + "' is bound to two different generations");
    }
  }
  return refs;
}

Result<std::vector<FailureDomainRef>> canonicalize_failure_domains(std::vector<FailureDomainRef> refs) {
  if (refs.size() > kMaxBindingResources) {
    return make_error(ErrorCode::kResourceExhausted, "failure-domain set exceeds the maximum width");
  }
  std::sort(refs.begin(), refs.end());
  for (std::size_t i = 1; i < refs.size(); ++i) {
    if (refs[i].domain == refs[i - 1].domain) {
      if (refs[i].generation == refs[i - 1].generation) {
        refs.erase(refs.begin() + static_cast<std::ptrdiff_t>(i));
        --i;
        continue;
      }
      return make_error(ErrorCode::kConflict, "failure domain is bound to two different generations");
    }
  }
  return refs;
}

std::string authority_fingerprint_bytes(const AuthorityVector& authority) {
  Writer writer(512);
  writer.u64(authority.fabric_epoch.value());
  writer.u64(authority.reservation_generation.value());
  writer.fixed128(authority.claimant);
  writer.u64(authority.claimant_generation.value());
  writer.fixed128(authority.capacity_snapshot);
  writer.u64(authority.capacity_generation.value());
  writer.text(authority.policy.view());
  writer.u64(authority.policy_generation.value());
  writer.u64(authority.path_generation.value());
  writer.count(authority.resources.size());
  for (const ResourceRef& ref : authority.resources) {
    writer.text(ref.resource.view());
    writer.u64(ref.generation.value());
  }
  writer.count(authority.failure_domains.size());
  for (const FailureDomainRef& ref : authority.failure_domains) {
    writer.text(ref.domain.view());
    writer.u64(ref.generation.value());
  }
  return writer.take();
}

}  // namespace brf
