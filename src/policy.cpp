// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "brf/policy.hpp"

#include <algorithm>

namespace brf {

const char* to_string(GuaranteeClass cls) noexcept {
  switch (cls) {
    case GuaranteeClass::kScavenger: return "SCAVENGER";
    case GuaranteeClass::kPreemptible: return "PREEMPTIBLE";
    case GuaranteeClass::kProtected: return "PROTECTED";
    case GuaranteeClass::kGuaranteed: return "GUARANTEED";
  }
  return "UNKNOWN";
}

Result<GuaranteeClass> parse_guarantee_class(std::string_view text) noexcept {
  if (text == "SCAVENGER") return GuaranteeClass::kScavenger;
  if (text == "PREEMPTIBLE") return GuaranteeClass::kPreemptible;
  if (text == "PROTECTED") return GuaranteeClass::kProtected;
  if (text == "GUARANTEED") return GuaranteeClass::kGuaranteed;
  return make_error(ErrorCode::kInvalidArgument, "unknown guarantee class");
}

bool PolicyRecord::materially_differs(const PolicyRecord& other) const noexcept {
  return allow_recall_guaranteed != other.allow_recall_guaranteed ||
         allow_recall_protected != other.allow_recall_protected ||
         allow_preemption_on_commit != other.allow_preemption_on_commit ||
         max_preemption_victims != other.max_preemption_victims ||
         allow_overcommit != other.allow_overcommit ||
         overcommit_allowance != other.overcommit_allowance ||
         auto_revalidate_on_generation_change != other.auto_revalidate_on_generation_change ||
         policy_headroom != other.policy_headroom ||
         minimum_reservation_amount != other.minimum_reservation_amount;
}

bool operator==(const PolicyRecord& a, const PolicyRecord& b) noexcept {
  return a.name == b.name && a.generation == b.generation &&
         a.allow_recall_guaranteed == b.allow_recall_guaranteed &&
         a.allow_recall_protected == b.allow_recall_protected &&
         a.allow_preemption_on_commit == b.allow_preemption_on_commit &&
         a.max_preemption_victims == b.max_preemption_victims &&
         a.default_recall_grace == b.default_recall_grace && a.allow_overcommit == b.allow_overcommit &&
         a.overcommit_allowance == b.overcommit_allowance &&
         a.minimum_reservation_amount == b.minimum_reservation_amount && a.allow_past_start == b.allow_past_start &&
         a.max_future_horizon == b.max_future_horizon &&
         a.max_extra_headroom == b.max_extra_headroom &&
         a.auto_revalidate_on_generation_change == b.auto_revalidate_on_generation_change &&
         a.policy_headroom == b.policy_headroom && a.max_conflict_set == b.max_conflict_set &&
         a.max_explanation_bytes == b.max_explanation_bytes && a.max_series_members == b.max_series_members &&
         a.max_hold_ttl == b.max_hold_ttl && a.max_holds_per_session == b.max_holds_per_session &&
         a.max_hold_bandwidth == b.max_hold_bandwidth;
}

Status validate_policy(const PolicyRecord& record) {
  if (record.name.empty()) {
    return make_error(ErrorCode::kInvalidName, "policy record has an empty name");
  }
  if (record.max_conflict_set == 0 || record.max_conflict_set > 4096) {
    return make_error(ErrorCode::kInvalidArgument, "max_conflict_set must be within [1, 4096]");
  }
  if (record.max_explanation_bytes < 128 || record.max_explanation_bytes > 65536) {
    return make_error(ErrorCode::kInvalidArgument, "max_explanation_bytes must be within [128, 65536]");
  }
  if (record.max_series_members == 0 || record.max_series_members > 4096) {
    return make_error(ErrorCode::kInvalidArgument, "max_series_members must be within [1, 4096]");
  }
  if (record.max_holds_per_session > 4096) {
    return make_error(ErrorCode::kInvalidArgument, "max_holds_per_session is unreasonably large");
  }
  if (record.max_preemption_victims > 1024) {
    return make_error(ErrorCode::kInvalidArgument, "max_preemption_victims is unreasonably large");
  }
  if (record.overcommit_allowance.bps < 0 || record.overcommit_allowance.bps > kMaxBandwidthBps) {
    return make_error(ErrorCode::kInvalidBandwidth, "overcommit allowance is out of range");
  }
  if (record.policy_headroom.bps < 0 || record.policy_headroom.bps > kMaxBandwidthBps) {
    return make_error(ErrorCode::kInvalidBandwidth, "policy headroom is out of range");
  }
  if (record.max_extra_headroom.bps < 0 || record.max_extra_headroom.bps > kMaxBandwidthBps) {
    return make_error(ErrorCode::kInvalidBandwidth, "maximum extra headroom is out of range");
  }
  if (record.minimum_reservation_amount.bps < 0 ||
      record.minimum_reservation_amount.bps > kMaxBandwidthBps) {
    return make_error(ErrorCode::kInvalidBandwidth, "minimum reservation amount is out of range");
  }
  if (record.max_hold_bandwidth.bps < 0 || record.max_hold_bandwidth.bps > kMaxBandwidthBps) {
    return make_error(ErrorCode::kInvalidBandwidth, "maximum hold bandwidth is out of range");
  }
  if (record.max_future_horizon.ns < 0 || record.max_future_horizon.ns > kMaxReservationSpanNs) {
    return make_error(ErrorCode::kInvalidInterval, "maximum future horizon is out of range");
  }
  if (record.default_recall_grace.ns < 0 || record.default_recall_grace.ns > kMaxReservationSpanNs) {
    return make_error(ErrorCode::kInvalidInterval, "default recall grace is out of range");
  }
  if (record.max_hold_ttl.ns < 0 || record.max_hold_ttl.ns > kMaxReservationSpanNs) {
    return make_error(ErrorCode::kInvalidInterval, "maximum hold TTL is out of range");
  }
  return {};
}

Result<bool> PolicyRegistry::apply(const PolicyRecord& record) {
  Status valid = validate_policy(record);
  if (!valid) return valid.error();

  auto it = entries_.find(record.name);
  if (it == entries_.end()) {
    Entry entry;
    entry.record = record;
    entry.ingested_at = record.ingested_at;
    entries_.emplace(record.name, std::move(entry));
    return true;
  }
  Entry& entry = it->second;
  if (record.generation == entry.record.generation) {
    if (!(record == entry.record)) {
      return make_error(ErrorCode::kConflict,
                        "policy '" + record.name.str() +
                            "' was re-declared at the same generation with different content");
    }
    return false;
  }
  if (record.generation < entry.record.generation) {
    return make_error(ErrorCode::kStaleGeneration,
                      "policy '" + record.name.str() + "' was offered a stale generation");
  }
  const PolicyRecord previous = entry.record;
  Entry next;
  next.record = record;
  next.ingested_at = record.ingested_at;
  next.prior_generations = entry.prior_generations;
  next.prior_generations.push_back(previous.generation);
  entry = std::move(next);
  return true;
}

void PolicyRegistry::inject(Entry entry) { entries_[entry.record.name] = std::move(entry); }

const PolicyRegistry::Entry* PolicyRegistry::find(const PolicyName& name) const noexcept {
  auto it = entries_.find(name);
  return it == entries_.end() ? nullptr : &it->second;
}

const PolicyRecord* PolicyRegistry::current(const PolicyName& name) const noexcept {
  const Entry* entry = find(name);
  return entry == nullptr ? nullptr : &entry->record;
}

std::vector<PolicyName> PolicyRegistry::policy_names() const {
  std::vector<PolicyName> names;
  names.reserve(entries_.size());
  for (const auto& pair : entries_) {
    names.push_back(pair.first);
  }
  return names;
}

PolicyRecord PolicyRegistry::strict_default(PolicyName name) {
  PolicyRecord record;
  record.name = name;
  record.generation = PolicyGeneration(1);
  record.allow_recall_guaranteed = false;
  record.allow_recall_protected = true;
  record.allow_preemption_on_commit = false;
  record.max_preemption_victims = 0;
  record.default_recall_grace = Duration{0};
  record.allow_overcommit = false;
  record.overcommit_allowance = Bandwidth{0};
  record.minimum_reservation_amount = Bandwidth{0};
  record.allow_past_start = false;
  record.max_future_horizon = Duration{0};
  record.max_extra_headroom = Bandwidth{0};
  record.auto_revalidate_on_generation_change = false;
  record.policy_headroom = Bandwidth{0};
  record.max_conflict_set = 64;
  record.max_explanation_bytes = 4096;
  record.max_series_members = 64;
  record.max_hold_ttl = Duration{5 * kNsPerSecond};
  record.max_holds_per_session = 16;
  record.max_hold_bandwidth = Bandwidth{1000000000LL};
  return record;
}

}  // namespace brf
