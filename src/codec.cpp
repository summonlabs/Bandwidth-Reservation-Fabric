// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "brf/codec.hpp"

#include "brf/version.hpp"

namespace brf::codec {
namespace {

[[nodiscard]] Status read_string(Reader& r, std::string& out, std::size_t max_size = kMaxTextBytes) {
  Result<std::string_view> raw = r.text(max_size);
  if (!raw) return raw.error();
  out.assign(raw.value().data(), raw.value().size());
  return {};
}

}  // namespace

// --- enums ------------------------------------------------------------------
void encode(Writer& w, BindingKind v) { w.u8(static_cast<std::uint8_t>(v)); }
Status decode(Reader& r, BindingKind& v) {
  Result<std::uint8_t> raw = r.u8();
  if (!raw) return raw.error();
  if (raw.value() > 1) return make_error(ErrorCode::kCorrupt, "unknown binding kind");
  v = raw.value() == 0 ? BindingKind::kResources : BindingKind::kPath;
  return {};
}

void encode(Writer& w, GuaranteeClass v) { w.u8(static_cast<std::uint8_t>(v)); }
Status decode(Reader& r, GuaranteeClass& v) {
  Result<std::uint8_t> raw = r.u8();
  if (!raw) return raw.error();
  if (raw.value() > 3) return make_error(ErrorCode::kCorrupt, "unknown guarantee class");
  v = static_cast<GuaranteeClass>(raw.value());
  return {};
}

void encode(Writer& w, ReservationState v) { w.u8(static_cast<std::uint8_t>(v)); }
Status decode(Reader& r, ReservationState& v) {
  Result<std::uint8_t> raw = r.u8();
  if (!raw) return raw.error();
  if (raw.value() > 14) return make_error(ErrorCode::kCorrupt, "unknown reservation state");
  v = static_cast<ReservationState>(raw.value());
  return {};
}

void encode(Writer& w, Applicability v) { w.u8(static_cast<std::uint8_t>(v)); }
Status decode(Reader& r, Applicability& v) {
  Result<std::uint8_t> raw = r.u8();
  if (!raw) return raw.error();
  if (raw.value() > 2) return make_error(ErrorCode::kCorrupt, "unknown applicability value");
  v = static_cast<Applicability>(raw.value());
  return {};
}

void encode(Writer& w, ApplicabilityReason v) { w.u8(static_cast<std::uint8_t>(v)); }
Status decode(Reader& r, ApplicabilityReason& v) {
  Result<std::uint8_t> raw = r.u8();
  if (!raw) return raw.error();
  if (raw.value() > 8) return make_error(ErrorCode::kCorrupt, "unknown applicability reason");
  v = static_cast<ApplicabilityReason>(raw.value());
  return {};
}

void encode(Writer& w, AdmissionOutcome v) { w.u8(static_cast<std::uint8_t>(v)); }
Status decode(Reader& r, AdmissionOutcome& v) {
  Result<std::uint8_t> raw = r.u8();
  if (!raw) return raw.error();
  if (raw.value() > 15) return make_error(ErrorCode::kCorrupt, "unknown admission outcome");
  v = static_cast<AdmissionOutcome>(raw.value());
  return {};
}

void encode(Writer& w, ErrorCode v) { w.u16(static_cast<std::uint16_t>(v)); }
Status decode(Reader& r, ErrorCode& v) {
  Result<std::uint16_t> raw = r.u16();
  if (!raw) return raw.error();
  if (raw.value() > static_cast<std::uint16_t>(ErrorCode::kInternal)) {
    return make_error(ErrorCode::kCorrupt, "unknown error code");
  }
  v = static_cast<ErrorCode>(raw.value());
  return {};
}

void encode(Writer& w, RecordKind v) { w.u16(static_cast<std::uint16_t>(v)); }
Status decode(Reader& r, RecordKind& v) {
  Result<std::uint16_t> raw = r.u16();
  if (!raw) return raw.error();
  if (raw.value() < 1 || raw.value() > 14) return make_error(ErrorCode::kCorrupt, "unknown record kind");
  v = static_cast<RecordKind>(raw.value());
  return {};
}

void encode(Writer& w, HolderKind v) { w.u8(static_cast<std::uint8_t>(v)); }
Status decode(Reader& r, HolderKind& v) {
  Result<std::uint8_t> raw = r.u8();
  if (!raw) return raw.error();
  if (raw.value() > 1) return make_error(ErrorCode::kCorrupt, "unknown holder kind");
  v = raw.value() == 0 ? HolderKind::kReservation : HolderKind::kHold;
  return {};
}

void encode(Writer& w, const std::optional<Bandwidth>& v) {
  w.boolean(v.has_value());
  if (v.has_value()) encode(w, *v);
}
Status decode(Reader& r, std::optional<Bandwidth>& v) {
  Result<bool> present = r.boolean();
  if (!present) return present.error();
  if (!present.value()) {
    v.reset();
    return {};
  }
  Bandwidth value;
  Status decoded = decode(r, value);
  if (!decoded) return decoded;
  v = value;
  return {};
}

// --- primitives -------------------------------------------------------------
void encode(Writer& w, const Identity128& v) { w.fixed128(v); }
Status decode(Reader& r, Identity128& v) {
  Result<Identity128> raw = r.fixed128();
  if (!raw) return raw.error();
  v = raw.value();
  return {};
}

void encode(Writer& w, const Interval& v) {
  w.i64(v.start.ns);
  w.i64(v.end.ns);
}
Status decode(Reader& r, Interval& v) {
  Result<std::int64_t> start = r.i64();
  if (!start) return start.error();
  Result<std::int64_t> end = r.i64();
  if (!end) return end.error();
  v.start = Timestamp{start.value()};
  v.end = Timestamp{end.value()};
  return {};
}

void encode(Writer& w, const Bandwidth& v) { w.i64(v.bps); }
Status decode(Reader& r, Bandwidth& v) {
  Result<std::int64_t> raw = r.i64();
  if (!raw) return raw.error();
  v = Bandwidth{raw.value()};
  return {};
}

void encode(Writer& w, const Duration& v) { w.i64(v.ns); }
Status decode(Reader& r, Duration& v) {
  Result<std::int64_t> raw = r.i64();
  if (!raw) return raw.error();
  v = Duration{raw.value()};
  return {};
}

void encode(Writer& w, const Timestamp& v) { w.i64(v.ns); }
Status decode(Reader& r, Timestamp& v) {
  Result<std::int64_t> raw = r.i64();
  if (!raw) return raw.error();
  v = Timestamp{raw.value()};
  return {};
}

// --- identity and authority -------------------------------------------------
void encode(Writer& w, const ResourceRef& v) {
  encode(w, v.resource);
  encode(w, v.generation);
}
Status decode(Reader& r, ResourceRef& v) {
  Status a = decode(r, v.resource);
  if (!a) return a;
  return decode(r, v.generation);
}

void encode(Writer& w, const FailureDomainRef& v) {
  encode(w, v.domain);
  encode(w, v.generation);
}
Status decode(Reader& r, FailureDomainRef& v) {
  Status a = decode(r, v.domain);
  if (!a) return a;
  return decode(r, v.generation);
}

void encode(Writer& w, const AuthorityVector& v) {
  encode(w, v.fabric_epoch);
  encode(w, v.reservation_generation);
  w.fixed128(v.claimant);
  encode(w, v.claimant_generation);
  w.fixed128(v.capacity_snapshot);
  encode(w, v.capacity_generation);
  encode(w, v.policy);
  encode(w, v.policy_generation);
  encode(w, v.path_generation);
  encode_list(w, v.resources);
  encode_list(w, v.failure_domains);
}
Status decode(Reader& r, AuthorityVector& v) {
  Status s = decode(r, v.fabric_epoch);
  if (!s) return s;
  s = decode(r, v.reservation_generation);
  if (!s) return s;
  Result<Identity128> claimant = r.fixed128();
  if (!claimant) return claimant.error();
  v.claimant = claimant.value();
  s = decode(r, v.claimant_generation);
  if (!s) return s;
  Result<Identity128> snapshot = r.fixed128();
  if (!snapshot) return snapshot.error();
  v.capacity_snapshot = snapshot.value();
  s = decode(r, v.capacity_generation);
  if (!s) return s;
  s = decode(r, v.policy);
  if (!s) return s;
  s = decode(r, v.policy_generation);
  if (!s) return s;
  s = decode(r, v.path_generation);
  if (!s) return s;
  s = decode_list(r, v.resources);
  if (!s) return s;
  return decode_list(r, v.failure_domains);
}

void encode(Writer& w, const Provenance& v) {
  encode(w, v.actor);
  w.fixed128(v.publisher);
  w.fixed128(v.publisher_boot);
  w.fixed128(v.session);
  w.fixed128(v.attempt);
  encode(w, v.fabric_epoch);
  w.fixed128(v.coordinator_boot);
  encode(w, v.recorded_at);
  encode(w, v.sequence);
  w.text(v.reason);
}
Status decode(Reader& r, Provenance& v) {
  Status s = decode(r, v.actor);
  if (!s) return s;
  Result<Identity128> publisher = r.fixed128();
  if (!publisher) return publisher.error();
  v.publisher = publisher.value();
  Result<Identity128> boot = r.fixed128();
  if (!boot) return boot.error();
  v.publisher_boot = boot.value();
  Result<Identity128> session = r.fixed128();
  if (!session) return session.error();
  v.session = session.value();
  Result<Identity128> attempt = r.fixed128();
  if (!attempt) return attempt.error();
  v.attempt = attempt.value();
  s = decode(r, v.fabric_epoch);
  if (!s) return s;
  Result<Identity128> coordinator = r.fixed128();
  if (!coordinator) return coordinator.error();
  v.coordinator_boot = coordinator.value();
  s = decode(r, v.recorded_at);
  if (!s) return s;
  s = decode(r, v.sequence);
  if (!s) return s;
  return read_string(r, v.reason, kMaxProvenanceReasonBytes);
}

// --- capacity ---------------------------------------------------------------
void encode(Writer& w, const MaintenanceWindow& v) {
  encode(w, v.interval);
  w.text(v.reason);
}
Status decode(Reader& r, MaintenanceWindow& v) {
  Status s = decode(r, v.interval);
  if (!s) return s;
  return read_string(r, v.reason, 256);
}

void encode(Writer& w, const ResourceCapacity& v) {
  encode(w, v.resource);
  encode(w, v.generation);
  encode(w, v.reservable_capacity);
  encode(w, v.protected_headroom);
  encode(w, v.failure_domain);
  encode(w, v.failure_domain_generation);
  encode_list(w, v.maintenance);
}
Status decode(Reader& r, ResourceCapacity& v) {
  Status s = decode(r, v.resource);
  if (!s) return s;
  s = decode(r, v.generation);
  if (!s) return s;
  s = decode(r, v.reservable_capacity);
  if (!s) return s;
  s = decode(r, v.protected_headroom);
  if (!s) return s;
  s = decode(r, v.failure_domain);
  if (!s) return s;
  s = decode(r, v.failure_domain_generation);
  if (!s) return s;
  return decode_list(r, v.maintenance);
}

void encode(Writer& w, const CapacitySnapshot& v) {
  w.fixed128(v.id);
  encode(w, v.generation);
  encode(w, v.fabric_epoch);
  encode(w, v.ingested_at);
  w.boolean(v.complete);
  encode_list(w, v.resources);
}
Status decode(Reader& r, CapacitySnapshot& v) {
  Result<Identity128> id = r.fixed128();
  if (!id) return id.error();
  v.id = id.value();
  Status s = decode(r, v.generation);
  if (!s) return s;
  s = decode(r, v.fabric_epoch);
  if (!s) return s;
  s = decode(r, v.ingested_at);
  if (!s) return s;
  Result<bool> complete = r.boolean();
  if (!complete) return complete.error();
  v.complete = complete.value();
  return decode_list(r, v.resources);
}

void encode(Writer& w, const PathAuthority& v) {
  encode(w, v.path);
  encode(w, v.generation);
  encode_list(w, v.components);
  encode(w, v.issued_at);
  w.boolean(v.retired);
}
Status decode(Reader& r, PathAuthority& v) {
  Status s = decode(r, v.path);
  if (!s) return s;
  s = decode(r, v.generation);
  if (!s) return s;
  s = decode_list(r, v.components);
  if (!s) return s;
  s = decode(r, v.issued_at);
  if (!s) return s;
  Result<bool> retired = r.boolean();
  if (!retired) return retired.error();
  v.retired = retired.value();
  return {};
}

void encode(Writer& w, const PathAuthoritySnapshot& v) {
  w.fixed128(v.id);
  encode(w, v.generation);
  encode(w, v.fabric_epoch);
  encode(w, v.ingested_at);
  w.boolean(v.complete);
  encode_list(w, v.paths);
}
Status decode(Reader& r, PathAuthoritySnapshot& v) {
  Result<Identity128> id = r.fixed128();
  if (!id) return id.error();
  v.id = id.value();
  Status s = decode(r, v.generation);
  if (!s) return s;
  s = decode(r, v.fabric_epoch);
  if (!s) return s;
  s = decode(r, v.ingested_at);
  if (!s) return s;
  Result<bool> complete = r.boolean();
  if (!complete) return complete.error();
  v.complete = complete.value();
  return decode_list(r, v.paths);
}

// --- policy -----------------------------------------------------------------
void encode(Writer& w, const PolicyRecord& v) {
  encode(w, v.name);
  encode(w, v.generation);
  encode(w, v.ingested_at);
  w.boolean(v.allow_recall_guaranteed);
  w.boolean(v.allow_recall_protected);
  w.boolean(v.allow_preemption_on_commit);
  w.u32(v.max_preemption_victims);
  encode(w, v.default_recall_grace);
  w.boolean(v.allow_overcommit);
  encode(w, v.overcommit_allowance);
  encode(w, v.minimum_reservation_amount);
  w.boolean(v.allow_past_start);
  encode(w, v.max_future_horizon);
  encode(w, v.max_extra_headroom);
  w.boolean(v.auto_revalidate_on_generation_change);
  encode(w, v.policy_headroom);
  w.u32(v.max_conflict_set);
  w.u32(v.max_explanation_bytes);
  w.u32(v.max_series_members);
  encode(w, v.max_hold_ttl);
  w.u32(v.max_holds_per_session);
  encode(w, v.max_hold_bandwidth);
}
Status decode(Reader& r, PolicyRecord& v) {
  Status s = decode(r, v.name);
  if (!s) return s;
  s = decode(r, v.generation);
  if (!s) return s;
  s = decode(r, v.ingested_at);
  if (!s) return s;
  Result<bool> b1 = r.boolean();
  if (!b1) return b1.error();
  v.allow_recall_guaranteed = b1.value();
  Result<bool> b2 = r.boolean();
  if (!b2) return b2.error();
  v.allow_recall_protected = b2.value();
  Result<bool> b3 = r.boolean();
  if (!b3) return b3.error();
  v.allow_preemption_on_commit = b3.value();
  Result<std::uint32_t> victims = r.u32();
  if (!victims) return victims.error();
  if (victims.value() > 1024) return make_error(ErrorCode::kCorrupt, "policy victim bound out of range");
  v.max_preemption_victims = victims.value();
  s = decode(r, v.default_recall_grace);
  if (!s) return s;
  Result<bool> b4 = r.boolean();
  if (!b4) return b4.error();
  v.allow_overcommit = b4.value();
  s = decode(r, v.overcommit_allowance);
  if (!s) return s;
  s = decode(r, v.minimum_reservation_amount);
  if (!s) return s;
  Result<bool> b5 = r.boolean();
  if (!b5) return b5.error();
  v.allow_past_start = b5.value();
  s = decode(r, v.max_future_horizon);
  if (!s) return s;
  s = decode(r, v.max_extra_headroom);
  if (!s) return s;
  Result<bool> b6 = r.boolean();
  if (!b6) return b6.error();
  v.auto_revalidate_on_generation_change = b6.value();
  s = decode(r, v.policy_headroom);
  if (!s) return s;
  Result<std::uint32_t> conflict_set = r.u32();
  if (!conflict_set) return conflict_set.error();
  if (conflict_set.value() == 0 || conflict_set.value() > 4096) {
    return make_error(ErrorCode::kCorrupt, "policy conflict-set bound out of range");
  }
  v.max_conflict_set = conflict_set.value();
  Result<std::uint32_t> explanation = r.u32();
  if (!explanation) return explanation.error();
  if (explanation.value() < 128 || explanation.value() > 65536) {
    return make_error(ErrorCode::kCorrupt, "policy explanation bound out of range");
  }
  v.max_explanation_bytes = explanation.value();
  Result<std::uint32_t> series = r.u32();
  if (!series) return series.error();
  if (series.value() == 0 || series.value() > 4096) {
    return make_error(ErrorCode::kCorrupt, "policy series bound out of range");
  }
  v.max_series_members = series.value();
  s = decode(r, v.max_hold_ttl);
  if (!s) return s;
  Result<std::uint32_t> holds = r.u32();
  if (!holds) return holds.error();
  if (holds.value() > 4096) return make_error(ErrorCode::kCorrupt, "policy hold bound out of range");
  v.max_holds_per_session = holds.value();
  return decode(r, v.max_hold_bandwidth);
}

// --- reservation ------------------------------------------------------------
void encode(Writer& w, const RecurrenceSpec& v) {
  w.boolean(v.enabled);
  encode(w, v.period);
  w.u32(v.count);
}
Status decode(Reader& r, RecurrenceSpec& v) {
  Result<bool> enabled = r.boolean();
  if (!enabled) return enabled.error();
  v.enabled = enabled.value();
  Status s = decode(r, v.period);
  if (!s) return s;
  Result<std::uint32_t> count = r.u32();
  if (!count) return count.error();
  if (count.value() > 4096) return make_error(ErrorCode::kCorrupt, "recurrence count out of range");
  v.count = count.value();
  return {};
}

void encode(Writer& w, const ReservationTerms& v) {
  w.fixed128(v.claimant);
  encode(w, v.claimant_generation);
  encode(w, v.binding_kind);
  encode_list(w, v.resources);
  encode(w, v.path);
  encode(w, v.required_path_generation);
  encode(w, v.interval);
  encode(w, v.amount);
  encode(w, v.minimum_amount);
  encode(w, v.maximum_amount);
  encode(w, v.guarantee);
  w.u32(v.priority);
  w.boolean(v.preemptible);
  w.boolean(v.recall_permitted);
  encode(w, v.grace);
  encode(w, v.headroom_requirement);
  encode(w, v.policy);
  encode_list(w, v.policy_labels);
  encode(w, v.recurrence);
}
Status decode(Reader& r, ReservationTerms& v) {
  Result<Identity128> claimant = r.fixed128();
  if (!claimant) return claimant.error();
  v.claimant = claimant.value();
  Status s = decode(r, v.claimant_generation);
  if (!s) return s;
  s = decode(r, v.binding_kind);
  if (!s) return s;
  s = decode_list(r, v.resources);
  if (!s) return s;
  s = decode(r, v.path);
  if (!s) return s;
  s = decode(r, v.required_path_generation);
  if (!s) return s;
  s = decode(r, v.interval);
  if (!s) return s;
  s = decode(r, v.amount);
  if (!s) return s;
  s = decode(r, v.minimum_amount);
  if (!s) return s;
  s = decode(r, v.maximum_amount);
  if (!s) return s;
  s = decode(r, v.guarantee);
  if (!s) return s;
  Result<std::uint32_t> priority = r.u32();
  if (!priority) return priority.error();
  if (priority.value() > kMaxPriority) return make_error(ErrorCode::kCorrupt, "priority out of range");
  v.priority = priority.value();
  Result<bool> preemptible = r.boolean();
  if (!preemptible) return preemptible.error();
  v.preemptible = preemptible.value();
  Result<bool> recall = r.boolean();
  if (!recall) return recall.error();
  v.recall_permitted = recall.value();
  s = decode(r, v.grace);
  if (!s) return s;
  s = decode(r, v.headroom_requirement);
  if (!s) return s;
  s = decode(r, v.policy);
  if (!s) return s;
  Status labels = decode_list(r, v.policy_labels);
  if (!labels) return labels;
  if (v.policy_labels.size() > kMaxPolicyLabels) {
    return make_error(ErrorCode::kResourceExhausted, "too many policy labels");
  }
  for (const std::string& label : v.policy_labels) {
    if (label.size() > kMaxLabelBytes) {
      return make_error(ErrorCode::kCorrupt, "policy label exceeds its bound");
    }
  }
  return decode(r, v.recurrence);
}

void encode(Writer& w, const ReservationRecord& v) {
  w.fixed128(v.id);
  encode(w, v.generation);
  w.boolean(v.series_member);
  w.fixed128(v.series);
  encode(w, v.series_index);
  encode(w, v.terms);
  encode(w, v.authority);
  encode(w, v.state);
  encode(w, v.applicability);
  encode(w, v.applicability_reason);
  encode(w, v.declared_at);
  encode(w, v.committed_at);
  encode(w, v.activated_at);
  encode(w, v.state_changed_at);
  encode(w, v.recall_effective_at);
  encode(w, v.recall_grace);
  encode(w, v.terminated_at);
  w.fixed128(v.predecessor);
  encode(w, v.predecessor_generation);
  w.text(v.state_reason);
  encode(w, v.last_provenance);
  encode(w, v.sequence);
}
Status decode(Reader& r, ReservationRecord& v) {
  Result<Identity128> id = r.fixed128();
  if (!id) return id.error();
  v.id = id.value();
  Status s = decode(r, v.generation);
  if (!s) return s;
  Result<bool> member = r.boolean();
  if (!member) return member.error();
  v.series_member = member.value();
  Result<Identity128> series = r.fixed128();
  if (!series) return series.error();
  v.series = series.value();
  s = decode(r, v.series_index);
  if (!s) return s;
  s = decode(r, v.terms);
  if (!s) return s;
  s = decode(r, v.authority);
  if (!s) return s;
  s = decode(r, v.state);
  if (!s) return s;
  s = decode(r, v.applicability);
  if (!s) return s;
  s = decode(r, v.applicability_reason);
  if (!s) return s;
  s = decode(r, v.declared_at);
  if (!s) return s;
  s = decode(r, v.committed_at);
  if (!s) return s;
  s = decode(r, v.activated_at);
  if (!s) return s;
  s = decode(r, v.state_changed_at);
  if (!s) return s;
  s = decode(r, v.recall_effective_at);
  if (!s) return s;
  s = decode(r, v.recall_grace);
  if (!s) return s;
  s = decode(r, v.terminated_at);
  if (!s) return s;
  Result<Identity128> predecessor = r.fixed128();
  if (!predecessor) return predecessor.error();
  v.predecessor = predecessor.value();
  s = decode(r, v.predecessor_generation);
  if (!s) return s;
  s = read_string(r, v.state_reason, kMaxProvenanceReasonBytes);
  if (!s) return s;
  s = decode(r, v.last_provenance);
  if (!s) return s;
  return decode(r, v.sequence);
}

void encode(Writer& w, const SupersessionEdge& v) {
  w.fixed128(v.predecessor);
  encode(w, v.predecessor_generation);
  w.fixed128(v.successor);
  encode(w, v.successor_generation);
  encode(w, v.recorded_at);
  encode(w, v.sequence);
  w.text(v.reason);
}
Status decode(Reader& r, SupersessionEdge& v) {
  Result<Identity128> predecessor = r.fixed128();
  if (!predecessor) return predecessor.error();
  v.predecessor = predecessor.value();
  Status s = decode(r, v.predecessor_generation);
  if (!s) return s;
  Result<Identity128> successor = r.fixed128();
  if (!successor) return successor.error();
  v.successor = successor.value();
  s = decode(r, v.successor_generation);
  if (!s) return s;
  s = decode(r, v.recorded_at);
  if (!s) return s;
  s = decode(r, v.sequence);
  if (!s) return s;
  return read_string(r, v.reason, kMaxProvenanceReasonBytes);
}

void encode(Writer& w, const ReservationSeries& v) {
  w.fixed128(v.id);
  encode(w, v.generation);
  w.fixed128(v.claimant);
  encode(w, v.claimant_generation);
  encode(w, v.spec);
  encode(w, v.first_interval);
  encode(w, v.amount);
  encode(w, v.state);
  encode(w, v.created_at);
  encode(w, v.state_changed_at);
  w.fixed128(v.predecessor_series_generation);
  encode(w, v.predecessor_generation);
  encode_list(w, v.members);
  encode(w, v.last_provenance);
  encode(w, v.sequence);
}
Status decode(Reader& r, ReservationSeries& v) {
  Result<Identity128> id = r.fixed128();
  if (!id) return id.error();
  v.id = id.value();
  Status s = decode(r, v.generation);
  if (!s) return s;
  Result<Identity128> claimant = r.fixed128();
  if (!claimant) return claimant.error();
  v.claimant = claimant.value();
  s = decode(r, v.claimant_generation);
  if (!s) return s;
  s = decode(r, v.spec);
  if (!s) return s;
  s = decode(r, v.first_interval);
  if (!s) return s;
  s = decode(r, v.amount);
  if (!s) return s;
  s = decode(r, v.state);
  if (!s) return s;
  s = decode(r, v.created_at);
  if (!s) return s;
  s = decode(r, v.state_changed_at);
  if (!s) return s;
  Result<Identity128> predecessor = r.fixed128();
  if (!predecessor) return predecessor.error();
  v.predecessor_series_generation = predecessor.value();
  s = decode(r, v.predecessor_generation);
  if (!s) return s;
  s = decode_list(r, v.members);
  if (!s) return s;
  s = decode(r, v.last_provenance);
  if (!s) return s;
  return decode(r, v.sequence);
}

// --- holds ------------------------------------------------------------------
void encode(Writer& w, const HoldRecord& v) {
  w.fixed128(v.id);
  encode(w, v.generation);
  w.fixed128(v.claimant);
  encode(w, v.claimant_generation);
  w.fixed128(v.session);
  w.fixed128(v.boot);
  encode(w, v.epoch);
  encode(w, v.binding_kind);
  encode_list(w, v.resources);
  encode(w, v.path);
  encode(w, v.path_generation);
  encode(w, v.interval);
  encode(w, v.amount);
  encode(w, v.guarantee);
  encode(w, v.created_at);
  encode(w, v.expires_at);
  w.boolean(v.released);
  encode(w, v.released_at);
  w.text(v.release_reason);
}
Status decode(Reader& r, HoldRecord& v) {
  Result<Identity128> id = r.fixed128();
  if (!id) return id.error();
  v.id = id.value();
  Status s = decode(r, v.generation);
  if (!s) return s;
  Result<Identity128> claimant = r.fixed128();
  if (!claimant) return claimant.error();
  v.claimant = claimant.value();
  s = decode(r, v.claimant_generation);
  if (!s) return s;
  Result<Identity128> session = r.fixed128();
  if (!session) return session.error();
  v.session = session.value();
  Result<Identity128> boot = r.fixed128();
  if (!boot) return boot.error();
  v.boot = boot.value();
  s = decode(r, v.epoch);
  if (!s) return s;
  s = decode(r, v.binding_kind);
  if (!s) return s;
  s = decode_list(r, v.resources);
  if (!s) return s;
  s = decode(r, v.path);
  if (!s) return s;
  s = decode(r, v.path_generation);
  if (!s) return s;
  s = decode(r, v.interval);
  if (!s) return s;
  s = decode(r, v.amount);
  if (!s) return s;
  s = decode(r, v.guarantee);
  if (!s) return s;
  s = decode(r, v.created_at);
  if (!s) return s;
  s = decode(r, v.expires_at);
  if (!s) return s;
  Result<bool> released = r.boolean();
  if (!released) return released.error();
  v.released = released.value();
  s = decode(r, v.released_at);
  if (!s) return s;
  return read_string(r, v.release_reason, kMaxProvenanceReasonBytes);
}

// --- request context --------------------------------------------------------
void encode(Writer& w, const RequestContext& v) {
  encode(w, v.actor);
  w.fixed128(v.publisher);
  w.fixed128(v.publisher_boot);
  w.fixed128(v.session);
  w.fixed128(v.attempt);
  w.fixed128(v.claimant);
  encode(w, v.claimant_generation);
  encode(w, v.asserted_epoch);
  w.text(v.reason);
}
Status decode(Reader& r, RequestContext& v) {
  Status s = decode(r, v.actor);
  if (!s) return s;
  Result<Identity128> publisher = r.fixed128();
  if (!publisher) return publisher.error();
  v.publisher = publisher.value();
  Result<Identity128> boot = r.fixed128();
  if (!boot) return boot.error();
  v.publisher_boot = boot.value();
  Result<Identity128> session = r.fixed128();
  if (!session) return session.error();
  v.session = session.value();
  Result<Identity128> attempt = r.fixed128();
  if (!attempt) return attempt.error();
  v.attempt = attempt.value();
  Result<Identity128> claimant = r.fixed128();
  if (!claimant) return claimant.error();
  v.claimant = claimant.value();
  s = decode(r, v.claimant_generation);
  if (!s) return s;
  s = decode(r, v.asserted_epoch);
  if (!s) return s;
  return read_string(r, v.reason, kMaxProvenanceReasonBytes);
}

// --- durable payloads -------------------------------------------------------
void encode(Writer& w, const ReservationMutation& v) {
  encode(w, v.record);
  w.boolean(v.has_series);
  if (v.has_series) encode(w, v.series);
  encode_list(w, v.members);
  w.boolean(v.has_edge);
  if (v.has_edge) encode(w, v.edge);
  w.boolean(v.supersede_record);
  encode_list(w, v.companions);
  w.boolean(v.has_attempt);
  if (v.has_attempt) encode(w, v.attempt);
}
Status decode(Reader& r, ReservationMutation& v) {
  Status s = decode(r, v.record);
  if (!s) return s;
  Result<bool> has_series = r.boolean();
  if (!has_series) return has_series.error();
  v.has_series = has_series.value();
  if (v.has_series) {
    s = decode(r, v.series);
    if (!s) return s;
  }
  s = decode_list(r, v.members);
  if (!s) return s;
  Result<bool> has_edge = r.boolean();
  if (!has_edge) return has_edge.error();
  v.has_edge = has_edge.value();
  if (v.has_edge) {
    s = decode(r, v.edge);
    if (!s) return s;
  }
  Result<bool> supersede = r.boolean();
  if (!supersede) return supersede.error();
  v.supersede_record = supersede.value();
  s = decode_list(r, v.companions);
  if (!s) return s;
  Result<bool> has_attempt = r.boolean();
  if (!has_attempt) return has_attempt.error();
  v.has_attempt = has_attempt.value();
  if (v.has_attempt) {
    s = decode(r, v.attempt);
    if (!s) return s;
  }
  return {};
}

void encode(Writer& w, const StateMutation& v) {
  w.fixed128(v.id);
  encode(w, v.generation);
  encode(w, v.from_state);
  encode(w, v.to_state);
  encode(w, v.at);
  w.text(v.reason);
  encode(w, v.provenance);
  encode(w, v.recall_effective_at);
  w.boolean(v.has_attempt);
  if (v.has_attempt) encode(w, v.attempt);
}
Status decode(Reader& r, StateMutation& v) {
  Result<Identity128> id = r.fixed128();
  if (!id) return id.error();
  v.id = id.value();
  Status s = decode(r, v.generation);
  if (!s) return s;
  s = decode(r, v.from_state);
  if (!s) return s;
  s = decode(r, v.to_state);
  if (!s) return s;
  s = decode(r, v.at);
  if (!s) return s;
  s = read_string(r, v.reason, kMaxProvenanceReasonBytes);
  if (!s) return s;
  s = decode(r, v.provenance);
  if (!s) return s;
  s = decode(r, v.recall_effective_at);
  if (!s) return s;
  Result<bool> has_attempt = r.boolean();
  if (!has_attempt) return has_attempt.error();
  v.has_attempt = has_attempt.value();
  if (v.has_attempt) {
    return decode(r, v.attempt);
  }
  return {};
}

void encode(Writer& w, const ApplicabilityMutation& v) {
  w.fixed128(v.id);
  encode(w, v.generation);
  encode(w, v.applicability);
  encode(w, v.reason);
  encode(w, v.at);
}
Status decode(Reader& r, ApplicabilityMutation& v) {
  Result<Identity128> id = r.fixed128();
  if (!id) return id.error();
  v.id = id.value();
  Status s = decode(r, v.generation);
  if (!s) return s;
  s = decode(r, v.applicability);
  if (!s) return s;
  s = decode(r, v.reason);
  if (!s) return s;
  return decode(r, v.at);
}

void encode(Writer& w, const AttemptMutation& v) {
  w.fixed128(v.attempt);
  w.fixed128(v.fingerprint);
  encode(w, v.outcome);
  w.fixed128(v.reservation);
  encode(w, v.generation);
  encode(w, v.result_sequence);
  w.fixed128(v.claimant);
  encode(w, v.at);
}
Status decode(Reader& r, AttemptMutation& v) {
  Result<Identity128> attempt = r.fixed128();
  if (!attempt) return attempt.error();
  v.attempt = attempt.value();
  Result<Identity128> fingerprint = r.fixed128();
  if (!fingerprint) return fingerprint.error();
  v.fingerprint = fingerprint.value();
  Status s = decode(r, v.outcome);
  if (!s) return s;
  Result<Identity128> reservation = r.fixed128();
  if (!reservation) return reservation.error();
  v.reservation = reservation.value();
  s = decode(r, v.generation);
  if (!s) return s;
  s = decode(r, v.result_sequence);
  if (!s) return s;
  Result<Identity128> claimant = r.fixed128();
  if (!claimant) return claimant.error();
  v.claimant = claimant.value();
  return decode(r, v.at);
}

void encode(Writer& w, const EpochMutation& v) {
  encode(w, v.epoch);
  w.fixed128(v.coordinator_boot);
  encode(w, v.at);
}
Status decode(Reader& r, EpochMutation& v) {
  Status s = decode(r, v.epoch);
  if (!s) return s;
  Result<Identity128> boot = r.fixed128();
  if (!boot) return boot.error();
  v.coordinator_boot = boot.value();
  return decode(r, v.at);
}

void encode(Writer& w, const FenceMutation& v) {
  w.fixed128(v.claimant);
  encode(w, v.claimant_generation);
  w.fixed128(v.boot);
  w.fixed128(v.session);
  encode(w, v.at);
  w.text(v.reason);
  w.boolean(v.claimant_wide);
}
Status decode(Reader& r, FenceMutation& v) {
  Result<Identity128> claimant = r.fixed128();
  if (!claimant) return claimant.error();
  v.claimant = claimant.value();
  Status s = decode(r, v.claimant_generation);
  if (!s) return s;
  Result<Identity128> boot = r.fixed128();
  if (!boot) return boot.error();
  v.boot = boot.value();
  Result<Identity128> session = r.fixed128();
  if (!session) return session.error();
  v.session = session.value();
  s = decode(r, v.at);
  if (!s) return s;
  s = read_string(r, v.reason, kMaxProvenanceReasonBytes);
  if (!s) return s;
  Result<bool> wide = r.boolean();
  if (!wide) return wide.error();
  v.claimant_wide = wide.value();
  return {};
}

void encode(Writer& w, const ClaimantMutation& v) {
  w.fixed128(v.claimant);
  encode(w, v.generation);
  encode(w, v.at);
}
Status decode(Reader& r, ClaimantMutation& v) {
  Result<Identity128> claimant = r.fixed128();
  if (!claimant) return claimant.error();
  v.claimant = claimant.value();
  Status s = decode(r, v.generation);
  if (!s) return s;
  return decode(r, v.at);
}

void encode(Writer& w, const OvercommitMutation& v) {
  encode(w, v.resource);
  encode(w, v.generation);
  encode(w, v.committed_peak);
  encode(w, v.ceiling);
  encode(w, v.window);
  encode(w, v.at);
  w.boolean(v.resolved);
}
Status decode(Reader& r, OvercommitMutation& v) {
  Status s = decode(r, v.resource);
  if (!s) return s;
  s = decode(r, v.generation);
  if (!s) return s;
  s = decode(r, v.committed_peak);
  if (!s) return s;
  s = decode(r, v.ceiling);
  if (!s) return s;
  s = decode(r, v.window);
  if (!s) return s;
  s = decode(r, v.at);
  if (!s) return s;
  Result<bool> resolved = r.boolean();
  if (!resolved) return resolved.error();
  v.resolved = resolved.value();
  return {};
}

void encode(Writer& w, const RetireMutation& v) {
  encode_list(w, v.ids);
  encode_list(w, v.generations);
  encode(w, v.at);
}
Status decode(Reader& r, RetireMutation& v) {
  Status s = decode_list(r, v.ids);
  if (!s) return s;
  s = decode_list(r, v.generations);
  if (!s) return s;
  if (v.ids.size() != v.generations.size()) {
    return make_error(ErrorCode::kCorrupt, "retire mutation identity/generation arrays are not parallel");
  }
  return decode(r, v.at);
}

void encode(Writer& w, const CapacityMutation& v) {
  encode(w, v.snapshot);
  encode_list(w, v.withdrawals);
}
Status decode(Reader& r, CapacityMutation& v) {
  Status s = decode(r, v.snapshot);
  if (!s) return s;
  return decode_list(r, v.withdrawals);
}

void encode(Writer& w, const DurableRecord& v) {
  encode(w, v.kind);
  switch (v.kind) {
    case RecordKind::kFabricBoot:
      encode(w, v.epoch);
      break;
    case RecordKind::kCapacitySnapshot:
      encode(w, v.capacity);
      break;
    case RecordKind::kPathSnapshot:
      encode(w, v.path);
      break;
    case RecordKind::kPolicyRecord:
      encode(w, v.policy);
      break;
    case RecordKind::kReservationCommit:
    case RecordKind::kReservationAmend:
      encode(w, v.reservation);
      break;
    case RecordKind::kReservationSeries:
      encode(w, v.reservation);
      break;
    case RecordKind::kReservationState:
      encode(w, v.state);
      break;
    case RecordKind::kReservationApplicability:
      encode(w, v.applicability);
      break;
    case RecordKind::kAttemptOutcome:
      encode(w, v.attempt);
      break;
    case RecordKind::kOvercommit:
      encode(w, v.overcommit);
      break;
    case RecordKind::kRetire:
      encode(w, v.retire);
      break;
    case RecordKind::kFence:
      encode(w, v.fence);
      break;
    case RecordKind::kClaimantRegistration:
      encode(w, v.claimant);
      break;
  }
}

Status decode(Reader& r, DurableRecord& v) {
  Status s = decode(r, v.kind);
  if (!s) return s;
  switch (v.kind) {
    case RecordKind::kFabricBoot:
      return decode(r, v.epoch);
    case RecordKind::kCapacitySnapshot:
      return decode(r, v.capacity);
    case RecordKind::kPathSnapshot:
      return decode(r, v.path);
    case RecordKind::kPolicyRecord:
      return decode(r, v.policy);
    case RecordKind::kReservationCommit:
    case RecordKind::kReservationAmend:
      return decode(r, v.reservation);
    case RecordKind::kReservationSeries:
      return decode(r, v.reservation);
    case RecordKind::kReservationState:
      return decode(r, v.state);
    case RecordKind::kReservationApplicability:
      return decode(r, v.applicability);
    case RecordKind::kAttemptOutcome:
      return decode(r, v.attempt);
    case RecordKind::kOvercommit:
      return decode(r, v.overcommit);
    case RecordKind::kRetire:
      return decode(r, v.retire);
    case RecordKind::kFence:
      return decode(r, v.fence);
    case RecordKind::kClaimantRegistration:
      return decode(r, v.claimant);
  }
  return make_error(ErrorCode::kCorrupt, "unsupported durable record kind");
}

// --- snapshot state ---------------------------------------------------------
void encode(Writer& w, const SnapshotCapacityEntry& v) {
  encode(w, v.capacity);
  w.fixed128(v.snapshot);
  encode(w, v.ingested_at);
  w.boolean(v.withdrawn);
  encode(w, v.withdrawn_at);
  encode_list(w, v.prior_generations);
}
Status decode(Reader& r, SnapshotCapacityEntry& v) {
  Status s = decode(r, v.capacity);
  if (!s) return s;
  Result<Identity128> snapshot = r.fixed128();
  if (!snapshot) return snapshot.error();
  v.snapshot = snapshot.value();
  s = decode(r, v.ingested_at);
  if (!s) return s;
  Result<bool> withdrawn = r.boolean();
  if (!withdrawn) return withdrawn.error();
  v.withdrawn = withdrawn.value();
  s = decode(r, v.withdrawn_at);
  if (!s) return s;
  return decode_list(r, v.prior_generations);
}

void encode(Writer& w, const SnapshotPathEntry& v) {
  encode(w, v.path);
  w.fixed128(v.snapshot);
  encode(w, v.ingested_at);
  w.boolean(v.retired);
  encode_list(w, v.prior_generations);
}
Status decode(Reader& r, SnapshotPathEntry& v) {
  Status s = decode(r, v.path);
  if (!s) return s;
  Result<Identity128> snapshot = r.fixed128();
  if (!snapshot) return snapshot.error();
  v.snapshot = snapshot.value();
  s = decode(r, v.ingested_at);
  if (!s) return s;
  Result<bool> retired = r.boolean();
  if (!retired) return retired.error();
  v.retired = retired.value();
  return decode_list(r, v.prior_generations);
}

void encode(Writer& w, const SnapshotPolicyEntry& v) {
  encode(w, v.record);
  encode(w, v.ingested_at);
  encode_list(w, v.prior_generations);
}
Status decode(Reader& r, SnapshotPolicyEntry& v) {
  Status s = decode(r, v.record);
  if (!s) return s;
  s = decode(r, v.ingested_at);
  if (!s) return s;
  return decode_list(r, v.prior_generations);
}

void encode(Writer& w, const SnapshotState& v) {
  encode(w, v.epoch);
  w.fixed128(v.coordinator_boot);
  encode(w, v.sequence);
  encode_list(w, v.capacity);
  encode_list(w, v.paths);
  encode_list(w, v.policies);
  encode_list(w, v.reservations);
  encode_list(w, v.series);
  encode_list(w, v.edges);
  encode_list(w, v.attempts);
  encode_list(w, v.fences);
  encode_list(w, v.claimants);
  encode_list(w, v.overcommits);
  encode_list(w, v.retired);
}
Status decode(Reader& r, SnapshotState& v) {
  Status s = decode(r, v.epoch);
  if (!s) return s;
  Result<Identity128> boot = r.fixed128();
  if (!boot) return boot.error();
  v.coordinator_boot = boot.value();
  s = decode(r, v.sequence);
  if (!s) return s;
  s = decode_list(r, v.capacity);
  if (!s) return s;
  s = decode_list(r, v.paths);
  if (!s) return s;
  s = decode_list(r, v.policies);
  if (!s) return s;
  s = decode_list(r, v.reservations);
  if (!s) return s;
  s = decode_list(r, v.series);
  if (!s) return s;
  s = decode_list(r, v.edges);
  if (!s) return s;
  s = decode_list(r, v.attempts);
  if (!s) return s;
  s = decode_list(r, v.fences);
  if (!s) return s;
  s = decode_list(r, v.claimants);
  if (!s) return s;
  s = decode_list(r, v.overcommits);
  if (!s) return s;
  return decode_list(r, v.retired);
}

// --- reports and results ----------------------------------------------------
void encode(Writer& w, const CapabilityDelta& v) {
  encode(w, v.resource);
  encode(w, v.generation);
  encode(w, v.reservable_capacity);
  encode(w, v.protected_headroom);
  encode(w, v.committable_ceiling);
  encode(w, v.committed_peak_before);
  encode(w, v.committed_peak_after);
  encode(w, v.holds_peak);
  encode(w, v.remaining_after);
  encode(w, v.window);
  w.boolean(v.maintenance_covers);
  w.boolean(v.overcommit_emergency);
}
Status decode(Reader& r, CapabilityDelta& v) {
  Status s = decode(r, v.resource);
  if (!s) return s;
  s = decode(r, v.generation);
  if (!s) return s;
  s = decode(r, v.reservable_capacity);
  if (!s) return s;
  s = decode(r, v.protected_headroom);
  if (!s) return s;
  s = decode(r, v.committable_ceiling);
  if (!s) return s;
  s = decode(r, v.committed_peak_before);
  if (!s) return s;
  s = decode(r, v.committed_peak_after);
  if (!s) return s;
  s = decode(r, v.holds_peak);
  if (!s) return s;
  s = decode(r, v.remaining_after);
  if (!s) return s;
  s = decode(r, v.window);
  if (!s) return s;
  Result<bool> maintenance = r.boolean();
  if (!maintenance) return maintenance.error();
  v.maintenance_covers = maintenance.value();
  Result<bool> emergency = r.boolean();
  if (!emergency) return emergency.error();
  v.overcommit_emergency = emergency.value();
  return {};
}

void encode(Writer& w, const ConflictEntry& v) {
  w.fixed128(v.id);
  encode(w, v.generation);
  encode(w, v.resource);
  encode(w, v.interval);
  encode(w, v.amount);
  encode(w, v.guarantee);
  encode(w, v.state);
  w.boolean(v.is_hold);
}
Status decode(Reader& r, ConflictEntry& v) {
  Result<Identity128> id = r.fixed128();
  if (!id) return id.error();
  v.id = id.value();
  Status s = decode(r, v.generation);
  if (!s) return s;
  s = decode(r, v.resource);
  if (!s) return s;
  s = decode(r, v.interval);
  if (!s) return s;
  s = decode(r, v.amount);
  if (!s) return s;
  s = decode(r, v.guarantee);
  if (!s) return s;
  s = decode(r, v.state);
  if (!s) return s;
  Result<bool> hold = r.boolean();
  if (!hold) return hold.error();
  v.is_hold = hold.value();
  return {};
}

void encode(Writer& w, const ConflictSet& v) {
  encode_list(w, v.entries);
  w.u64(v.total_considered);
  w.u64(v.scan_limit_hit);
  w.boolean(v.truncated);
}
Status decode(Reader& r, ConflictSet& v) {
  Status s = decode_list(r, v.entries);
  if (!s) return s;
  Result<std::uint64_t> total = r.u64();
  if (!total) return total.error();
  v.total_considered = static_cast<std::size_t>(total.value());
  Result<std::uint64_t> limit = r.u64();
  if (!limit) return limit.error();
  v.scan_limit_hit = static_cast<std::size_t>(limit.value());
  Result<bool> truncated = r.boolean();
  if (!truncated) return truncated.error();
  v.truncated = truncated.value();
  return {};
}

void encode(Writer& w, const AdmissionReport& v) {
  encode(w, v.outcome);
  w.text(v.explanation);
  encode_list(w, v.resources);
  encode(w, v.conflicts);
  encode_list(w, v.preemption_plan);
  encode_list(w, v.preemption_plan_generations);
  w.boolean(v.preemption_planned);
  encode(w, v.applicability_reason);
}
Status decode(Reader& r, AdmissionReport& v) {
  Status s = decode(r, v.outcome);
  if (!s) return s;
  s = read_string(r, v.explanation, kMaxTextBytes);
  if (!s) return s;
  s = decode_list(r, v.resources);
  if (!s) return s;
  s = decode(r, v.conflicts);
  if (!s) return s;
  s = decode_list(r, v.preemption_plan);
  if (!s) return s;
  s = decode_list(r, v.preemption_plan_generations);
  if (!s) return s;
  if (v.preemption_plan.size() != v.preemption_plan_generations.size()) {
    return make_error(ErrorCode::kCorrupt, "preemption plan arrays are not parallel");
  }
  Result<bool> planned = r.boolean();
  if (!planned) return planned.error();
  v.preemption_planned = planned.value();
  return decode(r, v.applicability_reason);
}

void encode(Writer& w, const CommitResult& v) {
  encode(w, v.record);
  w.boolean(v.has_series);
  if (v.has_series) encode(w, v.series);
  encode_list(w, v.members);
  encode(w, v.report);
  w.boolean(v.replayed);
  w.fixed128(v.attempt);
  encode(w, v.sequence);
}
Status decode(Reader& r, CommitResult& v) {
  Status s = decode(r, v.record);
  if (!s) return s;
  Result<bool> has_series = r.boolean();
  if (!has_series) return has_series.error();
  v.has_series = has_series.value();
  if (v.has_series) {
    s = decode(r, v.series);
    if (!s) return s;
  }
  s = decode_list(r, v.members);
  if (!s) return s;
  s = decode(r, v.report);
  if (!s) return s;
  Result<bool> replayed = r.boolean();
  if (!replayed) return replayed.error();
  v.replayed = replayed.value();
  Result<Identity128> attempt = r.fixed128();
  if (!attempt) return attempt.error();
  v.attempt = attempt.value();
  return decode(r, v.sequence);
}

void encode(Writer& w, const AmendmentResult& v) {
  encode(w, v.predecessor);
  encode(w, v.successor);
  w.boolean(v.has_series);
  if (v.has_series) encode(w, v.series);
  encode_list(w, v.members);
  encode(w, v.report);
  w.boolean(v.replayed);
}
Status decode(Reader& r, AmendmentResult& v) {
  Status s = decode(r, v.predecessor);
  if (!s) return s;
  s = decode(r, v.successor);
  if (!s) return s;
  Result<bool> has_series = r.boolean();
  if (!has_series) return has_series.error();
  v.has_series = has_series.value();
  if (v.has_series) {
    s = decode(r, v.series);
    if (!s) return s;
  }
  s = decode_list(r, v.members);
  if (!s) return s;
  s = decode(r, v.report);
  if (!s) return s;
  Result<bool> replayed = r.boolean();
  if (!replayed) return replayed.error();
  v.replayed = replayed.value();
  return {};
}

void encode(Writer& w, const LifecycleResult& v) {
  encode(w, v.record);
  w.boolean(v.replayed);
  w.u64(v.transitions);
}
Status decode(Reader& r, LifecycleResult& v) {
  Status s = decode(r, v.record);
  if (!s) return s;
  Result<bool> replayed = r.boolean();
  if (!replayed) return replayed.error();
  v.replayed = replayed.value();
  Result<std::uint64_t> transitions = r.u64();
  if (!transitions) return transitions.error();
  v.transitions = static_cast<std::size_t>(transitions.value());
  return {};
}

void encode(Writer& w, const AttemptReconciliation& v) {
  w.fixed128(v.attempt);
  w.boolean(v.known);
  encode(w, v.outcome);
  w.fixed128(v.reservation);
  encode(w, v.generation);
  encode(w, v.sequence);
  w.boolean(v.committed);
  w.text(v.note);
}
Status decode(Reader& r, AttemptReconciliation& v) {
  Result<Identity128> attempt = r.fixed128();
  if (!attempt) return attempt.error();
  v.attempt = attempt.value();
  Result<bool> known = r.boolean();
  if (!known) return known.error();
  v.known = known.value();
  Status s = decode(r, v.outcome);
  if (!s) return s;
  Result<Identity128> reservation = r.fixed128();
  if (!reservation) return reservation.error();
  v.reservation = reservation.value();
  s = decode(r, v.generation);
  if (!s) return s;
  s = decode(r, v.sequence);
  if (!s) return s;
  Result<bool> committed = r.boolean();
  if (!committed) return committed.error();
  v.committed = committed.value();
  return read_string(r, v.note, kMaxProvenanceReasonBytes);
}

void encode(Writer& w, const RemainingCapacity& v) {
  encode(w, v.resource);
  encode(w, v.generation);
  encode(w, v.window);
  encode(w, v.committable_ceiling);
  encode(w, v.committed_peak);
  encode(w, v.holds_peak);
  encode(w, v.remaining);
  w.boolean(v.maintenance_covers);
  w.boolean(v.overcommit_emergency);
}
Status decode(Reader& r, RemainingCapacity& v) {
  Status s = decode(r, v.resource);
  if (!s) return s;
  s = decode(r, v.generation);
  if (!s) return s;
  s = decode(r, v.window);
  if (!s) return s;
  s = decode(r, v.committable_ceiling);
  if (!s) return s;
  s = decode(r, v.committed_peak);
  if (!s) return s;
  s = decode(r, v.holds_peak);
  if (!s) return s;
  s = decode(r, v.remaining);
  if (!s) return s;
  Result<bool> maintenance = r.boolean();
  if (!maintenance) return maintenance.error();
  v.maintenance_covers = maintenance.value();
  Result<bool> emergency = r.boolean();
  if (!emergency) return emergency.error();
  v.overcommit_emergency = emergency.value();
  return {};
}

void encode(Writer& w, const ChangePoint& v) {
  encode(w, v.at);
  encode(w, v.committed);
  encode(w, v.holds);
}
Status decode(Reader& r, ChangePoint& v) {
  Status s = decode(r, v.at);
  if (!s) return s;
  s = decode(r, v.committed);
  if (!s) return s;
  return decode(r, v.holds);
}

void encode(Writer& w, const CapacityTimeline& v) {
  encode(w, v.resource);
  encode(w, v.window);
  encode_list(w, v.points);
  w.boolean(v.truncated);
}
Status decode(Reader& r, CapacityTimeline& v) {
  Status s = decode(r, v.resource);
  if (!s) return s;
  s = decode(r, v.window);
  if (!s) return s;
  s = decode_list(r, v.points);
  if (!s) return s;
  Result<bool> truncated = r.boolean();
  if (!truncated) return truncated.error();
  v.truncated = truncated.value();
  return {};
}

void encode(Writer& w, const LineageView& v) {
  w.fixed128(v.id);
  encode(w, v.generation);
  encode_list(w, v.ancestry);
  encode_list(w, v.descendants);
  w.boolean(v.truncated);
}
Status decode(Reader& r, LineageView& v) {
  Result<Identity128> id = r.fixed128();
  if (!id) return id.error();
  v.id = id.value();
  Status s = decode(r, v.generation);
  if (!s) return s;
  s = decode_list(r, v.ancestry);
  if (!s) return s;
  s = decode_list(r, v.descendants);
  if (!s) return s;
  Result<bool> truncated = r.boolean();
  if (!truncated) return truncated.error();
  v.truncated = truncated.value();
  return {};
}

void encode(Writer& w, const OvercommitReport& v) {
  w.count(v.entries.size());
  for (const OvercommitReport::Entry& entry : v.entries) {
    encode(w, entry.resource);
    encode(w, entry.generation);
    encode(w, entry.committed_peak);
    encode(w, entry.committable_ceiling);
    encode(w, entry.window);
    encode(w, entry.detected_at);
  }
  w.boolean(v.emergency_active);
}
Status decode(Reader& r, OvercommitReport& v) {
  Result<std::uint32_t> count = r.u32();
  if (!count) return count.error();
  if (count.value() > kMaxCollectionItems) {
    return make_error(ErrorCode::kResourceExhausted, "overcommit report exceeds the item bound");
  }
  v.entries.clear();
  for (std::uint32_t i = 0; i < count.value(); ++i) {
    OvercommitReport::Entry entry;
    Status s = decode(r, entry.resource);
    if (!s) return s;
    s = decode(r, entry.generation);
    if (!s) return s;
    s = decode(r, entry.committed_peak);
    if (!s) return s;
    s = decode(r, entry.committable_ceiling);
    if (!s) return s;
    s = decode(r, entry.window);
    if (!s) return s;
    s = decode(r, entry.detected_at);
    if (!s) return s;
    v.entries.push_back(std::move(entry));
  }
  Result<bool> active = r.boolean();
  if (!active) return active.error();
  v.emergency_active = active.value();
  return {};
}

void encode(Writer& w, const CoordinatorStats& v) {
  w.u64(v.commits);
  w.u64(v.commit_rejections);
  w.u64(v.replayed_attempts);
  w.u64(v.amendments);
  w.u64(v.releases);
  w.u64(v.expiries);
  w.u64(v.recalls);
  w.u64(v.revocations);
  w.u64(v.revalidations);
  w.u64(v.fenced_holds);
  w.u64(v.capacity_ingestions);
  w.u64(v.generation_advances);
  w.u64(v.durable_records);
  w.u64(v.overcommit_events);
  w.u64(v.tracked_reservations);
  w.u64(v.tracked_series);
  w.u64(v.live_holds);
  w.u64(v.index_entries);
  encode(w, v.epoch);
  w.fixed128(v.coordinator_boot);
  w.u64(v.journal_bytes);
  w.u64(v.snapshot_sequence);
}
Status decode(Reader& r, CoordinatorStats& v) {
  const auto read_u64 = [&r](std::uint64_t& out) -> Status {
    Result<std::uint64_t> raw = r.u64();
    if (!raw) return raw.error();
    out = raw.value();
    return {};
  };
  Status s = read_u64(v.commits);
  if (!s) return s;
  s = read_u64(v.commit_rejections);
  if (!s) return s;
  s = read_u64(v.replayed_attempts);
  if (!s) return s;
  s = read_u64(v.amendments);
  if (!s) return s;
  s = read_u64(v.releases);
  if (!s) return s;
  s = read_u64(v.expiries);
  if (!s) return s;
  s = read_u64(v.recalls);
  if (!s) return s;
  s = read_u64(v.revocations);
  if (!s) return s;
  s = read_u64(v.revalidations);
  if (!s) return s;
  s = read_u64(v.fenced_holds);
  if (!s) return s;
  s = read_u64(v.capacity_ingestions);
  if (!s) return s;
  s = read_u64(v.generation_advances);
  if (!s) return s;
  s = read_u64(v.durable_records);
  if (!s) return s;
  s = read_u64(v.overcommit_events);
  if (!s) return s;
  std::uint64_t tracked = 0;
  s = read_u64(tracked);
  if (!s) return s;
  v.tracked_reservations = static_cast<std::size_t>(tracked);
  std::uint64_t series = 0;
  s = read_u64(series);
  if (!s) return s;
  v.tracked_series = static_cast<std::size_t>(series);
  std::uint64_t holds = 0;
  s = read_u64(holds);
  if (!s) return s;
  v.live_holds = static_cast<std::size_t>(holds);
  std::uint64_t index_entries = 0;
  s = read_u64(index_entries);
  if (!s) return s;
  v.index_entries = static_cast<std::size_t>(index_entries);
  s = decode(r, v.epoch);
  if (!s) return s;
  Result<Identity128> boot = r.fixed128();
  if (!boot) return boot.error();
  v.coordinator_boot = boot.value();
  s = read_u64(v.journal_bytes);
  if (!s) return s;
  return read_u64(v.snapshot_sequence);
}

void encode(Writer& w, const IndexEntry& v) {
  encode(w, v.kind);
  w.fixed128(v.id);
  w.u64(v.holder_generation);
  encode(w, v.resource);
  encode(w, v.interval);
  encode(w, v.amount);
  encode(w, v.guarantee);
  encode(w, v.state);
}
Status decode(Reader& r, IndexEntry& v) {
  Status s = decode(r, v.kind);
  if (!s) return s;
  Result<Identity128> id = r.fixed128();
  if (!id) return id.error();
  v.id = id.value();
  Result<std::uint64_t> generation = r.u64();
  if (!generation) return generation.error();
  v.holder_generation = generation.value();
  s = decode(r, v.resource);
  if (!s) return s;
  s = decode(r, v.interval);
  if (!s) return s;
  s = decode(r, v.amount);
  if (!s) return s;
  s = decode(r, v.guarantee);
  if (!s) return s;
  return decode(r, v.state);
}

void encode(Writer& w, const RecoveryReport& v) {
  w.boolean(v.snapshot_loaded);
  w.boolean(v.torn_tail_truncated);
  w.u64(v.truncated_bytes);
  w.u64(v.snapshot_sequence);
  w.u64(v.records_replayed);
  w.u64(v.records_skipped);
  w.u64(v.last_sequence);
  encode(w, v.recovered_epoch);
  w.text(v.detail);
}
Status decode(Reader& r, RecoveryReport& v) {
  Result<bool> snapshot = r.boolean();
  if (!snapshot) return snapshot.error();
  v.snapshot_loaded = snapshot.value();
  Result<bool> torn = r.boolean();
  if (!torn) return torn.error();
  v.torn_tail_truncated = torn.value();
  Result<std::uint64_t> truncated_bytes = r.u64();
  if (!truncated_bytes) return truncated_bytes.error();
  v.truncated_bytes = truncated_bytes.value();
  Result<std::uint64_t> snapshot_sequence = r.u64();
  if (!snapshot_sequence) return snapshot_sequence.error();
  v.snapshot_sequence = snapshot_sequence.value();
  Result<std::uint64_t> replayed = r.u64();
  if (!replayed) return replayed.error();
  v.records_replayed = replayed.value();
  Result<std::uint64_t> skipped = r.u64();
  if (!skipped) return skipped.error();
  v.records_skipped = skipped.value();
  Result<std::uint64_t> last = r.u64();
  if (!last) return last.error();
  v.last_sequence = last.value();
  Status s = decode(r, v.recovered_epoch);
  if (!s) return s;
  return read_string(r, v.detail, 256);
}

// --- journal envelope -------------------------------------------------------
std::string encode_record(const DurableRecord& record) {
  Writer writer(256);
  writer.u16(kDurableFormatVersion);
  encode(writer, record);
  return writer.take();
}

Status decode_record(std::string_view payload, RecordKind kind, DurableRecord& record) {
  Reader reader(payload);
  Result<std::uint16_t> version = reader.u16();
  if (!version) return version.error();
  if (version.value() != kDurableFormatVersion) {
    return make_error(ErrorCode::kUnsupported, "durable record format version is not supported");
  }
  record.kind = kind;
  Status decoded = decode(reader, record);
  if (!decoded) return decoded;
  if (record.kind != kind) {
    return make_error(ErrorCode::kCorrupt, "durable record kind does not match its container");
  }
  if (!reader.exhausted()) {
    return make_error(ErrorCode::kCorrupt, "durable record has trailing bytes");
  }
  return {};
}

}  // namespace brf::codec
