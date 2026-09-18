// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Core value-type, encoding, and index proofs.
#include <algorithm>
#include <string>
#include <vector>

#include "brf/brf.hpp"
#include "support/fixtures.hpp"
#include "support/test_harness.hpp"

using namespace brf;  // NOLINT(google-build-using-namespace)
using namespace brf::test;

BRF_TEST(identity, hex_round_trip) {
  const Identity128 id = random_identity();
  const std::string hex = id.to_hex();
  BRF_CHECK_EQ(hex.size(), std::size_t{32});
  Result<Identity128> parsed = Identity128::from_hex(hex);
  BRF_REQUIRE(parsed.has_value());
  BRF_CHECK(parsed.value() == id);
}

BRF_TEST(identity, rejects_malformed) {
  BRF_CHECK(!Identity128::from_hex("").has_value());
  BRF_CHECK(!Identity128::from_hex("00").has_value());
  BRF_CHECK(!Identity128::from_hex("0000000000000000000000000000000g").has_value());
  BRF_CHECK(!Identity128::from_hex("0000000000000000000000000000000000").has_value());
  BRF_CHECK(Identity128::from_hex("0011223344556677889900AABBCCDDEE").has_value());
}

BRF_TEST(identity, derive_is_deterministic_and_distinct) {
  const Identity128 parent = Identity128::from_hex("00112233445566778899aabbccddeeff").value();
  const Identity128 first = Identity128::derive(parent, 0);
  const Identity128 again = Identity128::derive(parent, 0);
  const Identity128 second = Identity128::derive(parent, 1);
  BRF_CHECK(first == again);
  BRF_CHECK(!(first == second));
  BRF_CHECK(!first.is_nil());
}

BRF_TEST(counter, overflow_refused) {
  const ReservationGeneration top(UINT64_MAX);
  BRF_CHECK(!top.next().has_value());
  const ReservationGeneration low(1);
  BRF_REQUIRE(low.next().has_value());
  BRF_CHECK_EQ(low.next().value().value(), std::uint64_t{2});
}

BRF_TEST(name, validation_rules) {
  BRF_CHECK(ResourceName::from_string("").error().code == ErrorCode::kInvalidName);
  BRF_CHECK(ResourceName::from_string("has space").error().code == ErrorCode::kInvalidName);
  BRF_CHECK(ResourceName::from_string("has/slash/ok").has_value());
  BRF_CHECK(ResourceName::from_string("../../etc/passwd").error().code == ErrorCode::kInvalidName);
  std::string long_name(80, 'a');
  BRF_CHECK(ResourceName::from_string(long_name).error().code == ErrorCode::kInvalidName);
  std::string unicode = "caf\xC3\xA9";  // "café": non-ASCII bytes are refused
  BRF_CHECK(ResourceName::from_string(unicode).error().code == ErrorCode::kInvalidName);
}

BRF_TEST(time, canonical_format_round_trip) {
  const Timestamp instant{kBaseEpochNs + 123456789};
  const std::string text = format_timestamp(instant);
  BRF_CHECK_EQ(text, std::string("2026-01-01T00:00:00.123456789Z"));
  Result<Timestamp> parsed = parse_timestamp(text);
  BRF_REQUIRE(parsed.has_value());
  BRF_CHECK(parsed.value() == instant);
}

BRF_TEST(time, parse_rejects_local_forms) {
  BRF_CHECK(!parse_timestamp("2026-01-01T00:00:00+01:00").has_value());
  BRF_CHECK(!parse_timestamp("2026-01-01 00:00:00Z").has_value());
  BRF_CHECK(!parse_timestamp("2026-13-01T00:00:00Z").has_value());
  BRF_CHECK(!parse_timestamp("2026-02-30T00:00:00Z").has_value());
  BRF_CHECK(!parse_timestamp("2026-01-01T24:00:00Z").has_value());
  BRF_CHECK(parse_timestamp("2026-02-29T00:00:00Z").error().code == ErrorCode::kInvalidArgument);
  BRF_CHECK(parse_timestamp("2024-02-29T00:00:00Z").has_value());
}

BRF_TEST(time, interval_validation) {
  BRF_CHECK(validate_interval(window_of(10, 0)).error().code == ErrorCode::kInvalidInterval);
  BRF_CHECK(validate_interval(window_of(10, 10)).error().code == ErrorCode::kInvalidInterval);
  BRF_CHECK(validate_interval(window_of(-5, 10)).error().code == ErrorCode::kInvalidInterval);
  BRF_CHECK(validate_interval(window_of(0, kMaxTimestampNs + 1)).error().code == ErrorCode::kInvalidInterval);
  BRF_CHECK(validate_interval(window_of(0, kMaxReservationSpanNs + 1)).has_value() == false);
  BRF_CHECK(window_of(0, 10).overlaps(window_of(9, 20)));
  BRF_CHECK(!window_of(0, 10).overlaps(window_of(10, 20)));
  BRF_CHECK(window_of(0, 10).contains(Timestamp{9}));
  BRF_CHECK(!window_of(0, 10).contains(Timestamp{10}));
}

BRF_TEST(bandwidth, checked_arithmetic) {
  BRF_CHECK(!make_bandwidth(0).has_value());
  BRF_CHECK(!make_bandwidth(-1).has_value());
  BRF_CHECK(!make_bandwidth(kMaxBandwidthBps + 1).has_value());
  BRF_CHECK_EQ(add(Bandwidth{kMaxBandwidthBps}, Bandwidth{1}).error().code, ErrorCode::kOverflow);
  BRF_CHECK_EQ(subtract(Bandwidth{1}, Bandwidth{2}).error().code, ErrorCode::kInvalidBandwidth);
  BRF_CHECK_EQ(saturating_add(Bandwidth{kMaxBandwidthBps}, Bandwidth{kMaxBandwidthBps}).bps,
               kMaxBandwidthBps);
  BRF_CHECK_EQ(parse_bandwidth("10G").value().bps, std::int64_t{10000000000LL});
  BRF_CHECK_EQ(parse_bandwidth("512").value().bps, std::int64_t{512});
  BRF_CHECK(!parse_bandwidth("10X").has_value());
  BRF_CHECK(!parse_bandwidth("").has_value());
}

BRF_TEST(wire, reader_is_bounds_checked) {
  Writer writer;
  writer.u8(1);
  writer.u16(2);
  writer.u32(3);
  writer.u64(4);
  writer.text("hello");
  const std::string buffer = writer.take();
  Reader reader(buffer);
  BRF_CHECK_EQ(reader.u8().value(), std::uint8_t{1});
  BRF_CHECK_EQ(reader.u16().value(), std::uint16_t{2});
  BRF_CHECK_EQ(reader.u32().value(), std::uint32_t{3});
  BRF_CHECK_EQ(reader.u64().value(), std::uint64_t{4});
  BRF_CHECK_EQ(std::string(reader.text(64).value()), std::string("hello"));
  BRF_CHECK(reader.exhausted());
  BRF_CHECK_EQ(reader.u8().error().code, ErrorCode::kCorrupt);
  Reader empty(std::string_view{});
  BRF_CHECK_EQ(empty.u32().error().code, ErrorCode::kCorrupt);
}

BRF_TEST(wire, length_prefix_cannot_exhaust_memory) {
  Writer writer;
  writer.u32(0xFFFFFFFFU);
  const std::string buffer = writer.take();
  Reader reader(buffer);
  BRF_CHECK_EQ(reader.text(kMaxTextBytes).error().code, ErrorCode::kResourceExhausted);
  Reader reader2(buffer);
  BRF_CHECK_EQ(reader2.bytes(16).error().code, ErrorCode::kResourceExhausted);
  Reader reader3(buffer);
  BRF_CHECK_EQ(reader3.bytes(kMaxBlobBytes).error().code, ErrorCode::kResourceExhausted);
}

BRF_TEST(crc, known_vectors) {
  const char* check = "123456789";
  BRF_CHECK_EQ(crc32c(check, 9), std::uint32_t{0xE3069283});
  BRF_CHECK_EQ(crc32c("", 0), std::uint32_t{0});
  Crc32cBuilder builder;
  builder.update("12345", 5);
  builder.update("6789", 4);
  BRF_CHECK_EQ(builder.finish(), std::uint32_t{0xE3069283});
}

BRF_TEST(index, range_add_and_peak) {
  IntervalCapacityIndex index;
  index.add(window_of(10, 20), Bandwidth{100});
  index.add(window_of(15, 25), Bandwidth{50});
  BRF_CHECK_EQ(index.peak(window_of(0, 100)).bps, std::int64_t{150});
  BRF_CHECK_EQ(index.peak(window_of(0, 10)).bps, std::int64_t{0});
  BRF_CHECK_EQ(index.peak(window_of(20, 22)).bps, std::int64_t{50});
  BRF_CHECK_EQ(index.at(Timestamp{12}).bps, std::int64_t{100});
  BRF_CHECK(index.exceeds(window_of(14, 16), Bandwidth{120}));
  BRF_CHECK(!index.exceeds(window_of(14, 16), Bandwidth{150}));
  index.remove(window_of(15, 25), Bandwidth{50});
  BRF_CHECK_EQ(index.peak(window_of(0, 100)).bps, std::int64_t{100});
  index.remove(window_of(10, 20), Bandwidth{100});
  BRF_CHECK_EQ(index.peak(window_of(0, 100)).bps, std::int64_t{0});
}

BRF_TEST(index, overlap_enumeration_is_bounded_and_sorted) {
  CapacityIndex index;
  for (int i = 0; i < 10; ++i) {
    IndexEntry entry;
    entry.kind = HolderKind::kReservation;
    entry.id = Identity128::derive(Identity128::from_hex("00112233445566778899aabbccddeeff").value(),
                                   static_cast<std::uint64_t>(i));
    entry.holder_generation = 1;
    entry.resource = name_of("r1");
    entry.interval = window_of(100 + i, 200 + i);
    entry.amount = Bandwidth{10};
    BRF_CHECK_OK(index.insert(entry));
  }
  std::size_t total = 0;
  bool truncated = false;
  const std::vector<IndexEntry> overlaps =
      index.overlapping(name_of("r1"), window_of(0, 1000), 3, 1000, &total, &truncated);
  BRF_CHECK_EQ(overlaps.size(), std::size_t{3});
  BRF_CHECK_EQ(total, std::size_t{10});
  BRF_CHECK(truncated);
  const std::vector<IndexEntry> all =
      index.overlapping(name_of("r1"), window_of(0, 1000), 100, 1000, &total, &truncated);
  BRF_CHECK_EQ(all.size(), std::size_t{10});
  BRF_CHECK(!truncated);
  for (std::size_t i = 1; i < all.size(); ++i) {
    BRF_CHECK(!(all[i].interval.start < all[i - 1].interval.start));
  }
}

BRF_TEST(index, multi_resource_holder_is_erased_atomically) {
  CapacityIndex index;
  const Identity128 id = Identity128::from_hex("00112233445566778899aabbccddeeff").value();
  for (const char* resource : {"r1", "r2", "r3"}) {
    IndexEntry entry;
    entry.id = id;
    entry.holder_generation = 7;
    entry.resource = name_of(resource);
    entry.interval = window_of(0, 100);
    entry.amount = Bandwidth{25};
    BRF_CHECK_OK(index.insert(entry));
  }
  BRF_CHECK_EQ(index.entry_count(), std::size_t{3});
  BRF_CHECK_OK(index.erase_all(HolderKind::kReservation, id, 7));
  BRF_CHECK_EQ(index.entry_count(), std::size_t{0});
  BRF_CHECK_EQ(index.peak_committed(name_of("r2"), window_of(0, 100)).bps, std::int64_t{0});
}

BRF_TEST(index, timeline_reports_step_changes) {
  CapacityIndex index;
  IndexEntry first;
  first.id = Identity128::from_hex("00112233445566778899aabbccddeeff").value();
  first.holder_generation = 1;
  first.resource = name_of("r1");
  first.interval = window_of(100, 200);
  first.amount = Bandwidth{10};
  BRF_CHECK_OK(index.insert(first));
  IndexEntry second = first;
  second.id = Identity128::from_hex("ffeeddccbbaa99887766554433221100").value();
  second.interval = window_of(150, 300);
  second.amount = Bandwidth{5};
  BRF_CHECK_OK(index.insert(second));
  bool truncated = false;
  const std::vector<ChangePoint> points = index.timeline(name_of("r1"), window_of(0, 400), 16, &truncated);
  BRF_REQUIRE(points.size() >= 3);
  BRF_CHECK(!truncated);
  // The step function starts at the query window, then changes exactly at the
  // interval boundaries.
  BRF_CHECK_EQ(points[0].at.ns, std::int64_t{0});
  BRF_CHECK_EQ(points[0].committed.bps, std::int64_t{0});
  bool saw_start = false;
  bool saw_overlap = false;
  bool saw_end = false;
  for (const ChangePoint& point : points) {
    if (point.at.ns == 100) {
      saw_start = true;
      BRF_CHECK_EQ(point.committed.bps, std::int64_t{10});
    }
    if (point.at.ns == 150) {
      saw_overlap = true;
      BRF_CHECK_EQ(point.committed.bps, std::int64_t{15});
    }
    if (point.at.ns == 200) {
      saw_end = true;
      BRF_CHECK_EQ(point.committed.bps, std::int64_t{5});
    }
  }
  BRF_CHECK(saw_start);
  BRF_CHECK(saw_overlap);
  BRF_CHECK(saw_end);
}

BRF_TEST(reservation, terms_validation) {
  const ClaimantId claimant = Identity128::from_hex("00112233445566778899aabbccddeeff").value();
  ReservationTerms terms = terms_of(claimant, ClaimantGeneration(1), "r1", 1000, window_of(0, 1000));
  BRF_CHECK(validate_terms(terms).has_value());

  ReservationTerms zero_amount = terms;
  zero_amount.amount = Bandwidth{0};
  BRF_CHECK_EQ(validate_terms(zero_amount).error().code, ErrorCode::kInvalidBandwidth);

  ReservationTerms inverted = terms;
  inverted.interval = window_of(1000, 1000);
  BRF_CHECK_EQ(validate_terms(inverted).error().code, ErrorCode::kInvalidInterval);

  ReservationTerms duplicate = terms;
  duplicate.resources.push_back(name_of("r1"));
  BRF_CHECK_EQ(validate_terms(duplicate).error().code, ErrorCode::kConflict);

  ReservationTerms contradictory = terms;
  contradictory.guarantee = GuaranteeClass::kGuaranteed;
  contradictory.preemptible = true;
  BRF_CHECK_EQ(validate_terms(contradictory).error().code, ErrorCode::kConflict);

  ReservationTerms bad_labels = terms;
  bad_labels.policy_labels.push_back(std::string(200, 'x'));
  BRF_CHECK_EQ(validate_terms(bad_labels).error().code, ErrorCode::kInvalidArgument);
}

BRF_TEST(reservation, series_expansion_is_deterministic_and_disjoint) {
  RecurrenceSpec spec;
  spec.enabled = true;
  spec.period = Duration{kHour};
  spec.count = 4;
  Result<std::vector<Interval>> expanded = expand_series(window_of(0, kMinute), spec, 64);
  BRF_REQUIRE(expanded.has_value());
  BRF_CHECK_EQ(expanded.value().size(), std::size_t{4});
  BRF_CHECK_EQ(expanded.value()[1].start.ns, kHour);
  BRF_CHECK_EQ(expanded.value()[3].end.ns, 3 * kHour + kMinute);

  RecurrenceSpec overlapping = spec;
  overlapping.period = Duration{kMinute / 2};
  BRF_CHECK(!expand_series(window_of(0, kMinute), overlapping, 64).has_value());

  RecurrenceSpec too_many = spec;
  too_many.count = 100;
  BRF_CHECK_EQ(expand_series(window_of(0, kMinute), too_many, 64).error().code, ErrorCode::kResourceExhausted);

  const ReservationSeriesId series =
      Identity128::from_hex("00112233445566778899aabbccddeeff").value();
  BRF_CHECK(derive_member_id(series, SeriesIndex(3)) == derive_member_id(series, SeriesIndex(3)));
  BRF_CHECK(!(derive_member_id(series, SeriesIndex(3)) == derive_member_id(series, SeriesIndex(4))));
}

BRF_TEST(lifecycle, state_predicates) {
  BRF_CHECK(consumes_capacity(ReservationState::kCommitted));
  BRF_CHECK(consumes_capacity(ReservationState::kActive));
  BRF_CHECK(consumes_capacity(ReservationState::kRecallPending));
  BRF_CHECK(!consumes_capacity(ReservationState::kReleased));
  BRF_CHECK(!consumes_capacity(ReservationState::kSuperseded));
  BRF_CHECK(is_terminal(ReservationState::kReleased));
  BRF_CHECK(is_terminal(ReservationState::kExpired));
  BRF_CHECK(is_terminal(ReservationState::kStale));
  BRF_CHECK(!is_terminal(ReservationState::kActive));
  for (std::uint8_t raw = 0; raw <= 14; ++raw) {
    const ReservationState state = static_cast<ReservationState>(raw);
    Result<ReservationState> parsed = parse_reservation_state(to_string(state));
    BRF_REQUIRE(parsed.has_value());
    BRF_CHECK(parsed.value() == state);
  }
}

BRF_TEST(codec, canonical_round_trip_of_reservation) {
  ReservationRecord record;
  record.id = Identity128::from_hex("00112233445566778899aabbccddeeff").value();
  record.generation = ReservationGeneration(3);
  record.terms = terms_of(Identity128::from_hex("ffeeddccbbaa99887766554433221100").value(),
                          ClaimantGeneration(2), "r1", 5000, window_of(0, 1000));
  record.state = ReservationState::kCommitted;
  record.authority.fabric_epoch = FabricEpoch(7);
  record.authority.resources.push_back(ResourceRef{name_of("r1"), ResourceGeneration(4)});
  record.sequence = DurableSequence(11);
  record.state_reason = "unit test";
  Writer writer(256);
  codec::encode(writer, record);
  const std::string bytes = writer.take();
  Reader reader(bytes);
  ReservationRecord decoded;
  BRF_CHECK_OK(codec::decode(reader, decoded));
  BRF_CHECK(reader.exhausted());
  Writer second(256);
  codec::encode(second, decoded);
  BRF_CHECK_EQ(second.buffer(), bytes);
  BRF_CHECK(decoded.id == record.id);
  BRF_CHECK_EQ(decoded.generation.value(), std::uint64_t{3});
  BRF_CHECK(decoded.terms.interval == record.terms.interval);
}

BRF_TEST(codec, decode_rejects_truncated_and_trailing_bytes) {
  codec::AttemptMutation mutation;
  mutation.attempt = Identity128::from_hex("00112233445566778899aabbccddeeff").value();
  mutation.fingerprint = Identity128::from_hex("ffeeddccbbaa99887766554433221100").value();
  mutation.outcome = AdmissionOutcome::kCommittable;
  mutation.at = Timestamp{42};
  Writer writer(128);
  codec::encode(writer, mutation);
  const std::string bytes = writer.take();
  for (std::size_t cut = 0; cut < bytes.size(); ++cut) {
    const std::string truncated = bytes.substr(0, cut);
    Reader reader(truncated);
    codec::AttemptMutation ignored;
    BRF_CHECK(!codec::decode(reader, ignored).has_value());
  }
  const std::string trailing = bytes + std::string(1, '\0');
  Reader reader(trailing);
  codec::AttemptMutation ignored;
  BRF_CHECK_OK(codec::decode(reader, ignored));
  BRF_CHECK(!reader.exhausted());
}

BRF_TEST(codec, record_envelope_is_versioned) {
  codec::DurableRecord record;
  record.kind = RecordKind::kFabricBoot;
  record.epoch.epoch = FabricEpoch(5);
  record.epoch.coordinator_boot = Identity128::from_hex("00112233445566778899aabbccddeeff").value();
  record.epoch.at = Timestamp{99};
  const std::string payload = codec::encode_record(record);
  codec::DurableRecord decoded;
  BRF_CHECK_OK(codec::decode_record(payload, RecordKind::kFabricBoot, decoded));
  BRF_CHECK_EQ(decoded.epoch.epoch.value(), std::uint64_t{5});

  codec::DurableRecord mismatched;
  BRF_CHECK(!codec::decode_record(payload, RecordKind::kFence, mismatched).has_value());

  std::string future = payload;
  future[0] = static_cast<char>(0xFF);
  future[1] = static_cast<char>(0xFF);
  codec::DurableRecord ignored;
  BRF_CHECK_EQ(codec::decode_record(future, RecordKind::kFabricBoot, ignored).error().code,
               ErrorCode::kUnsupported);
}

BRF_TEST(authority, conflicting_resource_generations_refused) {
  std::vector<ResourceRef> refs;
  refs.push_back(ResourceRef{name_of("r1"), ResourceGeneration(1)});
  refs.push_back(ResourceRef{name_of("r1"), ResourceGeneration(2)});
  BRF_CHECK_EQ(canonicalize_resources(refs).error().code, ErrorCode::kConflict);

  std::vector<ResourceRef> duplicates;
  duplicates.push_back(ResourceRef{name_of("r1"), ResourceGeneration(1)});
  duplicates.push_back(ResourceRef{name_of("r1"), ResourceGeneration(1)});
  Result<std::vector<ResourceRef>> canonical = canonicalize_resources(duplicates);
  BRF_REQUIRE(canonical.has_value());
  BRF_CHECK_EQ(canonical.value().size(), std::size_t{1});

  std::vector<ResourceRef> too_wide;
  for (std::size_t i = 0; i <= kMaxBindingResources; ++i) {
    too_wide.push_back(
        ResourceRef{name_of(("r" + std::to_string(i)).c_str()), ResourceGeneration(1)});
  }
  BRF_CHECK_EQ(canonicalize_resources(too_wide).error().code, ErrorCode::kResourceExhausted);
}

BRF_TEST(sanitize, reason_text_is_bounded_and_printable) {
  const std::string dirty = std::string("ok\x01\x02") + std::string(4096, 'x');
  const std::string clean = sanitize_reason(dirty);
  BRF_CHECK(clean.size() <= kMaxProvenanceReasonBytes);
  for (char ch : clean) {
    BRF_CHECK(static_cast<unsigned char>(ch) >= 0x20U && static_cast<unsigned char>(ch) <= 0x7EU);
  }
  BRF_CHECK_EQ(sanitize_reason("a...b"), std::string("a.b"));
  BRF_CHECK_EQ(sanitize_reason(""), std::string(""));
}
