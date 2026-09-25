#define BOOST_TEST_MODULE jgs245_ports_tests
#include <boost/test/included/unit_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

import jgs245_ports.domain;
import jgs245_ports.parser;
import jgs245_ports.render;

namespace
{
using Bytes3 = std::array<std::uint8_t, 3>;
constexpr std::size_t maximum_configuration_size = 16U * 1024U * 1024U;

struct VlanSpec
{
    std::uint16_t id;
    Bytes3 members;
    Bytes3 tagged;
    std::uint8_t trailing{0x03};
};

[[nodiscard]] auto byte(std::uint8_t value) -> std::byte
{
    return static_cast<std::byte>(value);
}

void set_text(std::vector<std::byte>& bytes, std::size_t offset, std::string_view text)
{
    for (std::size_t index = 0; index < text.size(); ++index) bytes.at(offset + index) = byte(static_cast<std::uint8_t>(text[index]));
}

void append_record_header(std::vector<std::byte>& bytes, std::uint8_t type, std::size_t size)
{
    bytes.push_back(byte(type));
    bytes.push_back(byte(static_cast<std::uint8_t>((size >> 16) & 0xff)));
    bytes.push_back(byte(static_cast<std::uint8_t>((size >> 8) & 0xff)));
    bytes.push_back(byte(static_cast<std::uint8_t>(size & 0xff)));
}

[[nodiscard]] auto sample_vlans() -> std::vector<VlanSpec>
{
    return {
            {1, {0xff, 0xd8, 0x0e}, {0x00, 0x00, 0x00}},
            {2, {0x00, 0x00, 0x00}, {0x00, 0x00, 0x00}},
            {3, {0x80, 0x20, 0x00}, {0x80, 0x00, 0x00}},
            {4, {0x80, 0x04, 0x01}, {0x80, 0x00, 0x00}},
            {5, {0x80, 0x20, 0x00}, {0x80, 0x20, 0x00}},
            {6, {0x82, 0x00, 0x00}, {0x82, 0x00, 0x00}},
            {2000, {0x00, 0x03, 0xf0}, {0x00, 0x00, 0x00}},
            {2999, {0x00, 0x00, 0x00}, {0x00, 0x00, 0x00}},
    };
}

[[nodiscard]] auto sample_pvids() -> std::vector<std::pair<std::uint8_t, std::uint16_t> >
{
    std::vector<std::pair<std::uint8_t, std::uint16_t> > pvids;
    for (std::uint8_t port = 1; port <= 24; ++port)
    {
        std::uint16_t pvid = 1;
        if (port == 11) pvid = 3;
        if (port == 14 || port == 24) pvid = 4;
        if (port >= 15 && port <= 20) pvid = 2000;
        pvids.emplace_back(port, pvid);
    }
    return pvids;
}

[[nodiscard]] auto make_fixture(std::vector<VlanSpec> const& vlans = sample_vlans(), std::vector<std::pair<std::uint8_t, std::uint16_t> > const& pvids = sample_pvids()) -> std::vector<std::byte>
{
    std::vector<std::byte> bytes(0x40, std::byte{});
    set_text(bytes, 0x00, "JGS524Ev2");
    set_text(bytes, 0x14, "v2.2.3");
    set_text(bytes, 0x28, "2.6.0.50");
    set_text(bytes, 0x3c, "v1");

    append_record_header(bytes, 0x28, 4 + vlans.size() * 13);
    for (auto const& vlan : vlans)
    {
        append_record_header(bytes, 0x28, 13);
        bytes.push_back(byte(static_cast<std::uint8_t>(vlan.id >> 8)));
        bytes.push_back(byte(static_cast<std::uint8_t>(vlan.id & 0xff)));
        for (auto value : vlan.members) bytes.push_back(byte(value));
        for (auto value : vlan.tagged) bytes.push_back(byte(value));
        bytes.push_back(byte(vlan.trailing));
    }

    append_record_header(bytes, 0x30, 4 + pvids.size() * 7);
    for (auto const [port, pvid] : pvids)
    {
        append_record_header(bytes, 0x30, 7);
        bytes.push_back(byte(port));
        bytes.push_back(byte(static_cast<std::uint8_t>(pvid >> 8)));
        bytes.push_back(byte(static_cast<std::uint8_t>(pvid & 0xff)));
    }
    return bytes;
}

[[nodiscard]] auto parse(std::vector<std::byte> const& bytes) -> jgs245_ports::Configuration
{
    return jgs245_ports::parse_configuration(std::span<std::byte const>(bytes));
}

[[nodiscard]] auto vlan(jgs245_ports::Configuration const& configuration, std::uint16_t id) -> jgs245_ports::Vlan const&
{
    auto const iterator = std::ranges::find(configuration.vlans, id, &jgs245_ports::Vlan::vlan_id);
    BOOST_REQUIRE(iterator != configuration.vlans.end());
    return *iterator;
}
} // namespace

BOOST_AUTO_TEST_CASE(bitmap_decoding_uses_msb_first_port_order)
{
    auto const decoded = jgs245_ports::decode_port_bitmap({byte(0x80), byte(0x04), byte(0x01)});
    BOOST_TEST(decoded == std::vector<unsigned>({1, 14, 24}));
}

BOOST_AUTO_TEST_CASE(verified_vlan_examples_decode_exactly)
{
    auto const configuration = parse(make_fixture());

    auto const& vlan4 = vlan(configuration, 4);
    BOOST_TEST(vlan4.member_ports == std::vector<unsigned>({1, 14, 24}));
    BOOST_TEST(vlan4.tagged_ports == std::vector<unsigned>({1}));
    BOOST_TEST(vlan4.untagged_ports == std::vector<unsigned>({14, 24}));

    auto const& vlan5 = vlan(configuration, 5);
    BOOST_TEST(vlan5.member_ports == std::vector<unsigned>({1, 11}));
    BOOST_TEST(vlan5.tagged_ports == std::vector<unsigned>({1, 11}));
    BOOST_TEST(vlan5.untagged_ports.empty());

    auto const& vlan6 = vlan(configuration, 6);
    BOOST_TEST(vlan6.member_ports == std::vector<unsigned>({1, 7}));
    BOOST_TEST(vlan6.tagged_ports == std::vector<unsigned>({1, 7}));

    auto const& vlan2000 = vlan(configuration, 2000);
    BOOST_TEST(vlan2000.member_ports == std::vector<unsigned>({15, 16, 17, 18, 19, 20}));
    BOOST_TEST(vlan2000.untagged_ports == std::vector<unsigned>({15, 16, 17, 18, 19, 20}));
    BOOST_TEST(vlan2000.tagged_ports.empty());
}

BOOST_AUTO_TEST_CASE(pvids_and_port_centric_model_match_verified_sample)
{
    auto const configuration = parse(make_fixture());
    BOOST_REQUIRE_EQUAL(configuration.ports.size(), 24);

    auto const& port1 = configuration.ports.at(0);
    BOOST_TEST(*port1.pvid == 1);
    BOOST_TEST(port1.member_vlans == std::vector<std::uint16_t>({1, 3, 4, 5, 6}));
    BOOST_TEST(port1.untagged_vlans == std::vector<std::uint16_t>({1}));
    BOOST_TEST(port1.tagged_vlans == std::vector<std::uint16_t>({3, 4, 5, 6}));

    BOOST_TEST(*configuration.ports.at(10).pvid == 3);
    BOOST_TEST(*configuration.ports.at(13).pvid == 4);
    BOOST_TEST(*configuration.ports.at(14).pvid == 2000);
    BOOST_TEST(*configuration.ports.at(23).pvid == 4);
    BOOST_TEST(configuration.warnings.empty());
}

BOOST_AUTO_TEST_CASE(truncated_record_pair_is_rejected)
{
    auto bytes = make_fixture();
    bytes.pop_back();
    BOOST_CHECK_THROW(static_cast<void>(parse(bytes)), jgs245_ports::ParseError);
}

BOOST_AUTO_TEST_CASE(parser_rejects_input_over_safety_limit)
{
    std::vector<std::byte> bytes(maximum_configuration_size + 1, std::byte{});
    BOOST_CHECK_THROW(static_cast<void>(parse(bytes)), jgs245_ports::ParseError);
}

BOOST_AUTO_TEST_CASE(record_marker_bytes_are_not_accepted_without_nested_framing)
{
    auto bytes = make_fixture();
    bytes.insert(bytes.begin() + 0x40, {byte(0x28), byte(0x00), byte(0x00), byte(0x04)});
    auto const configuration = parse(bytes);
    BOOST_TEST(configuration.vlans.size() == 8);
    BOOST_TEST(configuration.ports.size() == 24);
}

BOOST_AUTO_TEST_CASE(tagged_bits_outside_membership_are_rejected)
{
    auto vlans = sample_vlans();
    vlans.at(1).tagged = {0x80, 0x00, 0x00};
    BOOST_CHECK_THROW(static_cast<void>(parse(make_fixture(vlans))), jgs245_ports::ParseError);
}

BOOST_AUTO_TEST_CASE(invalid_vlan_id_is_rejected)
{
    auto vlans = sample_vlans();
    vlans.at(0).id = 0;
    BOOST_CHECK_THROW(static_cast<void>(parse(make_fixture(vlans))), jgs245_ports::ParseError);
}

BOOST_AUTO_TEST_CASE(duplicate_vlan_is_rejected)
{
    auto vlans = sample_vlans();
    vlans.at(1).id = 1;
    BOOST_CHECK_THROW(static_cast<void>(parse(make_fixture(vlans))), jgs245_ports::ParseError);
}

BOOST_AUTO_TEST_CASE(duplicate_pvid_record_is_rejected)
{
    auto pvids = sample_pvids();
    pvids.at(1).first = 1;
    BOOST_CHECK_THROW(static_cast<void>(parse(make_fixture(sample_vlans(), pvids))), jgs245_ports::ParseError);
}

BOOST_AUTO_TEST_CASE(unsupported_model_is_rejected)
{
    auto bytes = make_fixture();
    bytes.at(0) = byte('X');
    BOOST_CHECK_THROW(static_cast<void>(parse(bytes)), jgs245_ports::ParseError);
}

BOOST_AUTO_TEST_CASE(missing_pvid_and_pvid_membership_mismatch_are_warnings)
{
    auto pvids = sample_pvids();
    pvids.erase(pvids.begin() + 23);
    pvids.at(0).second = 2;
    auto const configuration = parse(make_fixture(sample_vlans(), pvids));
    BOOST_REQUIRE_EQUAL(configuration.warnings.size(), 2);
    BOOST_TEST(configuration.warnings.at(0).find("port 1") != std::string::npos);
    BOOST_TEST(configuration.warnings.at(1).find("port 24") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(trailing_bytes_and_malformed_trailing_records_are_reported)
{
    auto trailing_byte_fixture = make_fixture();
    trailing_byte_fixture.push_back(byte(0xaa));
    auto const trailing_byte_configuration = parse(trailing_byte_fixture);
    BOOST_REQUIRE_EQUAL(trailing_byte_configuration.warnings.size(), 1);
    BOOST_TEST(trailing_byte_configuration.warnings.front().find("1 trailing byte(s)") != std::string::npos);

    auto malformed_record_fixture = make_fixture();
    append_record_header(malformed_record_fixture, 0x38, 10);
    auto const malformed_record_configuration = parse(malformed_record_fixture);
    BOOST_REQUIRE_EQUAL(malformed_record_configuration.warnings.size(), 1);
    BOOST_TEST(malformed_record_configuration.warnings.front().find("malformed trailing record") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(parser_rejects_excessive_following_record_count)
{
    auto bytes = make_fixture();
    for (std::size_t index = 0; index < 4097; ++index) append_record_header(bytes, 0x38, 4);
    BOOST_CHECK_THROW(static_cast<void>(parse(bytes)), jgs245_ports::ParseError);
}

BOOST_AUTO_TEST_CASE(renderers_reject_oversized_domain_models)
{
    auto excessive_ports = parse(make_fixture());
    excessive_ports.ports.push_back(jgs245_ports::Port{.port = 25});
    BOOST_CHECK_THROW(static_cast<void>(jgs245_ports::render_json(excessive_ports)), std::runtime_error);

    auto excessive_warning = parse(make_fixture());
    excessive_warning.warnings.push_back(std::string(1025, 'x'));
    BOOST_CHECK_THROW(static_cast<void>(jgs245_ports::render_html(excessive_warning)), std::runtime_error);

    auto excessive_records = parse(make_fixture());
    excessive_records.records.resize(10001);
    BOOST_CHECK_THROW(static_cast<void>(jgs245_ports::render_record_dump(excessive_records)), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(renderers_are_port_centric_and_self_contained)
{
    auto const configuration = parse(make_fixture());
    auto const json = jgs245_ports::render_json(configuration);
    auto const csv = jgs245_ports::render_csv(configuration);
    auto const html = jgs245_ports::render_html(configuration);

    BOOST_TEST(json.find("\"port\":1") != std::string::npos);
    BOOST_TEST(json.find("\"tagged_vlans\":[3,4,5,6]") != std::string::npos);
    BOOST_TEST(csv.starts_with("port,pvid,member_vlans,untagged_vlans,tagged_vlans\n"));
    BOOST_TEST(csv.find("1,1,1;3;4;5;6,1,3;4;5;6\n") != std::string::npos);
    BOOST_TEST(html.starts_with("<!doctype html>"));
    BOOST_TEST(html.find("<script") == std::string::npos);
    BOOST_TEST(html.find("VLAN matrix") != std::string::npos);
}
