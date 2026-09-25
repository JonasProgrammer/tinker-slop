module;

#include <boost/endian/conversion.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <set>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

export module jgs245_ports.parser;

import jgs245_ports.domain;

namespace jgs245_ports {namespace
    {
    constexpr std::size_t maximum_configuration_size = 16U * 1024U * 1024U;
    constexpr std::size_t record_header_size = 4;
    constexpr std::size_t vlan_record_size = 13;
    constexpr std::size_t pvid_record_size = 7;
    constexpr std::uint8_t vlan_record_type = 0x28;
    constexpr std::uint8_t pvid_record_type = 0x30;
    constexpr std::size_t model_offset = 0x00;
    constexpr std::size_t config_format_offset = 0x14;
    constexpr std::size_t firmware_offset = 0x28;
    constexpr std::size_t fixed_text_size = 0x14;
    constexpr std::size_t record_search_offset = 0x40;
    constexpr std::size_t maximum_vlan_records = 4094;
    constexpr std::size_t maximum_pvid_records = port_count;
    constexpr std::size_t maximum_following_records = 4096;

    struct RecordView
    {
        std::uint8_t type{};
        std::size_t offset{};
        std::size_t size{};
    };

    struct Anchors
    {
        RecordView vlan_container;
        RecordView pvid_container;
    };

    [[nodiscard]] auto byte_value(std::byte value) -> unsigned char
    {
        return std::to_integer<unsigned char>(value);
    }

    [[nodiscard]] auto byte_pointer(std::span<std::byte const> bytes, std::size_t offset) -> unsigned char const*
    {
        return reinterpret_cast<unsigned char const*>(bytes.data() + offset);
    }

    [[nodiscard]] auto read_u16_be(std::span<std::byte const> bytes, std::size_t offset) -> std::uint16_t
    {
        if (offset > bytes.size() || bytes.size() - offset < 2)
        {
            throw std::out_of_range("16-bit read exceeds input bounds");
        }
        return boost::endian::load_big_u16(byte_pointer(bytes, offset));
    }

    [[nodiscard]] auto read_u24_be(std::span<std::byte const> bytes, std::size_t offset) -> std::uint32_t
    {
        if (offset > bytes.size() || bytes.size() - offset < 3)
        {
            throw std::out_of_range("24-bit read exceeds input bounds");
        }
        return boost::endian::load_big_u24(byte_pointer(bytes, offset));
    }

    [[nodiscard]] auto offset_text(std::size_t offset) -> std::string
    {
        std::ostringstream output;
        output << "0x" << std::hex << offset;
        return output.str();
    }

    [[nodiscard]] auto read_record(std::span<std::byte const> bytes, std::size_t offset) -> std::optional<RecordView>
    {
        if (offset > bytes.size() || bytes.size() - offset < record_header_size) return std::nullopt;

        auto const size = static_cast<std::size_t>(read_u24_be(bytes, offset + 1));
        if (size < record_header_size || size > bytes.size() - offset) return std::nullopt;

        return RecordView{.type = byte_value(bytes[offset]), .offset = offset, .size = size};
    }

    [[nodiscard]] auto has_uniform_children(std::span<std::byte const> bytes, RecordView container, std::uint8_t type, std::size_t child_size, std::size_t maximum_children) -> bool
    {
        if (container.size <= record_header_size) return false;
        auto const payload_size = container.size - record_header_size;
        if (payload_size % child_size != 0) return false;
        if (payload_size / child_size > maximum_children) return false;

        auto cursor = container.offset + record_header_size;
        auto const end = container.offset + container.size;
        while (cursor < end)
        {
            auto child = read_record(bytes, cursor);
            if (!child || child->type != type || child->size != child_size) return false;
            cursor += child->size;
        }
        return cursor == end;
    }

    [[nodiscard]] auto locate_anchors(std::span<std::byte const> bytes) -> Anchors
    {
        std::vector<Anchors> matches;
        if (bytes.size() < record_search_offset + record_header_size)
        {
            throw std::runtime_error("input is too short to contain the known record area");
        }

        for (std::size_t offset = record_search_offset; offset + record_header_size <= bytes.size(); ++offset)
        {
            if (byte_value(bytes[offset]) != vlan_record_type) continue;
            auto vlan_container = read_record(bytes, offset);
            if (!vlan_container || !has_uniform_children(bytes, *vlan_container, vlan_record_type, vlan_record_size, maximum_vlan_records)) continue;

            auto const pvid_offset = offset + vlan_container->size;
            auto pvid_container = read_record(bytes, pvid_offset);
            if (!pvid_container || pvid_container->type != pvid_record_type) continue;
            if (!has_uniform_children(bytes, *pvid_container, pvid_record_type, pvid_record_size, maximum_pvid_records)) continue;

            matches.push_back(Anchors{.vlan_container = *vlan_container, .pvid_container = *pvid_container});
            if (matches.size() > 1) break;
        }

        if (matches.empty())
        {
            throw std::runtime_error("could not locate a structurally valid adjacent VLAN/PVID record pair");
        }
        if (matches.size() != 1)
        {
            throw std::runtime_error("input contains multiple plausible VLAN/PVID record pairs; refusing an ambiguous decode");
        }
        return matches.front();
    }

    [[nodiscard]] auto read_fixed_text(std::span<std::byte const> bytes, std::size_t offset, std::string_view field_name) -> std::string
    {
        if (offset > bytes.size() || bytes.size() - offset < fixed_text_size)
        {
            throw std::runtime_error(std::string(field_name) + " header field is truncated");
        }

        std::string value;
        value.reserve(fixed_text_size);
        bool terminated = false;
        for (std::size_t index = 0; index < fixed_text_size; ++index)
        {
            auto const character = byte_value(bytes[offset + index]);
            if (character == 0)
            {
                terminated = true;
                break;
            }
            if (character < 0x20 || character > 0x7e)
            {
                throw std::runtime_error(std::string(field_name) + " header field is not printable ASCII");
            }
            value.push_back(static_cast<char>(character));
        }

        if (!terminated || value.empty())
        {
            throw std::runtime_error(std::string(field_name) + " header field is not a non-empty NUL-terminated string");
        }
        return value;
    }

    [[nodiscard]] auto decode_bitmap_impl(std::array<std::byte, 3> bitmap) -> std::vector<unsigned>
    {
        std::vector<unsigned> ports;
        for (std::size_t byte_index = 0; byte_index < bitmap.size(); ++byte_index)
        {
            auto const value = byte_value(bitmap[byte_index]);
            for (unsigned bit_index = 0; bit_index < 8; ++bit_index)
            {
                auto const bit = static_cast<unsigned char>(0x80u >> bit_index);
                if ((value & bit) != 0) ports.push_back(static_cast<unsigned>(byte_index * 8 + bit_index + 1));
            }
        }
        return ports;
    }

    [[nodiscard]] auto parse_vlans(std::span<std::byte const> bytes, RecordView container, std::vector<RecordSummary>& summaries) -> std::vector<Vlan>
    {
        std::vector<Vlan> vlans;
        std::set<std::uint16_t> ids;
        summaries.push_back(RecordSummary{
                .offset = container.offset,
                .size = container.size,
                .type = container.type,
                .knowledge = Knowledge::inferred,
                .description = "VLAN container framing",
        });

        auto cursor = container.offset + record_header_size;
        auto const end = container.offset + container.size;
        while (cursor < end)
        {
            auto const vlan_id = read_u16_be(bytes, cursor + 4);
            if (vlan_id == 0 || vlan_id > 4094)
            {
                throw std::runtime_error("invalid VLAN ID " + std::to_string(vlan_id) + " at " + offset_text(cursor));
            }
            if (!ids.insert(vlan_id).second)
            {
                throw std::runtime_error("duplicate VLAN ID " + std::to_string(vlan_id) + " at " + offset_text(cursor));
            }

            std::array<std::byte, 3> membership{
                    bytes[cursor + 6],
                    bytes[cursor + 7],
                    bytes[cursor + 8],
            };
            std::array<std::byte, 3> tagged{
                    bytes[cursor + 9],
                    bytes[cursor + 10],
                    bytes[cursor + 11],
            };
            for (std::size_t index = 0; index < membership.size(); ++index)
            {
                auto const outside = static_cast<unsigned char>(byte_value(tagged[index]) & static_cast<unsigned char>(~byte_value(membership[index])));
                if (outside != 0)
                {
                    throw std::runtime_error("VLAN " + std::to_string(vlan_id) + " has tagged ports outside its membership bitmap at " + offset_text(cursor));
                }
            }

            std::array<std::byte, 3> untagged{};
            for (std::size_t index = 0; index < membership.size(); ++index)
            {
                untagged[index] = static_cast<std::byte>(byte_value(membership[index]) & static_cast<unsigned char>(~byte_value(tagged[index])));
            }

            vlans.push_back(Vlan{
                    .vlan_id = vlan_id,
                    .membership_bitmap = membership,
                    .tagged_bitmap = tagged,
                    .unknown_trailing = bytes[cursor + 12],
                    .member_ports = decode_bitmap_impl(membership),
                    .tagged_ports = decode_bitmap_impl(tagged),
                    .untagged_ports = decode_bitmap_impl(untagged),
                    .source_offset = cursor,
            });
            summaries.push_back(RecordSummary{
                    .offset = cursor,
                    .size = vlan_record_size,
                    .type = vlan_record_type,
                    .knowledge = Knowledge::verified,
                    .description = "VLAN " + std::to_string(vlan_id) + " payload",
            });
            cursor += vlan_record_size;
        }

        std::ranges::sort(vlans, {}, &Vlan::vlan_id);
        return vlans;
    }

    [[nodiscard]] auto parse_pvids(std::span<std::byte const> bytes, RecordView container, std::vector<RecordSummary>& summaries) -> std::array<std::optional<std::uint16_t>, port_count>
    {
        std::array<std::optional<std::uint16_t>, port_count> pvids{};
        summaries.push_back(RecordSummary{
                .offset = container.offset,
                .size = container.size,
                .type = container.type,
                .knowledge = Knowledge::inferred,
                .description = "PVID container framing",
        });

        auto cursor = container.offset + record_header_size;
        auto const end = container.offset + container.size;
        while (cursor < end)
        {
            auto const port = static_cast<unsigned>(byte_value(bytes[cursor + 4]));
            auto const pvid = read_u16_be(bytes, cursor + 5);
            if (port == 0 || port > port_count)
            {
                throw std::runtime_error("invalid physical port " + std::to_string(port) + " in PVID record at " + offset_text(cursor));
            }
            if (pvid == 0 || pvid > 4094)
            {
                throw std::runtime_error("invalid PVID " + std::to_string(pvid) + " for port " + std::to_string(port) + " at " + offset_text(cursor));
            }
            if (pvids[port - 1])
            {
                throw std::runtime_error("duplicate PVID record for port " + std::to_string(port) + " at " + offset_text(cursor));
            }
            pvids[port - 1] = pvid;
            summaries.push_back(RecordSummary{
                    .offset = cursor,
                    .size = pvid_record_size,
                    .type = pvid_record_type,
                    .knowledge = Knowledge::verified,
                    .description = "port " + std::to_string(port) + " PVID payload",
            });
            cursor += pvid_record_size;
        }
        return pvids;
    }

    void describe_following_records(std::span<std::byte const> bytes, std::size_t offset, std::vector<RecordSummary>& summaries, std::vector<std::string>& warnings)
    {
        auto cursor = offset;
        std::size_t record_count = 0;
        while (cursor < bytes.size())
        {
            auto const remaining = bytes.size() - cursor;
            if (remaining < record_header_size)
            {
                warnings.push_back(std::to_string(remaining) + " trailing byte(s) at " + offset_text(cursor) + " do not form a record header");
                return;
            }
            auto record = read_record(bytes, cursor);
            if (!record)
            {
                warnings.push_back("malformed trailing record at " + offset_text(cursor) + " with " + std::to_string(remaining) + " byte(s) remaining");
                return;
            }
            if (record_count >= maximum_following_records)
            {
                throw std::runtime_error("record count after the PVID table exceeds the safety limit of " + std::to_string(maximum_following_records));
            }
            summaries.push_back(RecordSummary{
                    .offset = record->offset,
                    .size = record->size,
                    .type = record->type,
                    .knowledge = Knowledge::unknown,
                    .description = "undecoded record",
            });
            cursor += record->size;
            ++record_count;
        }
    }

    [[nodiscard]] auto contains(std::vector<unsigned> const& values, unsigned value) -> bool
    {
        return std::ranges::binary_search(values, value);
    }

    [[nodiscard]] auto build_ports(std::vector<Vlan> const& vlans, std::array<std::optional<std::uint16_t>, port_count> const& pvids, std::vector<std::string>& warnings) -> std::vector<Port>
    {
        std::vector<Port> ports;
        ports.reserve(port_count);
        for (std::size_t index = 0; index < port_count; ++index)
        {
            Port port{.port = static_cast<unsigned>(index + 1), .pvid = pvids[index]};
            for (auto const& vlan : vlans)
            {
                if (contains(vlan.member_ports, port.port)) port.member_vlans.push_back(vlan.vlan_id);
                if (contains(vlan.tagged_ports, port.port)) port.tagged_vlans.push_back(vlan.vlan_id);
                if (contains(vlan.untagged_ports, port.port)) port.untagged_vlans.push_back(vlan.vlan_id);
            }

            if (!port.pvid)
            {
                warnings.push_back("port " + std::to_string(port.port) + " has no PVID record");
            }
            else if (!std::ranges::binary_search(port.untagged_vlans, *port.pvid))
            {
                warnings.push_back("port " + std::to_string(port.port) + " has PVID " + std::to_string(*port.pvid) + " but is not an untagged member of that VLAN");
            }
            ports.push_back(std::move(port));
        }
        return ports;
    }
    } // namespace

    export class ParseError : public std::runtime_error
    {
    public:
        using std::runtime_error::runtime_error;
    };

    export [[nodiscard]] auto decode_port_bitmap(std::array<std::byte, 3> bitmap) -> std::vector<unsigned>
    {
        return decode_bitmap_impl(bitmap);
    }

    export [[nodiscard]] auto parse_configuration(std::span<std::byte const> bytes) -> Configuration
    {
        try
        {
            if (bytes.size() > maximum_configuration_size)
            {
                throw std::runtime_error("input exceeds the 16 MiB parser safety limit");
            }
            Configuration configuration;
            configuration.device.model = read_fixed_text(bytes, model_offset, "model");
            configuration.device.config_format = read_fixed_text(bytes, config_format_offset, "config format");
            configuration.device.firmware = read_fixed_text(bytes, firmware_offset, "firmware");

            if (configuration.device.model != "JGS524Ev2")
            {
                throw std::runtime_error("unsupported model '" + configuration.device.model + "' (expected JGS524Ev2)");
            }
            if (configuration.device.config_format != "v2.2.3")
            {
                configuration.warnings.push_back("unverified config format '" + configuration.device.config_format + "'; decoded using the v2.2.3 record layout");
            }
            if (configuration.device.firmware != "2.6.0.50")
            {
                configuration.warnings.push_back("unverified firmware '" + configuration.device.firmware + "'; decoded using the 2.6.0.50 record layout");
            }

            auto const anchors = locate_anchors(bytes);
            configuration.vlans = parse_vlans(bytes, anchors.vlan_container, configuration.records);
            auto const pvids = parse_pvids(bytes, anchors.pvid_container, configuration.records);
            describe_following_records(bytes, anchors.pvid_container.offset + anchors.pvid_container.size, configuration.records, configuration.warnings);
            configuration.ports = build_ports(configuration.vlans, pvids, configuration.warnings);
            return configuration;
        }
        catch (ParseError const&)
        {
            throw;
        }
        catch (std::exception const& error)
        {
            throw ParseError(error.what());
        }
    }
} // namespace jgs245_ports
