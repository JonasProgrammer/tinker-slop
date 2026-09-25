module;

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

export module jgs245_ports.domain;

export namespace jgs245_ports
{
constexpr std::size_t port_count = 24;

enum class Knowledge
{
    verified,
    inferred,
    unknown,
};

struct DeviceMetadata
{
    std::string model;
    std::string config_format;
    std::string firmware;
};

struct Vlan
{
    std::uint16_t vlan_id{};
    std::array<std::byte, 3> membership_bitmap{};
    std::array<std::byte, 3> tagged_bitmap{};
    std::byte unknown_trailing{};
    std::vector<unsigned> member_ports;
    std::vector<unsigned> tagged_ports;
    std::vector<unsigned> untagged_ports;
    std::size_t source_offset{};
};

struct Port
{
    unsigned port{};
    std::optional<std::uint16_t> pvid;
    std::vector<std::uint16_t> member_vlans;
    std::vector<std::uint16_t> tagged_vlans;
    std::vector<std::uint16_t> untagged_vlans;
};

struct RecordSummary
{
    std::size_t offset{};
    std::size_t size{};
    std::uint8_t type{};
    Knowledge knowledge{Knowledge::unknown};
    std::string description;
};

struct Configuration
{
    DeviceMetadata device;
    std::vector<Port> ports;
    std::vector<Vlan> vlans;
    std::vector<std::string> warnings;
    std::vector<RecordSummary> records;
};
} // namespace jgs245_ports
