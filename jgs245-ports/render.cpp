module;

#include <boost/json.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <optional>
#include <ostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

export module jgs245_ports.render;

import jgs245_ports.domain;

namespace jgs245_ports {namespace
    {
    template <typename Integer>
    [[nodiscard]] auto join_values(std::vector<Integer> const& values, std::string_view separator) -> std::string
    {
        if (values.empty()) return {};
        std::ostringstream output;
        for (std::size_t index = 0; index < values.size(); ++index)
        {
            if (index != 0) output << separator;
            output << static_cast<unsigned long long>(values[index]);
        }
        return output.str();
    }

    template <typename Integer>
    [[nodiscard]] auto format_ranges(std::vector<Integer> const& values) -> std::string
    {
        if (values.empty()) return "-";

        std::ostringstream output;
        std::size_t index = 0;
        while (index < values.size())
        {
            auto const start = values[index];
            auto end = start;
            auto next = index + 1;
            while (next < values.size() && static_cast<unsigned long long>(values[next]) == static_cast<unsigned long long>(end) + 1)
            {
                end = values[next];
                ++next;
            }
            if (index != 0) output << ',';
            auto const run_length = next - index;
            output << static_cast<unsigned long long>(start);
            if (run_length >= 3)
            {
                output << '-' << static_cast<unsigned long long>(end);
            }
            else if (run_length == 2)
            {
                output << ',' << static_cast<unsigned long long>(end);
            }
            index = next;
        }
        return output.str();
    }

    [[nodiscard]] auto pvid_text(std::optional<std::uint16_t> pvid) -> std::string
    {
        if (!pvid) return "-";
        return std::to_string(*pvid);
    }

    template <typename Integer>
    [[nodiscard]] auto json_numbers(std::vector<Integer> const& values) -> boost::json::array
    {
        boost::json::array result;
        result.reserve(values.size());
        for (auto value : values) result.emplace_back(static_cast<std::uint64_t>(value));
        return result;
    }

    [[nodiscard]] auto html_escape(std::string_view text) -> std::string
    {
        std::string escaped;
        escaped.reserve(text.size());
        for (char character : text)
        {
            switch (character)
            {
            case '&':
                escaped += "&amp;";
                break;
            case '<':
                escaped += "&lt;";
                break;
            case '>':
                escaped += "&gt;";
                break;
            case '"':
                escaped += "&quot;";
                break;
            case '\'':
                escaped += "&#39;";
                break;
            default:
                escaped += character;
                break;
            }
        }
        return escaped;
    }

    [[nodiscard]] auto knowledge_text(Knowledge knowledge) -> std::string_view
    {
        switch (knowledge)
        {
        case Knowledge::verified:
            return "VERIFIED";
        case Knowledge::inferred:
            return "INFERRED";
        case Knowledge::unknown:
            return "UNKNOWN";
        }
        return "UNKNOWN";
    }

    [[nodiscard]] auto vlan_status(Vlan const& vlan, unsigned port) -> char
    {
        if (std::ranges::binary_search(vlan.tagged_ports, port)) return 'T';
        if (std::ranges::binary_search(vlan.untagged_ports, port)) return 'U';
        return '-';
    }
    } // namespace

    export [[nodiscard]] auto render_table(Configuration const& configuration, bool show_vlans) -> std::string
    {
        std::size_t pvid_width = 4;
        std::size_t untagged_width = std::string_view("Untagged VLANs").size();
        std::size_t tagged_width = std::string_view("Tagged VLANs").size();
        std::vector<std::string> untagged;
        std::vector<std::string> tagged;
        untagged.reserve(configuration.ports.size());
        tagged.reserve(configuration.ports.size());
        for (auto const& port : configuration.ports)
        {
            auto untagged_text = format_ranges(port.untagged_vlans);
            auto tagged_text = format_ranges(port.tagged_vlans);
            pvid_width = std::max(pvid_width, pvid_text(port.pvid).size());
            untagged_width = std::max(untagged_width, untagged_text.size());
            tagged_width = std::max(tagged_width, tagged_text.size());
            untagged.push_back(std::move(untagged_text));
            tagged.push_back(std::move(tagged_text));
        }

        std::ostringstream output;
        output << std::right << std::setw(4) << "Port"
                << "  " << std::setw(static_cast<int>(pvid_width)) << "PVID"
                << "  " << std::left << std::setw(static_cast<int>(untagged_width)) << "Untagged VLANs"
                << "  " << std::setw(static_cast<int>(tagged_width)) << "Tagged VLANs" << '\n';
        output << "----  " << std::string(pvid_width, '-') << "  " << std::string(untagged_width, '-') << "  " << std::string(tagged_width, '-') << '\n';
        for (std::size_t index = 0; index < configuration.ports.size(); ++index)
        {
            auto const& port = configuration.ports[index];
            output << std::right << std::setw(4) << port.port << "  " << std::setw(static_cast<int>(pvid_width)) << pvid_text(port.pvid) << "  " << std::left << std::setw(
                            static_cast<int>(untagged_width))
                    << untagged[index] << "  " << std::setw(static_cast<int>(tagged_width)) << tagged[index] << '\n';
        }

        if (show_vlans)
        {
            output << "\nVLAN  Member ports  Untagged ports  Tagged ports\n"
                    << "----  ------------  --------------  ------------\n";
            for (auto const& vlan : configuration.vlans)
            {
                output << std::right << std::setw(4) << vlan.vlan_id << "  " << std::left << std::setw(12) << format_ranges(vlan.member_ports) << "  " << std::setw(14)
                        << format_ranges(vlan.untagged_ports) << "  " << format_ranges(vlan.tagged_ports) << '\n';
            }
        }
        return output.str();
    }

    export [[nodiscard]] auto render_json(Configuration const& configuration) -> std::string
    {
        boost::json::object device;
        device.emplace("model", configuration.device.model);
        device.emplace("firmware", configuration.device.firmware);
        device.emplace("config_format", configuration.device.config_format);

        boost::json::array ports;
        ports.reserve(configuration.ports.size());
        for (auto const& port : configuration.ports)
        {
            boost::json::object object;
            object.emplace("port", static_cast<std::uint64_t>(port.port));
            if (port.pvid)
            {
                object.emplace("pvid", static_cast<std::uint64_t>(*port.pvid));
            }
            else
            {
                object.emplace("pvid", nullptr);
            }
            object.emplace("member_vlans", json_numbers(port.member_vlans));
            object.emplace("tagged_vlans", json_numbers(port.tagged_vlans));
            object.emplace("untagged_vlans", json_numbers(port.untagged_vlans));
            ports.emplace_back(std::move(object));
        }

        boost::json::array vlans;
        vlans.reserve(configuration.vlans.size());
        for (auto const& vlan : configuration.vlans)
        {
            boost::json::object object;
            object.emplace("vlan_id", static_cast<std::uint64_t>(vlan.vlan_id));
            object.emplace("member_ports", json_numbers(vlan.member_ports));
            object.emplace("tagged_ports", json_numbers(vlan.tagged_ports));
            object.emplace("untagged_ports", json_numbers(vlan.untagged_ports));
            vlans.emplace_back(std::move(object));
        }

        boost::json::array warnings;
        warnings.reserve(configuration.warnings.size());
        for (auto const& warning : configuration.warnings) warnings.emplace_back(warning);

        boost::json::object root;
        root.emplace("device", std::move(device));
        root.emplace("ports", std::move(ports));
        root.emplace("vlans", std::move(vlans));
        root.emplace("warnings", std::move(warnings));
        return boost::json::serialize(root) + '\n';
    }

    export [[nodiscard]] auto render_csv(Configuration const& configuration) -> std::string
    {
        std::ostringstream output;
        output << "port,pvid,member_vlans,untagged_vlans,tagged_vlans\n";
        for (auto const& port : configuration.ports)
        {
            output << port.port << ',';
            if (port.pvid) output << *port.pvid;
            output << ',' << join_values(port.member_vlans, ";") << ',' << join_values(port.untagged_vlans, ";") << ',' << join_values(port.tagged_vlans, ";") << '\n';
        }
        return output.str();
    }

    export [[nodiscard]] auto render_html(Configuration const& configuration) -> std::string
    {
        std::ostringstream output;
        output << "<!doctype html>\n"
                "<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
                "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
                "<title>JGS524Ev2 VLAN report</title>\n"
                "<style>\n"
                ":root{color-scheme:light dark;--bg:#f4f6f8;--panel:#fff;--text:#17212b;--muted:#5b6875;--line:#cbd3da;--tag:#1565c0;--untag:#2e7d32;--warn:#9a5a00}"
                "@media(prefers-color-scheme:dark){:root{--bg:#111820;--panel:#1b2530;--text:#eef4f8;--muted:#aebbc6;--line:#43515e;--tag:#64b5f6;--untag:#81c784;--warn:#ffb74d}}"
                "*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.45 system-ui,sans-serif}"
                "main{max-width:1200px;margin:auto;padding:24px}h1,h2{line-height:1.2}h1{margin:0 0 4px}h2{margin-top:28px}"
                ".meta{color:var(--muted);margin:0 0 20px}.ports{display:grid;grid-template-columns:repeat(12,minmax(68px,1fr));gap:8px}"
                ".port{border:1px solid var(--line);border-top:5px solid var(--untag);border-radius:5px;background:var(--panel);padding:7px;min-height:94px}"
                ".port strong{display:block;font-size:17px}.port small{display:block;color:var(--muted)}.port .tag{color:var(--tag)}.port .untag{color:var(--untag)}"
                "table{width:100%;border-collapse:collapse;background:var(--panel)}th,td{border:1px solid var(--line);padding:6px 8px;text-align:left}th{position:sticky;top:0;background:var(--panel)}"
                ".matrix{font-size:12px}.matrix th,.matrix td{text-align:center;padding:4px}.matrix th:first-child{text-align:right}.t{background:color-mix(in srgb,var(--tag) "
                "25%,transparent);color:var(--tag);font-weight:700}.u{background:color-mix(in srgb,var(--untag) 25%,transparent);color:var(--untag);font-weight:700}.n{color:var(--muted)}"
                ".legend span{display:inline-block;margin-right:16px}.warnings{border-left:5px solid var(--warn);background:var(--panel);padding:10px 14px}.scroll{overflow:auto}"
                "@media(max-width:900px){.ports{grid-template-columns:repeat(6,minmax(68px,1fr))}}@media(max-width:520px){main{padding:14px}.ports{grid-template-columns:repeat(3,minmax(68px,1fr))}}"
                "</style>\n</head>\n<body>\n<main>\n<h1>Switch VLAN report</h1>\n<p class=\"meta\">Model "
                << html_escape(configuration.device.model) << " &middot; Firmware " << html_escape(configuration.device.firmware) << " &middot; Config format "
                << html_escape(configuration.device.config_format) << "</p>\n<h2>Port overview</h2>\n<div class=\"ports\">\n";

        for (auto const& port : configuration.ports)
        {
            output << "<article class=\"port\" aria-label=\"Port " << port.port << "\"><strong>Port " << port.port << "</strong><small>PVID " << html_escape(pvid_text(port.pvid))
                    << "</small><small class=\"untag\">U: " << html_escape(format_ranges(port.untagged_vlans)) << "</small><small class=\"tag\">T: " << html_escape(format_ranges(port.tagged_vlans))
                    << "</small></article>\n";
        }
        output << "</div>\n<h2>Port details</h2>\n<div class=\"scroll\"><table>\n<thead><tr><th>Port</th><th>PVID</th><th>Member VLANs</th><th>Untagged VLANs</th><th>Tagged "
                "VLANs</th></tr></thead>\n<tbody>\n";
        for (auto const& port : configuration.ports)
        {
            output << "<tr><th scope=\"row\">" << port.port << "</th><td>" << html_escape(pvid_text(port.pvid)) << "</td><td>" << html_escape(format_ranges(port.member_vlans)) << "</td><td>"
                    << html_escape(format_ranges(port.untagged_vlans)) << "</td><td>" << html_escape(format_ranges(port.tagged_vlans)) << "</td></tr>\n";
        }
        output <<
                "</tbody>\n</table></div>\n<h2>VLAN matrix</h2>\n<p class=\"legend\"><span><b class=\"t\">T</b> Tagged</span><span><b class=\"u\">U</b> Untagged</span><span><b class=\"n\">-</b> Not "
                "member</span></p>\n<div class=\"scroll\"><table class=\"matrix\">\n<thead><tr><th>VLAN</th>";
        for (unsigned port = 1; port <= port_count; ++port) output << "<th>" << port << "</th>";
        output << "</tr></thead>\n<tbody>\n";
        for (auto const& vlan : configuration.vlans)
        {
            output << "<tr><th scope=\"row\">" << vlan.vlan_id << "</th>";
            for (unsigned port = 1; port <= port_count; ++port)
            {
                auto const status = vlan_status(vlan, port);
                auto const css = status == 'T' ? "t" : status == 'U' ? "u" : "n";
                auto const label = status == 'T' ? "tagged" : status == 'U' ? "untagged" : "not a member";
                output << "<td class=\"" << css << "\" title=\"Port " << port << ": " << label << "\" aria-label=\"Port " << port << ": " << label << "\">" << status << "</td>";
            }
            output << "</tr>\n";
        }
        output << "</tbody>\n</table></div>\n<h2>Warnings</h2>\n";
        if (configuration.warnings.empty())
        {
            output << "<p>No inconsistencies detected.</p>\n";
        }
        else
        {
            output << "<ul class=\"warnings\">\n";
            for (auto const& warning : configuration.warnings) output << "<li>" << html_escape(warning) << "</li>\n";
            output << "</ul>\n";
        }
        output << "</main>\n</body>\n</html>\n";
        return output.str();
    }

    export [[nodiscard]] auto render_record_dump(Configuration const& configuration) -> std::string
    {
        std::ostringstream output;
        output << "Record summary (payload bytes omitted):\n";
        for (auto const& record : configuration.records)
        {
            output << "  offset=0x" << std::hex << record.offset << " type=0x" << std::setw(2) << std::setfill('0') << static_cast<unsigned>(record.type) << std::dec << std::setfill(' ')
                    << " size=" << record.size << " knowledge=" << knowledge_text(record.knowledge) << " description=" << record.description << '\n';
        }
        return output.str();
    }
} // namespace jgs245_ports
