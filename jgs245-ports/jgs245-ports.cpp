#include <boost/program_options.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

import jgs245_ports.domain;
import jgs245_ports.parser;
import jgs245_ports.render;

namespace
{
namespace po = boost::program_options;
namespace fs = std::filesystem;

constexpr std::string_view tool_version = "0.1.0";
constexpr std::uintmax_t maximum_input_size = 16U * 1024U * 1024U;

enum class OutputFormat
{
    table,
    json,
    csv,
    html,
};

struct CommandLine
{
    fs::path input;
    std::optional<fs::path> output;
    OutputFormat format{OutputFormat::table};
    bool show_vlans{};
    bool dump_records{};
    bool strict{};
};

struct CommandLineResult
{
    std::optional<CommandLine> command;
    int early_exit_code{};
};

[[nodiscard]] auto parse_format(std::string_view text) -> OutputFormat
{
    if (text == "table") return OutputFormat::table;
    if (text == "json") return OutputFormat::json;
    if (text == "csv") return OutputFormat::csv;
    if (text == "html") return OutputFormat::html;
    throw po::validation_error(po::validation_error::invalid_option_value, "format", std::string(text));
}

[[nodiscard]] auto parse_command_line(int argc, char const* const argv[]) -> CommandLineResult
{
    std::string input;
    std::string output;
    std::string format = "table";
    bool show_vlans = false;
    bool dump_records = false;
    bool strict = false;

    po::options_description options("Options");
    options.add_options() //
            ("help,h", "show this help message") //
            ("version,V", "show version information") //
            ("format,f", po::value(&format)->default_value("table"), "output format: table, json, csv, or html") //
            ("output,o", po::value(&output), "write output to this path (use - for stdout)") //
            ("show-vlans", po::bool_switch(&show_vlans), "append a VLAN-centric table to table output") //
            ("dump-records", po::bool_switch(&dump_records), "describe record offsets/types on stderr without payload bytes") //
            ("strict", po::bool_switch(&strict), "fail without rendering if any warning is produced")("input", po::value(&input), "configuration backup path") //
            ;

    po::positional_options_description positional;
    positional.add("input", 1);

    po::variables_map variables;
    po::store(po::command_line_parser(argc, argv).options(options).positional(positional).run(), variables);
    po::notify(variables);

    if (variables.contains("help"))
    {
        std::cout << "Usage: jgs245-ports [options] switch.cfg\n\n" << options << '\n';
        return {.early_exit_code = 0};
    }
    if (variables.contains("version"))
    {
        std::cout << "jgs245-ports " << tool_version << '\n';
        return {.early_exit_code = 0};
    }
    if (input.empty()) throw po::error("the input configuration path is required");

    CommandLine command{
            .input = fs::path(input),
            .output = output.empty() ? std::nullopt : std::optional<fs::path>(fs::path(output)),
            .format = parse_format(format),
            .show_vlans = show_vlans,
            .dump_records = dump_records,
            .strict = strict,
    };
    return {.command = std::move(command)};
}

[[nodiscard]] auto read_input(fs::path const& path) -> std::vector<std::byte>
{
    std::error_code error;
    auto const size = fs::file_size(path, error);
    if (error) throw std::runtime_error("cannot determine input size: " + error.message());
    if (size > maximum_input_size) throw std::runtime_error("input exceeds the 16 MiB safety limit");

    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot open input file");
    std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    if (!bytes.empty()) input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!input || input.peek() != std::ifstream::traits_type::eof()) throw std::runtime_error("could not read the complete input file");
    return bytes;
}

[[nodiscard]] auto paths_refer_to_same_file(fs::path const& input, fs::path const& output) -> bool
{
    if (output == "-") return false;
    std::error_code error;
    if (fs::exists(output, error) && !error)
    {
        auto const equivalent = fs::equivalent(input, output, error);
        if (!error) return equivalent;
    }

    error.clear();
    auto input_path = fs::weakly_canonical(input, error);
    if (error) input_path = fs::absolute(input).lexically_normal();
    error.clear();
    auto output_path = fs::weakly_canonical(output, error);
    if (error) output_path = fs::absolute(output).lexically_normal();
    return input_path == output_path;
}

[[nodiscard]] auto render(jgs245_ports::Configuration const& configuration, CommandLine const& command) -> std::string
{
    switch (command.format)
    {
    case OutputFormat::table:
        return jgs245_ports::render_table(configuration, command.show_vlans);
    case OutputFormat::json:
        return jgs245_ports::render_json(configuration);
    case OutputFormat::csv:
        return jgs245_ports::render_csv(configuration);
    case OutputFormat::html:
        return jgs245_ports::render_html(configuration);
    }
    throw std::logic_error("unhandled output format");
}

[[nodiscard]] auto write_output(std::string_view content, std::optional<fs::path> const& output_path) -> bool
{
    if (!output_path || *output_path == "-")
    {
        std::cout.write(content.data(), static_cast<std::streamsize>(content.size()));
        return static_cast<bool>(std::cout);
    }

    std::ofstream output(*output_path, std::ios::binary | std::ios::trunc);
    if (!output) return false;
    output.write(content.data(), static_cast<std::streamsize>(content.size()));
    output.close();
    return static_cast<bool>(output);
}
} // namespace

int main(int argc, char const* const argv[])
{
    CommandLineResult parsed;
    try
    {
        parsed = parse_command_line(argc, argv);
    }
    catch (po::error const& error)
    {
        std::cerr << "jgs245-ports: command-line error: " << error.what() << "\nTry 'jgs245-ports --help' for usage.\n";
        return 2;
    }
    if (!parsed.command) return parsed.early_exit_code;
    auto const& command = *parsed.command;

    if (command.output && paths_refer_to_same_file(command.input, *command.output))
    {
        std::cerr << "jgs245-ports: refusing to overwrite the input configuration file\n";
        return 3;
    }

    std::vector<std::byte> bytes;
    try
    {
        bytes = read_input(command.input);
    }
    catch (std::exception const& error)
    {
        std::cerr << "jgs245-ports: input error: " << error.what() << '\n';
        return 3;
    }

    jgs245_ports::Configuration configuration;
    try
    {
        configuration = jgs245_ports::parse_configuration(std::span<std::byte const>(bytes));
    }
    catch (jgs245_ports::ParseError const& error)
    {
        std::cerr << "jgs245-ports: malformed or unsupported configuration: " << error.what() << '\n';
        return 4;
    }

    for (auto const& warning : configuration.warnings) std::cerr << "jgs245-ports: warning: " << warning << '\n';
    if (command.dump_records)
    {
        std::cerr << "jgs245-ports: diagnostic record metadata may reveal configuration structure; payload bytes are intentionally omitted\n";
        std::cerr << jgs245_ports::render_record_dump(configuration);
    }
    if (command.strict && !configuration.warnings.empty())
    {
        std::cerr << "jgs245-ports: strict mode rejected a configuration with warnings\n";
        return 5;
    }

    auto const content = render(configuration, command);
    if (!write_output(content, command.output))
    {
        std::cerr << "jgs245-ports: output error: could not write the requested output\n";
        return 6;
    }
    return 0;
}
