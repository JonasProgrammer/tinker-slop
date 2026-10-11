#include <array>
#include <boost/program_options.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

import ubqt_redact.core;

namespace
{
namespace fs = std::filesystem;
using ubqt_redact::failure;

std::string read_file(fs::path const& path)
{
    std::error_code error;
    if (!fs::is_regular_file(path, error) || error) throw failure(3, "input must be a readable regular file");
    std::ifstream input(path, std::ios::binary);
    if (!input) throw failure(3, "cannot open input file");
    std::string result;
    std::array<char, 8192> buffer{};
    while (input)
    {
        input.read(buffer.data(), buffer.size());
        auto const count = static_cast<std::size_t>(input.gcount());
        if (count > ubqt_redact::input_limit - result.size()) throw failure(3, "input exceeds 16 MiB limit");
        result.append(buffer.data(), count);
    }
    if (!input.eof()) throw failure(3, "cannot read input file");
    return result;
}

bool same_path(fs::path const& a, fs::path const& b)
{
    std::error_code error;
    if (fs::equivalent(a, b, error) && !error) return true;
    error.clear();
    auto const left = fs::weakly_canonical(a, error);
    if (error) throw failure(3, "cannot resolve file path");
    auto const right = fs::weakly_canonical(b, error);
    if (error) throw failure(3, "cannot resolve file path");
    return left == right;
}

void validate_paths(fs::path const& input, fs::path const& output, fs::path const& map)
{
    if (input.empty() || output.empty() || map.empty()) throw failure(3, "file paths must not be empty");
    if (same_path(input, output) || same_path(input, map) || same_path(output, map)) throw failure(3, "input, output, and map must be distinct files");
    for (auto const& path : {output, map})
    {
        std::error_code error;
        auto const status = fs::symlink_status(path, error);
        if (error && error != std::errc::no_such_file_or_directory) throw failure(3, "cannot inspect file path");
        if (fs::is_symlink(status)) throw failure(3, "output and map paths must not be symbolic links");
    }
}

void require_new_file(fs::path const& path)
{
    std::error_code error;
    bool const exists = fs::exists(path, error);
    if (error || exists) throw failure(3, "destination already exists or cannot be inspected");
    auto parent = path.parent_path();
    if (parent.empty()) parent = ".";
    if (!fs::is_directory(parent, error) || error) throw failure(3, "destination parent is not a directory");
}

void write_file(fs::path const& path, std::string_view text, bool sensitive)
{
    if (!std::in_range<std::streamsize>(text.size())) throw failure(7, "output size cannot be represented");
    // C++26 exclusive creation also closes the ordinary existence-check race.
    std::ofstream output(path, std::ios::binary | std::ios::out | std::ios::noreplace);
    if (!output) throw failure(7, "cannot create output file");
    if (sensitive)
    {
        std::error_code error;
        fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace, error);
        if (error)
        {
            output.close();
            fs::remove(path, error);
            throw failure(7, "cannot restrict secret-bearing output permissions");
        }
    }
    output.write(text.data(), static_cast<std::streamsize>(text.size()));
    output.flush();
    bool const failed = !output;
    output.close();
    if (failed || !output)
    {
        std::error_code error;
        fs::remove(path, error);
        throw failure(7, "cannot write output file");
    }
}
} // namespace

int main(int argc, char** argv)
{
    namespace po = boost::program_options;
    try
    {
        std::string command, input, output, map, escape = "raw";
        po::options_description options("ubqt-redact options");
        options.add_options()("help,h", "Show help")("input", po::value(&input), "Source text (maximum 16 MiB)")("output", po::value(&output), "New output file; existing files are refused")(
                "map",
                po::value(&map),
                "Secret map JSON: contains plaintext secrets; keep private")(
                "escape",
                po::value(&escape),
                "Restore: raw (default), vyatta-value, routeros-value, json-string-value");
        po::options_description all;
        all.add(options).add_options()("command", po::value(&command), "Command");
        po::positional_options_description positional;
        positional.add("command", 1);
        po::variables_map arguments;
        try
        {
            po::store(po::command_line_parser(argc, argv).options(all).positional(positional).run(), arguments);
            po::notify(arguments);
        }
        catch (po::error const&)
        {
            throw failure(2, "invalid command line; use --help");
        }
        if (arguments.contains("help"))
        {
            std::cout << "Usage: ubqt-redact redact|restore --input FILE --output FILE --map FILE\n"
                    << options << "\nThe map contains plaintext secrets. Keep it out of AI workflows and version control.\n"
                    << "Value escaping inserts content inside existing double quotes; it does not add quotes.\n"
                    << "Exit codes: 0 success, 2 CLI, 3 file/path, 4 source, 5 map, 6 restore, 7 write.\n";
            return 0;
        }
        if ((command != "redact" && command != "restore") || !arguments.contains("input") || !arguments.contains("output") || !arguments.contains("map"))
            throw failure(2, "use redact or restore with --input, --output, and --map; see --help");
        if (command == "redact" && arguments.contains("escape")) throw failure(2, "--escape is only valid for restore");
        auto const mode = command == "restore" ? ubqt_redact::parse_escape_mode(escape) : ubqt_redact::escape_mode::raw;
        validate_paths(input, output, map);
        require_new_file(output);
        if (command == "redact") require_new_file(map);
        auto const source = read_file(input);
        if (command == "redact")
        {
            auto const result = ubqt_redact::redact(source, input);
            auto const map_text = ubqt_redact::write_map(result.mapping);
            write_file(map, map_text, true);
            try
            {
                write_file(output, result.text, false);
            }
            catch (...)
            {
                std::error_code error;
                fs::remove(map, error);
                throw;
            }
            std::cerr << "Redacted " << result.mapping.secrets.size() << " secret occurrence(s).\n";
            if (result.generic_matches) std::cerr << "Warning: " << result.generic_matches << " generic secret match(es); audit map contexts locally.\n";
        }
        else
        {
            auto const mapping = ubqt_redact::read_map(read_file(map));
            auto const restored = ubqt_redact::restore(source, mapping, mode);
            write_file(output, restored, true);
        }
        return 0;
    }
    catch (failure const& error)
    {
        std::cerr << "ubqt-redact: " << error.what() << '\n';
        return error.status;
    }
    catch (std::exception const&)
    {
        std::cerr << "ubqt-redact: operation failed\n";
        return 7;
    }
}
