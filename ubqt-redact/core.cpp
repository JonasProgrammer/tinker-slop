module;

#include <algorithm>
#include <array>
#include <boost/json.hpp>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <map>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

export module ubqt_redact.core;

export namespace ubqt_redact
{
constexpr std::size_t input_limit = 16 * 1024 * 1024;
constexpr std::size_t output_limit = 64 * 1024 * 1024;
constexpr std::size_t record_limit = 100000;
constexpr std::string_view sentinel_prefix = "JSTS_SECRET_v1_";

struct failure : std::runtime_error
{
    int status;
    failure(int code, std::string const& message) : std::runtime_error(message), status(code) {}
};

struct secret_record
{
    std::size_t id{};
    std::string sentinel;
    std::string kind;
    std::string original;
    std::string source_literal;
    std::string source_encoding;
    std::string path;
    std::size_t line{};
    std::size_t column{};
    bool generic{};
};

struct secret_map
{
    std::string run_id;
    std::string source_path;
    std::vector<secret_record> secrets;
};

struct redact_result
{
    std::string text;
    secret_map mapping;
    std::size_t generic_matches{};
};

enum class escape_mode
{
    raw,
    vyatta_value,
    routeros_value,
    json_string_value,
};

redact_result redact(std::string_view input, std::string source_path);

std::string write_map(secret_map const& mapping);

secret_map read_map(std::string_view input);

escape_mode parse_escape_mode(std::string_view name);

std::string escape_value(std::string_view value, escape_mode mode);

std::string restore(std::string_view input, secret_map const& mapping, escape_mode mode);
} // namespace ubqt_redact

namespace ubqt_redact
{
// Text is UTF-8; controls other than config whitespace are not accepted.
void validate_text(std::string_view text, int status)
{
    if (text.size() > input_limit) throw failure(status, "input exceeds 16 MiB limit");
    for (std::size_t i = 0; i < text.size();)
    {
        auto const c = static_cast<unsigned char>(text[i++]);
        if (c < 0x80)
        {
            if ((c < 0x20 && c != '\n' && c != '\r' && c != '\t') || c == 0x7f) throw failure(status, "unsupported control character");
            continue;
        }
        unsigned count;
        std::uint32_t value;
        std::uint32_t minimum;
        if (c >= 0xc2 && c <= 0xdf)
        {
            count = 1;
            value = c & 0x1f;
            minimum = 0x80;
        }
        else if (c >= 0xe0 && c <= 0xef)
        {
            count = 2;
            value = c & 0x0f;
            minimum = 0x800;
        }
        else if (c >= 0xf0 && c <= 0xf4)
        {
            count = 3;
            value = c & 7;
            minimum = 0x10000;
        }
        else
            throw failure(status, "invalid UTF-8");
        if (count > text.size() - i) throw failure(status, "truncated UTF-8");
        while (count--)
        {
            auto const next = static_cast<unsigned char>(text[i++]);
            if ((next & 0xc0) != 0x80) throw failure(status, "invalid UTF-8");
            value = (value << 6) | (next & 0x3f);
        }
        if (value < minimum || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) throw failure(status, "invalid UTF-8 code point");
    }
}

namespace detail
{
struct span
{
    std::size_t begin, end;
};

struct token
{
    std::size_t begin{}, end{}, inner_begin{}, inner_end{}, line{}, column{};
    std::string value;
    bool quoted{};
    bool pem{};
};

struct replacement
{
    span range;
    secret_record record;
};

bool identifier_char(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
}

std::vector<span> pem_spans(std::string_view text)
{
    constexpr std::array labels{"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "DSA PRIVATE KEY"};
    std::vector<span> result;
    std::size_t pos = 0;
    while ((pos = text.find("-----BEGIN ", pos)) != std::string_view::npos)
    {
        bool found = false;
        for (auto const label : labels)
        {
            auto const begin_marker = std::string("-----BEGIN ") + label + "-----";
            if (text.substr(pos, begin_marker.size()) != begin_marker) continue;
            auto const end_marker = std::string("-----END ") + label + "-----";
            auto const end = text.find(end_marker, pos + begin_marker.size());
            auto const nested = text.find("-----BEGIN ", pos + begin_marker.size());
            if (end == std::string_view::npos || (nested != std::string_view::npos && nested < end)) throw failure(4, "unterminated or nested private key block");
            result.push_back({pos, end + end_marker.size()});
            if (result.size() > record_limit) throw failure(4, "too many private key blocks");
            pos = end + end_marker.size();
            found = true;
            break;
        }
        if (!found)
        {
            auto const end = text.find("-----", pos + 11);
            if (end == std::string_view::npos || end - pos > 100) throw failure(4, "malformed PEM header");
            if (text.substr(pos, end - pos).find("PRIVATE") != std::string_view::npos) throw failure(4, "unsupported private key block");
            pos = end + 5;
        }
    }
    return result;
}

class scanner
{
    std::string_view text;
    std::vector<span> const& blocks;
    std::size_t pos{}, line = 1, column = 1, block_index{};

    void advance()
    {
        if (text[pos++] == '\n')
        {
            ++line;
            column = 1;
        }
        else
            ++column;
    }

    [[noreturn]] void error(char const* message) const { throw failure(4, std::string(message) + " at line " + std::to_string(line) + ", column " + std::to_string(column)); }

public:
    scanner(std::string_view input, std::vector<span> const& pem) : text(input), blocks(pem) {}

    enum class type
    {
        value,
        left,
        right,
        separator,
        end,
    };

    struct item
    {
        type kind;
        token atom;
    };

    item next()
    {
        for (;;)
        {
            if (pos == text.size()) return {type::end, {}};
            char const c = text[pos];
            if (c == ' ' || c == '\t' || c == '\r')
            {
                advance();
                continue;
            }
            if (c == '#' || text.substr(pos, 2) == "//")
            {
                while (pos < text.size() && text[pos] != '\n') advance();
                continue;
            }
            if (text.substr(pos, 2) == "/*")
            {
                advance();
                advance();
                while (pos < text.size() && text.substr(pos, 2) != "*/")
                {
                    if (text.substr(pos, 2) == "/*") error("nested block comment");
                    advance();
                }
                if (pos == text.size()) error("unterminated block comment");
                advance();
                advance();
                continue;
            }
            break;
        }
        char const c = text[pos];
        if (c == '{' || c == '}' || c == ';' || c == '\n')
        {
            advance();
            return {c == '{' ? type::left : c == '}' ? type::right : type::separator, {}};
        }
        token t;
        t.begin = t.inner_begin = pos;
        t.line = line;
        t.column = column;
        while (block_index < blocks.size() && blocks[block_index].begin < pos) ++block_index;
        if (block_index < blocks.size() && blocks[block_index].begin == pos)
        {
            t.pem = true;
            auto const end = blocks[block_index++].end;
            while (pos < end) advance();
            t.end = t.inner_end = pos;
            t.value = text.substr(t.begin, t.end - t.begin);
            return {type::value, std::move(t)};
        }
        if (c == '"')
        {
            t.quoted = true;
            advance();
            t.inner_begin = pos;
            while (pos < text.size() && text[pos] != '"')
            {
                if (text[pos] == '\\')
                {
                    advance();
                    if (pos == text.size()) error("truncated quoted escape");
                    switch (text[pos])
                    {
                    case 'n':
                        t.value += '\n';
                        break;
                    case 'r':
                        t.value += '\r';
                        break;
                    case 't':
                        t.value += '\t';
                        break;
                    case '\\':
                        t.value += '\\';
                        break;
                    case '"':
                        t.value += '"';
                        break;
                    default:
                        error("unsupported quoted escape");
                    }
                    advance();
                }
                else
                {
                    t.value += text[pos];
                    advance();
                }
            }
            if (pos == text.size()) error("unterminated quoted value");
            t.inner_end = pos;
            advance();
            t.end = pos;
            if (pos < text.size() && text[pos] != ' ' && text[pos] != '\t' && text[pos] != '\r' && text[pos] != '\n' && text[pos] != ';' && text[pos] != '{' && text[pos] != '}' && text[pos] != '#' &&
                text.substr(pos, 2) != "/*" && text.substr(pos, 2) != "//")
                error("missing delimiter after quoted value");
        }
        else
        {
            while (pos < text.size())
            {
                char const a = text[pos];
                if (a == ' ' || a == '\t' || a == '\r' || a == '\n' || a == ';' || a == '{' || a == '}') break;
                if (a == '"' || a == '\\') error("ambiguous unquoted value");
                advance();
            }
            t.end = t.inner_end = pos;
            t.value = text.substr(t.begin, t.end - t.begin);
        }
        return {type::value, std::move(t)};
    }
};

bool contains(std::vector<std::string> const& path, std::string_view atom)
{
    return std::ranges::find(path, atom) != path.end();
}

bool starts(std::vector<std::string> const& path, std::initializer_list<std::string_view> prefix)
{
    if (path.size() < prefix.size()) return false;
    return std::equal(prefix.begin(), prefix.end(), path.begin());
}

std::pair<std::string, bool> classify(std::vector<std::string> const& path, std::string_view leaf)
{
    if (starts(path, {"interfaces"}) && contains(path, "pppoe"))
    {
        if (leaf == "user-id") return {"pppoe-user", false};
        if (leaf == "password") return {"pppoe-password", false};
    }
    if (starts(path, {"system", "login", "user"}) && contains(path, "authentication") && (leaf == "plaintext-password" || leaf == "encrypted-password")) return {"password", false};
    if (starts(path, {"vpn"}) &&
        ((contains(path, "ipsec") && leaf == "pre-shared-secret") || (contains(path, "l2tp") && leaf == "pre-shared-secret") || (contains(path, "pptp") && leaf == "password")))
        return {"psk", false};
    if (starts(path, {"service", "dns", "dynamic"}) && (leaf == "login" || leaf == "password")) return {leaf == "login" ? "ddns-user" : "ddns-password", false};
    if (starts(path, {"service", "snmp"}))
    {
        if (leaf == "community") return {"snmp-community", false};
        if (contains(path, "v3") && contains(path, "user") && (contains(path, "auth") || contains(path, "privacy")) && leaf != "type" && leaf != "protocol") return {"snmp-secret", false};
    }
    if (leaf == "private-key" || leaf == "preshared-key") return {leaf == "private-key" ? "private-key" : "psk", false};
    constexpr std::array names{"password", "passwd", "plaintext-password", "encrypted-password", "secret", "shared-secret", "pre-shared-secret", "passphrase", "token"};
    for (auto name : names)
        if (leaf == name) return {"password", true};
    return {"", false};
}

std::string join(std::vector<std::string> const& path, std::string_view leaf)
{
    std::string result;
    for (auto const& atom : path)
    {
        if (!result.empty()) result += ' ';
        result += atom;
    }
    if (!result.empty()) result += ' ';
    result += leaf;
    return result;
}

std::string generate_run_id()
{
    std::random_device random;
    constexpr std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::uniform_int_distribution<unsigned> distribution(0, 31);
    std::string result;
    for (unsigned i = 0; i < 16; ++i) result += alphabet[distribution(random)];
    return result;
}

std::string make_sentinel(std::string_view run, std::string kind, std::size_t id)
{
    for (char& c : kind)
    {
        if (c == '-')
            c = '_';
        else if (c >= 'a' && c <= 'z')
            c = static_cast<char>(c - 'a' + 'A');
    }
    std::ostringstream out;
    out << sentinel_prefix << run << '_' << kind << '_' << std::setfill('0') << std::setw(6) << id;
    return out.str();
}

void append_bounded(std::string& out, std::string_view part, int code)
{
    if (part.size() > output_limit - out.size()) throw failure(code, "output exceeds 64 MiB limit");
    out.append(part);
}
} // namespace detail

redact_result redact(std::string_view input, std::string source_path)
{
    using namespace detail;
    validate_text(input, 4);
    if (input.find("JSTS_SECRET_") != std::string_view::npos) throw failure(4, "input contains an existing sentinel prefix");
    auto const blocks = pem_spans(input);
    scanner scan(input, blocks);
    std::vector<replacement> replacements;
    std::vector<std::string> path;
    std::vector<std::size_t> frames;
    std::vector<token> pending;
    std::size_t token_count = 0;
    std::size_t metadata_size = source_path.size();
    auto const add = [&](token const& t, std::string kind, bool generic, std::string context)
    {
        if (replacements.size() == record_limit) throw failure(4, "too many secrets");
        // Repeated long contexts must not amplify a small source without a bound.
        for (auto size : {t.value.size(), t.end - t.begin, context.size(), std::size_t{256}})
        {
            if (metadata_size > input_limit || size > input_limit - metadata_size) throw failure(4, "secret metadata exceeds 16 MiB limit");
            metadata_size += size;
        }
        secret_record record;
        record.kind = std::move(kind);
        record.original = t.value;
        record.source_literal = input.substr(t.begin, t.end - t.begin);
        record.source_encoding = t.quoted ? "vyatta-double-quoted" : t.pem ? "pem" : "vyatta-atom";
        record.path = std::move(context);
        record.line = t.line;
        record.column = t.column;
        record.generic = generic;
        replacements.push_back({{t.inner_begin, t.inner_end}, std::move(record)});
    };
    auto const flush = [&]()
    {
        if (pending.empty()) return;
        if (pending.size() == 1)
        {
            if (pending[0].pem)
                add(pending[0], "private-key", false, join(path, "private-key-block"));
            else if (!classify(path, pending[0].value).first.empty())
                throw failure(4, "missing secret value at line " + std::to_string(pending[0].line));
        }
        else if (pending.size() == 2)
        {
            auto [kind, generic] = classify(path, pending[0].value);
            if (pending[1].pem || pending[1].value.find("-----BEGIN ") != std::string::npos)
            {
                // Only recognized private PEM blocks promote an otherwise public value.
                auto block = std::ranges::lower_bound(blocks, pending[1].inner_begin, {}, &span::begin);
                if (block != blocks.end() && block->end <= pending[1].inner_end)
                {
                    kind = "private-key";
                    generic = false;
                }
            }
            if (!kind.empty()) add(pending[1], kind, generic, join(path, pending[0].value));
        }
        else
            throw failure(4, "ambiguous leaf statement at line " + std::to_string(pending[0].line));
        pending.clear();
    };
    for (;;)
    {
        auto item = scan.next();
        if (++token_count > 1000000) throw failure(4, "too many source tokens");
        if (item.kind == scanner::type::value)
        {
            // Two-atom leaves may share a line, as in compact brace configs.
            if (pending.size() == 2) flush();
            pending.push_back(std::move(item.atom));
        }
        else if (item.kind == scanner::type::left)
        {
            if (pending.empty() || frames.size() >= 128) throw failure(4, "invalid or excessive brace nesting");
            if (!classify(path, pending[0].value).first.empty())
            {
                if (pending.size() != 2) throw failure(4, "secret block requires one value");
                auto [kind, generic] = classify(path, pending[0].value);
                add(pending[1], kind, generic, join(path, pending[0].value));
                // Secret block identifiers must not leak into map context paths.
                pending[1].value = "<redacted>";
            }
            frames.push_back(path.size());
            for (auto const& t : pending) path.push_back(t.value);
            pending.clear();
        }
        else if (item.kind == scanner::type::right)
        {
            flush();
            if (frames.empty()) throw failure(4, "unmatched closing brace");
            path.resize(frames.back());
            frames.pop_back();
        }
        else if (item.kind == scanner::type::separator)
            flush();
        else
        {
            flush();
            break;
        }
    }
    if (!frames.empty()) throw failure(4, "unclosed brace");
    auto const scalar_count = replacements.size();
    std::size_t position = 0, line = 1, column = 1;
    // A scalar containing a PEM block takes precedence over the inner block.
    for (auto b : blocks)
    {
        while (position < b.begin)
        {
            if (input[position++] == '\n')
            {
                ++line;
                column = 1;
            }
            else
                ++column;
        }
        auto after = std::lower_bound(replacements.begin(), replacements.begin() + scalar_count, b.begin, [](replacement const& r, std::size_t begin) { return r.range.end <= begin; });
        bool covered = false;
        if (after != replacements.begin() + scalar_count && after->range.begin <= b.begin && after->range.end >= b.end) covered = true;
        if (!covered)
        {
            token t;
            t.begin = t.inner_begin = b.begin;
            t.end = t.inner_end = b.end;
            t.pem = true;
            t.value = input.substr(b.begin, b.end - b.begin);
            t.line = line;
            t.column = column;
            add(t, "private-key", false, "private-key-block");
        }
    }
    std::ranges::sort(replacements, {}, [](replacement const& r) { return r.range.begin; });
    redact_result result;
    result.mapping.run_id = generate_run_id();
    result.mapping.source_path = std::move(source_path);
    std::size_t previous = 0;
    for (auto& r : replacements)
    {
        if (r.range.begin < previous) throw failure(4, "overlapping secret spans");
        previous = r.range.end;
        r.record.id = result.mapping.secrets.size() + 1;
        r.record.sentinel = make_sentinel(result.mapping.run_id, r.record.kind, r.record.id);
        if (r.record.generic) ++result.generic_matches;
        result.mapping.secrets.push_back(r.record);
    }
    std::size_t size = input.size();
    for (auto const& r : replacements)
    {
        size -= r.range.end - r.range.begin;
        if (r.record.sentinel.size() > output_limit - size) throw failure(4, "output exceeds 64 MiB limit");
        size += r.record.sentinel.size();
    }
    result.text.resize(size);
    std::size_t cursor = input.size(), destination = size;
    auto const copy_back = [&](std::string_view part)
    {
        if (part.size() > destination) throw failure(4, "invalid replacement layout");
        destination -= part.size();
        part.copy(result.text.data() + destination, part.size());
    };
    // Fill from the end without repeatedly shifting large strings.
    for (auto r = replacements.rbegin(); r != replacements.rend(); ++r)
    {
        copy_back(input.substr(r->range.end, cursor - r->range.end));
        copy_back(r->record.sentinel);
        cursor = r->range.begin;
    }
    copy_back(input.substr(0, cursor));
    return result;
}

std::string write_map(secret_map const& mapping)
{
    namespace json = boost::json;
    json::array secrets;
    for (auto const& r : mapping.secrets)
        secrets.emplace_back(json::object{{"id", r.id},
                                          {"sentinel", r.sentinel},
                                          {"kind", r.kind},
                                          {"original", r.original},
                                          {"source_literal", r.source_literal},
                                          {"source_encoding", r.source_encoding},
                                          {"generic", r.generic},
                                          {"context", json::object{{"path", r.path}, {"line", r.line}, {"column", r.column}}}});
    std::string result = json::serialize(json::object{{"format", "jsts-secret-map"},
                                                      {"version", 1},
                                                      {"run_id", mapping.run_id},
                                                      {"source", json::object{{"kind", "ubiquiti-edgerouter-boot-cfg"}, {"path", mapping.source_path}}},
                                                      {"sentinel_prefix", sentinel_prefix},
                                                      {"secrets", std::move(secrets)}});
    result += '\n';
    if (result.size() > input_limit) throw failure(4, "mapping exceeds 16 MiB limit");
    return result;
}

namespace detail
{
boost::json::value const& member(boost::json::object const& object, std::string_view key)
{
    auto const* value = object.if_contains(key);
    if (!value) throw failure(5, "map is missing a required field");
    return *value;
}

std::string string_member(boost::json::object const& object, std::string_view key)
{
    auto const& value = member(object, key);
    if (!value.is_string()) throw failure(5, "map field must be a string");
    return std::string(value.as_string());
}

std::size_t number_member(boost::json::object const& object, std::string_view key)
{
    auto const& value = member(object, key);
    if (!value.is_int64() || value.as_int64() <= 0 || value.as_int64() > static_cast<std::int64_t>(input_limit)) throw failure(5, "map field must be a bounded positive integer");
    return static_cast<std::size_t>(value.as_int64());
}

// Boost.JSON accepts duplicate object keys; reject them before building the DOM.
void reject_duplicate_keys(std::string_view text)
{
    struct frame
    {
        bool object;
        bool expect_key;
        std::set<std::string> keys;
    };
    std::vector<frame> stack;
    for (std::size_t i = 0; i < text.size(); ++i)
    {
        char const c = text[i];
        if (c == '{' || c == '[')
        {
            if (stack.size() == 128) throw failure(5, "map nesting exceeds limit");
            frame next;
            next.object = c == '{';
            next.expect_key = next.object;
            stack.push_back(std::move(next));
        }
        else if (c == '}' || c == ']')
        {
            if (stack.empty()) throw failure(5, "malformed map structure");
            stack.pop_back();
        }
        else if (c == ',' && !stack.empty() && stack.back().object)
            stack.back().expect_key = true;
        else if (c == '"')
        {
            auto const begin = i++;
            while (i < text.size() && text[i] != '"')
            {
                if (text[i] == '\\') ++i;
                if (i < text.size()) ++i;
            }
            if (i == text.size()) throw failure(5, "unterminated map string");
            if (!stack.empty() && stack.back().object && stack.back().expect_key)
            {
                boost::system::error_code error;
                auto const key = boost::json::parse(text.substr(begin, i - begin + 1), error);
                if (error || !key.is_string()) throw failure(5, "malformed map key");
                if (!stack.back().keys.insert(std::string(key.as_string())).second) throw failure(5, "duplicate map object key");
                stack.back().expect_key = false;
            }
        }
    }
}
} // namespace detail

secret_map read_map(std::string_view input)
{
    using namespace detail;
    validate_text(input, 5);
    reject_duplicate_keys(input);
    boost::system::error_code error;
    boost::json::parse_options options;
    options.max_depth = 128;
    auto const value = boost::json::parse(input, error, {}, options);
    if (error || !value.is_object()) throw failure(5, "invalid mapping JSON");
    auto const& root = value.as_object();
    if (string_member(root, "format") != "jsts-secret-map" || number_member(root, "version") != 1 || string_member(root, "sentinel_prefix") != sentinel_prefix)
        throw failure(5, "unsupported map format or version");
    secret_map result;
    result.run_id = string_member(root, "run_id");
    if (result.run_id.size() < 8 || result.run_id.size() > 32 || !std::ranges::all_of(result.run_id, [](char c) { return (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7'); }))
        throw failure(5, "invalid map run ID");
    auto const& source = member(root, "source");
    if (!source.is_object() || string_member(source.as_object(), "kind") != "ubiquiti-edgerouter-boot-cfg") throw failure(5, "invalid map source");
    result.source_path = string_member(source.as_object(), "path");
    auto const& secrets = member(root, "secrets");
    if (!secrets.is_array() || secrets.as_array().size() > record_limit) throw failure(5, "invalid map secret array");
    std::set<std::string> seen;
    for (auto const& entry : secrets.as_array())
    {
        if (!entry.is_object()) throw failure(5, "invalid secret record");
        auto const& object = entry.as_object();
        secret_record r;
        r.id = number_member(object, "id");
        r.sentinel = string_member(object, "sentinel");
        r.kind = string_member(object, "kind");
        r.original = string_member(object, "original");
        constexpr std::array kinds{"pppoe-user", "pppoe-password", "password", "psk", "ddns-user", "ddns-password", "snmp-community", "snmp-secret", "private-key"};
        if (std::ranges::find(kinds, r.kind) == kinds.end() || r.id != result.secrets.size() + 1 || r.sentinel != make_sentinel(result.run_id, r.kind, r.id) || !seen.insert(r.sentinel).second)
            throw failure(5, "invalid or duplicate secret sentinel");
        validate_text(r.original, 5);
        if (r.original.find("JSTS_SECRET_") != std::string::npos) throw failure(5, "nested sentinel in secret value");
        auto const& context = member(object, "context");
        if (!context.is_object()) throw failure(5, "invalid secret context");
        r.path = string_member(context.as_object(), "path");
        r.line = number_member(context.as_object(), "line");
        r.column = number_member(context.as_object(), "column");
        if (auto const* literal = object.if_contains("source_literal"))
        {
            if (!literal->is_string()) throw failure(5, "invalid source literal");
            r.source_literal = std::string(literal->as_string());
        }
        if (auto const* encoding = object.if_contains("source_encoding"))
        {
            if (!encoding->is_string()) throw failure(5, "invalid source encoding");
            r.source_encoding = std::string(encoding->as_string());
            if (r.source_encoding != "vyatta-double-quoted" && r.source_encoding != "vyatta-atom" && r.source_encoding != "pem") throw failure(5, "unknown source encoding");
        }
        if (auto const* generic = object.if_contains("generic"))
        {
            if (!generic->is_bool()) throw failure(5, "invalid generic match flag");
            r.generic = generic->as_bool();
        }
        result.secrets.push_back(std::move(r));
    }
    return result;
}

escape_mode parse_escape_mode(std::string_view name)
{
    if (name == "raw") return escape_mode::raw;
    if (name == "vyatta-value") return escape_mode::vyatta_value;
    if (name == "routeros-value") return escape_mode::routeros_value;
    if (name == "json-string-value") return escape_mode::json_string_value;
    throw failure(2, "unknown escaping mode");
}

std::string escape_value(std::string_view value, escape_mode mode)
{
    switch (mode)
    {
    case escape_mode::raw:
        return std::string(value);
    case escape_mode::json_string_value:
    {
        auto const quoted = boost::json::serialize(boost::json::value(value));
        return quoted.substr(1, quoted.size() - 2);
    }
    case escape_mode::vyatta_value:
    case escape_mode::routeros_value:
        break;
    default:
        throw failure(2, "unknown escaping mode");
    }
    std::string result;
    for (char c : value)
    {
        switch (c)
        {
        case '\n':
        case '\r':
            if (mode == escape_mode::routeros_value) throw failure(6, "RouterOS value mode rejects multiline secrets");
            result += c == '\n' ? "\\n" : "\\r";
            break;
        case '\t':
            result += "\\t";
            break;
        case '\\':
            result += "\\\\";
            break;
        case '"':
            result += "\\\"";
            break;
        case '$':
            if (mode == escape_mode::routeros_value) result += '\\';
            result += c;
            break;
        default:
            result += c;
        }
    }
    return result;
}

std::string restore(std::string_view input, secret_map const& mapping, escape_mode mode)
{
    validate_text(input, 6);
    // Check the mode even when there are no placeholders.
    (void)escape_value("", mode);
    std::map<std::string_view, secret_record const*, std::less<> > records;
    for (auto const& record : mapping.secrets) records.emplace(record.sentinel, &record);
    std::map<std::string_view, std::string, std::less<> > escaped;
    std::string output;
    std::size_t pos = 0;
    while (pos < input.size())
    {
        auto const begin = input.find("JSTS_SECRET_", pos);
        if (begin == std::string_view::npos) break;
        detail::append_bounded(output, input.substr(pos, begin - pos), 6);
        auto end = begin;
        while (end < input.size() && detail::identifier_char(input[end])) ++end;
        if (begin > 0 && detail::identifier_char(input[begin - 1])) throw failure(6, "sentinel is embedded in an identifier");
        auto const name = input.substr(begin, end - begin);
        auto const found = records.find(name);
        if (found == records.end()) throw failure(6, "unknown or altered sentinel");
        auto cached = escaped.find(name);
        if (cached == escaped.end()) cached = escaped.emplace(name, escape_value(found->second->original, mode)).first;
        detail::append_bounded(output, cached->second, 6);
        pos = end;
    }
    detail::append_bounded(output, input.substr(pos), 6);
    return output;
}
} // namespace ubqt_redact
