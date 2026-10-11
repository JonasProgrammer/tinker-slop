#include <boost/json.hpp>
#include <iostream>
#include <source_location>
#include <stdexcept>
#include <string>
#include <string_view>

import ubqt_redact.core;

namespace
{
using namespace ubqt_redact;

void require(bool condition, std::source_location location = std::source_location::current())
{
    if (!condition)
    {
        std::cerr << "Expectation failed at line " << location.line() << '\n';
        throw std::runtime_error("test expectation failed");
    }
}

template <class function>
void rejects(int status, function test)
{
    try
    {
        test();
    }
    catch (failure const& error)
    {
        require(error.status == status);
        return;
    }
    throw std::runtime_error("expected rejection");
}

void tests()
{
    std::string const source = "# synthetic fixture\ninterfaces { ethernet eth0 { pppoe 0 { user-id \"alice@example\" password plain } } }\n";
    auto const result = redact(source, "fixture.cfg");
    require(result.mapping.secrets.size() == 2);
    require(result.mapping.secrets[0].kind == "pppoe-user");
    require(result.mapping.secrets[0].path == "interfaces ethernet eth0 pppoe 0 user-id");
    require(result.mapping.secrets[0].line == 2 && result.mapping.secrets[0].column == 48);
    require(result.mapping.secrets[1].kind == "pppoe-password");
    require(result.text.find("alice@example") == std::string::npos);
    require(restore(result.text, read_map(write_map(result.mapping)), escape_mode::raw) == source);
    auto const quotes = redact("password \"with \\\" quote \\\\ slash\\t\\n\"\n", "fixture");
    require(quotes.mapping.secrets[0].original == "with \" quote \\ slash\t\n");
    require(restore(quotes.text, quotes.mapping, parse_escape_mode("vyatta-value")) == "password \"with \\\" quote \\\\ slash\\t\\n\"\n");
    rejects(6, [&] { restore(quotes.text, quotes.mapping, escape_mode::routeros_value); });
    require(escape_value("a\"\\$\t", escape_mode::routeros_value) == "a\\\"\\\\\\$\\t");
    auto const json_escaped = escape_value("a\"\\\n\t", parse_escape_mode("json-string-value"));
    require(boost::json::parse("\"" + json_escaped + "\"").as_string() == "a\"\\\n\t");
    auto const equal = redact("password same\npassword same\n", "fixture");
    require(equal.mapping.secrets.size() == 2);
    require(equal.mapping.secrets[0].sentinel != equal.mapping.secrets[1].sentinel);
    require(equal.generic_matches == 2);
    auto const empty = redact("password \"\"\n", "fixture");
    require(empty.mapping.secrets.size() == 1 && empty.mapping.secrets[0].original.empty());
    auto const rules =
            redact("system { login { user admin { authentication { plaintext-password one\nencrypted-password two\n} } } }\n"
                   "vpn { ipsec { site-to-site { peer 1.2.3.4 { authentication { pre-shared-secret three\n} } } }\n"
                   "l2tp { remote-access { ipsec-settings { authentication { pre-shared-secret four\n} } } }\n"
                   "pptp { remote-access { authentication { local-users { username user { password five\n} } } } } }\n"
                   "service { dns { dynamic { interface eth0 { service provider { login six\npassword seven\n} } } }\n"
                   "snmp { community eight { authorization ro\n} v3 { user usr { auth { type sha\nplaintext-key nine\n} privacy { type aes\nencrypted-key ten\n} } } } }\n"
                   "interfaces { wireguard wg0 { private-key eleven\npreshared-key twelve\npublic-key public\n} }\n"
                   "custom { secret thirteen\ntoken fourteen\nkey public\n} \n",
                   "fixture");
    require(rules.mapping.secrets.size() == 14);
    require(rules.generic_matches == 2);
    require(rules.text.find("community eight") == std::string::npos);
    require(rules.text.find("type sha") != std::string::npos);
    require(rules.text.find("public-key public") != std::string::npos);
    auto const vif = redact("interfaces { ethernet eth0 { vif 10 { pppoe 0 { user-id u\npassword p\n} } } }", "fixture");
    require(vif.mapping.secrets.size() == 2 && vif.generic_matches == 0);
    std::string const pem = "-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----";
    for (auto config : {pem + "\n", "private-key \"" + pem + "\"\n", "/* " + pem + " */\n", "description \"" + pem + "\"\n", "private-key " + pem + "\n"})
    {
        auto const keys = redact(config, "fixture");
        require(keys.mapping.secrets.size() == 1);
        require(keys.mapping.secrets[0].kind == "private-key");
        require(keys.text.find("YWJj") == std::string::npos);
        require(restore(keys.text, keys.mapping, escape_mode::raw) == config);
    }
    require(redact("# password public\n/* password public */\ndescription \"public\"\n", "fixture").mapping.secrets.empty());
    for (auto const value : {"abc#def", "abc//def", "https://example.invalid/secret", "abc/*def*/"})
    {
        auto const punctuation = redact(std::string("password ") + value + "\n", "fixture");
        require(punctuation.mapping.secrets.size() == 1);
        require(punctuation.mapping.secrets[0].original == value);
        require(punctuation.text.find(value) == std::string::npos);
    }
    auto const mixed_keys = redact("/* " + pem + " */\nprivate-key \"" + pem + "\"\n/* " + pem + " */\n", "fixture");
    require(mixed_keys.mapping.secrets.size() == 3);
    rejects(4, [&] { redact("# -----BEGIN PRIVATE KEY-----\npassword s\n# -----END PRIVATE KEY-----\n", "fixture"); });
    std::string nested;
    for (unsigned i = 0; i < 128; ++i) nested += "node { ";
    require(redact(nested + "password p " + std::string(128, '}'), "fixture").mapping.secrets.size() == 1);
    rejects(4, [&] { redact(nested + "node { password p " + std::string(129, '}'), "fixture"); });
    std::string large_context = "node " + std::string(4096, 'x') + " {\n";
    for (unsigned i = 0; i < 5000; ++i) large_context += "password p\n";
    large_context += "}\n";
    rejects(4, [&] { redact(large_context, "fixture"); });
    for (auto const invalid : {"password \"unterminated",
                               "password \"bad\\q\"",
                               "}",
                               "a {",
                               "password\n",
                               "password value\\x",
                               "/* unfinished",
                               "password \"x\"tail",
                               "_JSTS_SECRET_v1",
                               "-----BEGIN PRIVATE KEY-----\nx",
                               "-----BEGIN UNKNOWN PRIVATE KEY-----\nx"})
        rejects(4, [&] { redact(invalid, "fixture"); });
    rejects(4, [&] { redact(std::string(129, '{'), "fixture"); });
    rejects(4, [&] { redact(std::string(input_limit + 1, 'a'), "fixture"); });
    rejects(4, [&] { redact(std::string("password ") + '\0', "fixture"); });
    rejects(4, [&] { redact(std::string("password ") + "\xc0\xaf", "fixture"); });
    rejects(6, [&] { restore("JSTS_SECRET_v1_UNKNOWN_PASSWORD_000001", result.mapping, escape_mode::raw); });
    rejects(6, [&] { restore("JSTS_SECRET_v2_UNKNOWN_PASSWORD_000001", result.mapping, escape_mode::raw); });
    rejects(6, [&] { restore("x" + result.mapping.secrets[0].sentinel, result.mapping, escape_mode::raw); });
    rejects(6, [&] { restore(result.mapping.secrets[0].sentinel + "x", result.mapping, escape_mode::raw); });
    rejects(2, [&] { parse_escape_mode("invalid"); });
    auto const repeated = result.mapping.secrets[0].sentinel + " " + result.mapping.secrets[0].sentinel;
    require(restore(repeated, result.mapping, escape_mode::raw) == "alice@example alice@example");
    auto document = boost::json::parse(write_map(result.mapping));
    for (auto const field : {"format", "version", "run_id", "sentinel_prefix", "source", "secrets"})
    {
        auto invalid = document;
        invalid.as_object().erase(field);
        rejects(5, [&] { read_map(boost::json::serialize(invalid)); });
    }
    auto invalid = document;
    invalid.as_object()["secrets"].as_array().push_back(invalid.as_object()["secrets"].as_array()[0]);
    rejects(5, [&] { read_map(boost::json::serialize(invalid)); });
    invalid = document;
    invalid.as_object()["version"] = 2;
    rejects(5, [&] { read_map(boost::json::serialize(invalid)); });
    invalid = document;
    invalid.as_object()["secrets"].as_array()[0].as_object()["original"] = "JSTS_SECRET_v1_x";
    rejects(5, [&] { read_map(boost::json::serialize(invalid)); });
    rejects(5, [&] { read_map("{\"version\":1,\"version\":2}"); });
    rejects(5, [&] { read_map("{\"version\":1,\"\\u0076ersion\":2}"); });
    rejects(5, [&] { read_map("{malformed"); });
    // Replacement expansion must stay bounded even for repeated sentinels.
    auto large = empty.mapping;
    large.secrets[0].original.assign(1024 * 1024, 'x');
    std::string many;
    for (unsigned i = 0; i < 65; ++i) many += large.secrets[0].sentinel + " ";
    rejects(6, [&] { restore(many, large, escape_mode::raw); });
}
} // namespace
int main()
{
    try
    {
        tests();
    }
    catch (std::exception const&)
    {
        std::cerr << "ubqt-redact test failed\n";
        return 1;
    }
    std::cout << "ubqt-redact tests passed\n";
}
