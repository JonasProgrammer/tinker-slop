# Agent instructions

## Scope

This repository contains independent, small C++ tools. Keep every tool isolated in
its own subdirectory, with its own `CMakeLists.txt` and `README.md`. Do not couple
tools through source files, targets, or dependencies unless the shared component
is deliberately introduced as a library.

Before making changes, read `AGENTS-local.md` when it exists. It contains
per-machine or per-developer instructions and is intentionally not committed.

Keep the root `README.md` tool index current. Every tool README must be reachable
through a link from the root README.

## CMake

- Use `JSTS` (JS TinkerSlop) as the prefix for project-owned CMake cache options
  and variables.
- Guard every tool with a root option that defaults to `ON`. Normalize the tool
  name to uppercase with underscores, for example:

  ```cmake
  option(JSTS_BUILD_HEXDUMP "Build the hexdump tool" ON)
  if(JSTS_BUILD_HEXDUMP)
      add_subdirectory(hexdump)
  endif()
  ```

- Discover and consume libraries in the subdirectory of each tool that needs
  them. Do not make an optional tool's dependencies a project-wide requirement.
- Define minimum dependency versions at an inherited scope with names such as
  `JSTS_BOOST_MIN`. Use the inherited value in each relevant `find_package` call.
- Define a general dependency setting as a `JSTS_<SETTING>` option. Give each
  tool an advanced `JSTS_<TOOL>_<SETTING>` option whose initial value is the
  inherited setting. Apply the resolved value only while configuring that tool.
  For example:

  ```cmake
  option(JSTS_BOOST_USE_STATIC_LIBS "Prefer static Boost libraries" OFF)

  option(
      JSTS_HEXDUMP_BOOST_USE_STATIC_LIBS
      "Prefer static Boost libraries for hexdump"
      "${JSTS_BOOST_USE_STATIC_LIBS}"
  )
  mark_as_advanced(JSTS_HEXDUMP_BOOST_USE_STATIC_LIBS)

  set(Boost_USE_STATIC_LIBS "${JSTS_HEXDUMP_BOOST_USE_STATIC_LIBS}")
  find_package(Boost ${JSTS_BOOST_MIN} REQUIRED COMPONENTS program_options)
  ```

- Do not force user cache values.
- Require C++26 and disable compiler extensions. Clang 22 is the minimum
  supported compiler and language-feature baseline. Do not require a newer
  compiler or a post-Clang-22 extension without an explicit project decision.
- Express usage requirements on targets. Avoid directory-wide compile options,
  include directories, definitions, or link settings when a target-scoped form
  exists.

## C++

- Use the `.cpp` extension for all C++ translation units, including module
  interface units. Do not use `.cppm`.
- Prefer C++ modules for project interfaces. Use classic headers when required
  by a dependency, toolchain limitation, or a clearly documented compatibility
  need.
- Write portable C++. Do not call platform APIs such as `Windows.h` or POSIX APIs
  directly unless the task explicitly permits platform-specific code. Put a
  library abstraction between project code and platform facilities.
- Preserve strict-aliasing guarantees. Do not type-pun through pointers or
  references. Use facilities such as `std::bit_cast` or `std::memcpy` when
  representation conversion is required.
- Represent untyped raw data with `std::byte`. Use character types for text and
  their other language-defined purposes, not as a general byte type.
- Little-endian data is the project assumption. Any code whose result depends on
  native byte order must reject other byte orders at compile time, close to the
  affected code, for example:

  ```cpp
  static_assert(std::endian::native == std::endian::little,
                "this code requires little-endian byte order");
  ```

- Treat every external input as malicious. Validate structure, ranges, lengths,
  encodings, and paths before use. Check arithmetic before allocating, indexing,
  narrowing, or advancing an iterator. Bound memory, recursion, and other
  attacker-controlled work. Reject malformed or ambiguous input with a useful
  error instead of relying on undefined behavior or assertions.

## Style and documentation

- Format changed C++ and module sources with the repository `.clang-format`
  before committing.
- Names in C++ should be snake_case.
- Keep source code and comments outside string literals ASCII-only.
- Keep README files and other prose documentation ASCII-only.
- Keep comments terse. State intent, constraints, or a non-obvious reason; do not
  narrate the code.
- Update a tool's README when its interface, dependencies, build options, or
  behavior changes. Add or update its root README link in the same change.

## Verification

- Configure and build every enabled tool with Clang 22 or newer.
- Exercise the tests relevant to the changed tool. Include malformed and boundary
  inputs when parsing or other input handling changes.
- Keep tools independently configurable: disabling one tool must remove its
  dependency requirements without breaking the remaining configuration.

## Commits

- Use Conventional Commits. The subject states the intent of the change instead
  of listing file-by-file edits, for example `feat(hex): reject truncated input`.
- Add an `Assisted-By: Codex` trailer to every commit created by an agent.
