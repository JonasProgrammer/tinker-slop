# JS TinkerSlop

JS TinkerSlop is a collection of independent small C++ tools. Each tool lives in
its own subdirectory and can be enabled or disabled separately at configure time.

## Requirements

- CMake 4.4 or newer
- Clang 22 or newer
- A C++26 standard library

## Build

Configure and build all tools that are enabled by default:

```sh
cmake -S . -B build
cmake --build build
```

Each tool has a `JSTS_BUILD_<TOOL>` CMake option that defaults to `ON`. Pass an
option at configure time to omit a tool:

```sh
cmake -S . -B build -DJSTS_BUILD_<TOOL>=OFF
```

Dependency versions and general dependency preferences are inherited by tools
that use them. Advanced `JSTS_<TOOL>_<SETTING>` options can override a preference
for one tool without changing the others.

## Tools

No tools have been added yet.

When adding a tool, give it a subdirectory and a README, then add a link to that
README in this section.
