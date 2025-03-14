# Contributing to phantom-screen

Thank you for your interest in contributing! phantom-screen is a research toolkit, and we welcome contributions that advance the understanding of Windows display pipeline security.

## Getting Started

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run tests: `ctest --test-dir build`
5. Submit a pull request

## Development Setup

### Prerequisites
- Windows 10/11
- Visual Studio 2019+ or MSVC Build Tools
- CMake 3.16+
- Windows SDK 10.0.19041.0+

### Building
```bash
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Debug
```

### Running Tests
```bash
ctest --test-dir build --config Debug --output-on-failure
```

## Code Style

- C++17 standard
- 4-space indentation
- `snake_case` for functions and variables
- `PascalCase` for class names
- `UPPER_CASE` for macros and constants
- Namespace: `phantom::<module>`

## What We Accept

- **Bug fixes** with clear description and test case
- **New bypass techniques** with documentation of the underlying mechanism
- **Detection improvements** for additional capture software
- **Performance improvements** with benchmarks
- **Documentation** improvements
- **Test coverage** improvements

## What We Don't Accept

- Code that targets specific anti-cheat systems by name
- Code designed primarily for malicious use
- Dependencies on external libraries (we keep this dependency-free)
- Changes that break the Windows SDK-only build

## Pull Request Process

1. Update documentation for any new features
2. Add tests for new functionality
3. Ensure CI passes
4. Request review from a maintainer

## Code of Conduct

Be respectful. This is a research project. We expect all contributors to:
- Be constructive in discussions
- Focus on technical merit
- Respect differing opinions
- Follow responsible disclosure practices

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
