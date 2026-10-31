# Contributing to SSLense

Thanks for helping. Bug reports, documentation fixes, tests, and code are all welcome.

## Before you start

- **Security problems:** do not open a public issue; follow [SECURITY.md](SECURITY.md).
- **Larger changes:** open an issue first to agree on the approach, especially for anything touching renewal, IIS bindings, the certificate store, or secrets.
- Read [PROJECT_SPEC.md](PROJECT_SPEC.md) and [ROADMAP.md](ROADMAP.md) for the design and priorities.

## Your first contribution

1. Pick an issue labelled [good first issue](https://github.com/panchalvimaldev/sslense/labels/good%20first%20issue), or ask in [Discussions](https://github.com/panchalvimaldev/sslense/discussions) if you are unsure where to start. Comment on the issue so nobody else takes it at the same time.
2. Fork the repository, create a branch, and make the change with a test.
3. Run `dotnet build` and `dotnet test` (below), then open a pull request that says what changed and how you checked it.

You do not need an IIS server to contribute. The test suite needs only Windows and the .NET 10 SDK. It runs without Administrator rights, uses mocks, an in-memory file system and a throwaway test certificate authority, and never changes IIS or contacts Let's Encrypt. An IIS machine is only needed to try a change by hand.

### Where things are

| Folder | What it contains |
|---|---|
| `src/SSLense.Core` | All behaviour. `Acme` (Let's Encrypt and other CAs), `Certificates` (store, imports, validation), `Iis` (sites and bindings), `Renewal`, `Reminders`, `Notifications`, `Diagnostics` (health check and bundles), `Config` (settings and state files) |
| `src/SSLense.Gui` | The WPF desktop app: `Views` (XAML) and `ViewModels`, which only call Core |
| `src/SSLense.Cli` | The command line (`Program.cs`), also only calling Core |
| `src/SSLense.Service` | The Windows service that runs renewals and reminders every hour |
| `tests/SSLense.Tests` | xUnit tests, organised like `src/SSLense.Core` |
| `installer` | The WiX MSI |
| `site` | The website, sslense.com |
| `docs/design` | Design documents for larger features |

## Building and testing

Requirements: Windows, the .NET 10 SDK (see `global.json`), and IIS with *IIS Management Scripts and Tools* for manual testing.

```powershell
dotnet build .\SSLense.sln
dotnet test .\SSLense.sln
```

Both must pass with no warnings; warnings are treated as errors. Building the MSI is optional and described in the README.

## Ground rules

- **Use Let's Encrypt staging only.** Never run tests or experiments against the production endpoint. Production rate limits are shared and easy to exhaust.
- **Keep the GUI and CLI thin.** Business logic belongs in `SSLense.Core`, behind interfaces that tests can mock. Every operation should work identically from the GUI and the CLI.
- **Never log secrets:** private keys, PFX passwords, ACME account keys, SMTP passwords, or webhook URLs.
- **Never leave a site without a working binding.** Changes to issuance, renewal, or binding code must preserve the existing certificate until the replacement is verified, and need tests for the failure paths.
- **Add tests** for new behaviour and for every bug fix.
- **Dependencies:** discuss new NuGet packages in an issue first. They must use a license compatible with Apache-2.0.
- Match the surrounding code's style, naming, and comment density.

## Sign your commits (DCO)

SSLense uses the [Developer Certificate of Origin](https://developercertificate.org/). By adding a `Signed-off-by` line to each commit, you certify that you wrote the change or have the right to submit it under the project's license:

```powershell
git commit -s -m "Describe the change"
```

This adds `Signed-off-by: Your Name <your.email@example.com>`, using your Git name and email.

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
