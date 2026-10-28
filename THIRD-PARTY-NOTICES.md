# Third-party notices

SSLense includes or is built with the components below. Each is used under its own license; their copyright notices and license texts are available from the linked projects. This list covers the components shipped in the SSLense MSI and binaries, including indirect dependencies of the packages listed.

| Component | License | Project |
|---|---|---|
| .NET runtime and Windows Desktop runtime (bundled in self-contained builds) | MIT | <https://github.com/dotnet/runtime>, <https://github.com/dotnet/wpf> |
| Microsoft.Extensions.* (Hosting, Configuration, DependencyInjection, Logging, Options, and related packages) | MIT | <https://github.com/dotnet/runtime> |
| System.CommandLine | MIT | <https://github.com/dotnet/command-line-api> |
| System.Diagnostics.EventLog, System.ServiceProcess.ServiceController | MIT | <https://github.com/dotnet/runtime> |
| CommunityToolkit.Mvvm | MIT | <https://github.com/CommunityToolkit/dotnet> |
| Certes | MIT | <https://github.com/fszlin/certes> |
| BouncyCastle.Cryptography | MIT | <https://github.com/bcgit/bc-csharp> |
| MailKit, MimeKit | MIT | <https://github.com/jstedfast/MailKit> |
| Serilog, Serilog.Extensions.Hosting, Serilog.Extensions.Logging, Serilog.Sinks.Console, Serilog.Sinks.File | Apache-2.0 | <https://github.com/serilog/serilog> |
| Microsoft.Web.Administration | Microsoft .NET Library License | <https://www.nuget.org/packages/Microsoft.Web.Administration> |
| WiX Toolset custom actions embedded in the MSI (WixToolset.Util.wixext) | MS-RL | <https://github.com/wixtoolset/wix> |

## Notes

- **Microsoft.Web.Administration** is distributed by Microsoft under its proprietary .NET Library license, not an open-source license. The license link in the package metadata no longer resolves, so its exact current terms have not been re-verified for this release. It is redistributed unmodified as part of SSLense, as other open-source IIS tools do. It is the only component not under an OSI-approved license.
- **WiX Toolset** builds the MSI. Its build tools are used under the WiX Open Source Maintenance Fee EULA; the custom-action code embedded in the MSI is licensed under the Microsoft Reciprocal License (MS-RL), and its source is available from the WiX project.
- Test-only dependencies (xUnit, Moq, Microsoft.NET.Test.Sdk) are not distributed.
