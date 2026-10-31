using System.IO;
using Serilog;
using Serilog.Configuration;
using Serilog.Core;
using Serilog.Events;
using SSLense.Core.Config;
using SSLense.Core.Logs;

namespace SSLense;

/// <summary>
/// The shared daily log file that the GUI, CLI, and service all write to. Linked into each app so they cannot drift apart.
/// </summary>
internal static class LogFileConfiguration
{
    // Short, so a stuck process can delay logging only briefly; after it, the entry is written without the lock.
    private static readonly TimeSpan LockTimeout = TimeSpan.FromSeconds(5);

    public static LoggerConfiguration SSLenseLogFile(this LoggerSinkConfiguration writeTo)
    {
        var file = new LoggerConfiguration()
            .MinimumLevel.Verbose()
            .WriteTo.File(
                Path.Combine(AppPaths.LogDirectory, "sslense-.log"),
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 30,
                shared: true)
            .CreateLogger();
        return writeTo.Sink(new LockedSink(file));
    }

    /// <summary>Writes each entry under <see cref="LogFileLock"/>, so Clear log never discards one written meanwhile.</summary>
    private sealed class LockedSink(Logger file) : ILogEventSink, IDisposable
    {
        public void Emit(LogEvent logEvent) => LogFileLock.Run(() => file.Write(logEvent), LockTimeout);

        public void Dispose() => file.Dispose();
    }
}
