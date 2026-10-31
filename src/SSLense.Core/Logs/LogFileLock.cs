using System.Security.AccessControl;
using System.Security.Principal;

namespace SSLense.Core.Logs;

/// <summary>
/// One machine-wide lock around writes to the shared log file and around clearing it. Serilog's own lock for shared files
/// is per Windows session, and the service runs in a different session from the GUI and CLI, so it cannot keep an entry
/// from being written between Clear log reading the file and emptying it. Every SSLense process takes this lock instead.
/// </summary>
public static class LogFileLock
{
    // Global\ so the service (session 0) and the GUI and CLI (the administrator's session) share one lock.
    private const string Name = @"Global\SSLense.LogFile";

    // Opened once per process; ownership is per thread, so one handle serves every thread.
    private static readonly Lazy<Mutex?> Shared = new(Open, LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>Runs <paramref name="action"/> while holding the lock, or without it after <paramref name="timeout"/>.</summary>
    /// <returns>Whether the lock was held.</returns>
    public static bool Run(Action action, TimeSpan timeout)
    {
        ArgumentNullException.ThrowIfNull(action);
        var mutex = Shared.Value;
        var held = mutex is not null && Wait(mutex, timeout);
        try
        {
            action();
        }
        finally
        {
            if (held) mutex!.ReleaseMutex();
        }

        return held;
    }

    /// <summary>Holds the lock for an asynchronous operation; throws when it cannot be taken within <paramref name="timeout"/>.</summary>
    public static async Task<T> RunExclusiveAsync<T>(Func<Task<T>> operation, TimeSpan timeout)
    {
        ArgumentNullException.ThrowIfNull(operation);
        // A mutex belongs to the thread that took it, so the whole operation runs on one dedicated thread.
        return await Task.Factory.StartNew(
                () =>
                {
                    var mutex = Shared.Value
                        ?? throw new InvalidOperationException("The SSLense log lock is not available to this account.");
                    if (!Wait(mutex, timeout))
                    {
                        throw new TimeoutException("Another SSLense process is writing to the log. Try again in a moment.");
                    }

                    try
                    {
                        return operation().GetAwaiter().GetResult();
                    }
                    finally
                    {
                        mutex.ReleaseMutex();
                    }
                },
                CancellationToken.None,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default)
            .ConfigureAwait(false);
    }

    private static Mutex? Open()
    {
        try
        {
            // Administrators and SYSTEM only, like the data folder: the service creates it as SYSTEM, the GUI and CLI
            // open it as elevated administrators.
            var security = new MutexSecurity();
            foreach (var sid in new[] { WellKnownSidType.BuiltinAdministratorsSid, WellKnownSidType.LocalSystemSid })
            {
                security.AddAccessRule(new MutexAccessRule(new SecurityIdentifier(sid, null), MutexRights.FullControl, AccessControlType.Allow));
            }

            return MutexAcl.Create(initiallyOwned: false, Name, out _, security);
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or WaitHandleCannotBeOpenedException or IOException)
        {
            // Logging must never fail because of the lock.
            return null;
        }
    }

    private static bool Wait(Mutex mutex, TimeSpan timeout)
    {
        try
        {
            return mutex.WaitOne(timeout);
        }
        catch (AbandonedMutexException)
        {
            // A process ended while holding it; the lock is now ours.
            return true;
        }
    }
}
