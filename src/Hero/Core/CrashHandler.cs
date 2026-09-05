namespace Hero.Core;

/// <summary>
/// The last thing HERO does before it stops working, in both halves of the product.
///
/// NOTHING WAS INSTALLED ANYWHERE. No DispatcherUnhandledException, no
/// AppDomain.UnhandledException, no TaskScheduler.UnobservedTaskException — a repo-wide grep for
/// all three returned nothing. For a tray-resident security tool whose failure mode is "silently
/// stops watching", that is the worst possible gap: an unhandled exception on the UI thread ended
/// the process with a Windows crash dialog, and the log file that exists precisely to hold that
/// answer recorded nothing at all. The user's evidence that HERO stopped protecting them was an
/// icon that was no longer in the tray.
///
/// Three surfaces, three different meanings, and they are not interchangeable:
///
///   * <b>Dispatcher</b> — a WPF UI callback threw. The guardian runs on background threads and is
///     unaffected, so the honest response is to log it and keep watching rather than take down a
///     security tool because a page failed to render. Handled, deliberately.
///   * <b>AppDomain</b> — terminal by definition. The process is going down whatever this does, so
///     the only job is to get the reason written before it does.
///   * <b>UnobservedTaskException</b> — a faulted Task nobody awaited. Since .NET 4.5 this does not
///     end the process, which is exactly why it matters: these are the failures that vanish
///     completely, and HERO runs a great deal of work on detached tasks.
/// </summary>
internal static class CrashHandler
{
    private static int _installed;

    /// <summary>
    /// Where this process writes. The service and the interactive app keep separate logs, and the
    /// service's is the one protected from the signed-in user.
    /// </summary>
    private static Action<string>? _write;

    /// <summary>
    /// Installs the handlers. Safe to call more than once; only the first call takes effect.
    /// </summary>
    /// <param name="write">The sink for the report — ServiceLog.Write or a user-log writer.</param>
    internal static void Install(Action<string> write)
    {
        if (Interlocked.Exchange(ref _installed, 1) != 0) return;
        _write = write;

        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
        {
            // IsTerminating is false only in rare hosted scenarios; say which it was, because
            // "HERO logged this and carried on" and "HERO logged this and died" are very
            // different things to read six hours later.
            Report(e.IsTerminating ? "FATAL" : "unhandled", e.ExceptionObject as Exception);
        };

        TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            Report("unobserved task", e.Exception);

            // Marks it handled so the default policy cannot escalate. The report above is the
            // point: without it these failures leave no trace whatsoever.
            e.SetObserved();
        };
    }

    /// <summary>
    /// Adds the WPF dispatcher handler. Separate from <see cref="Install"/> because the service has
    /// no dispatcher, and calling this there would be a lie about what the process does.
    /// </summary>
    internal static void InstallDispatcher(System.Windows.Application app)
    {
        app.DispatcherUnhandledException += (_, e) =>
        {
            Report("UI thread", e.Exception);

            // KEPT ALIVE ON PURPOSE. The guardian polls, scores and responds on background
            // threads; none of that is affected by a XAML binding or a page constructor throwing.
            // Ending the process would convert a cosmetic failure into a protection failure, which
            // is the trade this product exists to argue against.
            e.Handled = true;
        };
    }

    private static void Report(string kind, Exception? ex)
    {
        try
        {
            _write?.Invoke($"*** UNHANDLED EXCEPTION ({kind}) ***" + Environment.NewLine + Describe(ex));
        }
        catch
        {
            // The reporter itself failing is the one case with nowhere left to report to.
        }
    }

    /// <summary>
    /// Renders an exception with the detail that makes a report worth having.
    ///
    /// UNWRAPPED, because the wrapper is never the interesting part. An unobserved task arrives as
    /// an AggregateException whose own StackTrace is null and whose Message is a paragraph of
    /// boilerplate about the finalizer thread — measured, the first version of this logged exactly
    /// that plus "(no stack trace)", which says a failure happened and nothing about where. The
    /// frames are in the inner exceptions, and so is the type worth reading.
    /// </summary>
    private static string Describe(Exception? ex)
    {
        if (ex is null) return "  (no exception object)";

        var text = new System.Text.StringBuilder();

        void One(Exception e, int depth)
        {
            string indent = new(' ', 2 + depth * 2);
            text.Append(indent).Append(depth > 0 ? "caused by " : "").Append(e.GetType().FullName)
                .Append(": ").AppendLine(e.Message);

            if (!string.IsNullOrWhiteSpace(e.StackTrace)) text.AppendLine(e.StackTrace);

            // Flattened rather than recursed blindly: an AggregateException can hold several, and
            // a nested one holds several more.
            if (e is AggregateException aggregate)
            {
                foreach (var inner in aggregate.Flatten().InnerExceptions) One(inner, depth + 1);
            }
            else if (e.InnerException is { } inner)
            {
                One(inner, depth + 1);
            }
        }

        One(ex, 0);
        return text.ToString().TrimEnd();
    }
}
