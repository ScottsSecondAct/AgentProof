using System.Reflection;
using System.Runtime.InteropServices;

namespace AutomaGuard;

/// <summary>
/// Registers a <see cref="NativeLibrary.SetDllImportResolver"/> callback so
/// that the <c>aegis</c> native library is loaded from the per-platform
/// <c>runtimes/&lt;rid&gt;/native/</c> sub-directory bundled with the NuGet
/// package, before falling back to the default OS search path.
/// </summary>
internal static class NativeLibraryLoader
{
    private static readonly object _lock = new();
    private static bool _registered;

    /// <summary>
    /// Ensure the resolver is registered. Safe to call multiple times.
    /// </summary>
    internal static void EnsureRegistered()
    {
        if (_registered) return;
        lock (_lock)
        {
            if (_registered) return;
            NativeLibrary.SetDllImportResolver(
                typeof(NativeLibraryLoader).Assembly,
                Resolve);
            _registered = true;
        }
    }

    private static IntPtr Resolve(
        string libraryName,
        Assembly assembly,
        DllImportSearchPath? searchPath)
    {
        if (libraryName != NativeMethods.LibName)
            return IntPtr.Zero;

        string? platformDir = GetPlatformDirectory();
        if (platformDir is null)
            return IntPtr.Zero;

        // The assembly directory is the NuGet package layout root when published.
        string assemblyDir = Path.GetDirectoryName(assembly.Location) ?? AppContext.BaseDirectory;

        string[] candidates = BuildCandidatePaths(assemblyDir, platformDir);
        foreach (string path in candidates)
        {
            if (NativeLibrary.TryLoad(path, out IntPtr handle))
                return handle;
        }

        // Fall back to the default OS resolution (PATH / LD_LIBRARY_PATH / etc.)
        return IntPtr.Zero;
    }

    private static string[] BuildCandidatePaths(string assemblyDir, string platformDir)
    {
        string libFileName = GetLibraryFileName();

        return
        [
            // NuGet package layout: runtimes/<rid>/native/
            Path.Combine(assemblyDir, "runtimes", platformDir, "native", libFileName),
            // Development layout: native/<rid>/
            Path.Combine(assemblyDir, "..", "..", "native", platformDir, libFileName),
            // Same directory as the assembly (for single-file publish)
            Path.Combine(assemblyDir, libFileName),
        ];
    }

    private static string? GetPlatformDirectory()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            return RuntimeInformation.ProcessArchitecture switch
            {
                Architecture.X64  => "linux-x64",
                Architecture.Arm64 => "linux-arm64",
                _ => null,
            };
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return RuntimeInformation.ProcessArchitecture switch
            {
                Architecture.Arm64 => "osx-arm64",
                Architecture.X64  => "osx-x64",
                _ => null,
            };
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return RuntimeInformation.ProcessArchitecture switch
            {
                Architecture.X64 => "win-x64",
                _ => null,
            };
        }

        return null;
    }

    private static string GetLibraryFileName()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return "aegis.dll";
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            return "libaegis.dylib";
        return "libaegis.so";
    }
}
