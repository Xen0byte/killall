// killall — Windows 11 Native Process Termination Utility
// .NET 8 / C# 12 — Single-file console application
// Production-grade implementation with three-tier safety model

using System.ComponentModel;
using System.Diagnostics;
using System.Management;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace Killall;

// ============================================================
// Enums and Records
// ============================================================

internal enum SafetyTier { Immortal, AutoRestart, Allowed }
internal enum KillAction { Kill, Skip, Restart }

internal sealed record ProcessInfo(
    int Pid,
    int ParentPid,
    string Name,
    string? CommandLine,
    string? ExecutablePath);

internal sealed record KillRequest(
    List<ProcessTarget> Targets,
    bool KillTree,
    bool Force,
    bool DryRun,
    string Reason);

internal sealed record ProcessTarget(
    int Pid,
    string Name,
    SafetyTier Tier,
    KillAction Action,
    string? ExecutablePath,
    string? CommandLine);

// ============================================================
// Native Methods (P/Invoke)
// ============================================================

internal static class NativeMethods
{
    // ---- user32.dll ----

    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool IsHungAppWindow(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr SendMessageTimeout(
        IntPtr hWnd, uint Msg, UIntPtr wParam, IntPtr lParam,
        uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern int GetWindowTextLength(IntPtr hWnd);

    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    public const uint WM_NULL = 0x0000;
    public const uint SMTO_ABORTIFHUNG = 0x0002;

    // ---- iphlpapi.dll ----

    [DllImport("iphlpapi.dll", SetLastError = true)]
    public static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref int pdwSize, bool bOrder,
        int ulAf, TcpTableClass TableClass, uint Reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    public static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable, ref int pdwSize, bool bOrder,
        int ulAf, UdpTableClass TableClass, uint Reserved);

    public enum TcpTableClass
    {
        TCP_TABLE_OWNER_PID_ALL = 5
    }

    public enum UdpTableClass
    {
        UDP_TABLE_OWNER_PID = 1
    }

    public const int AF_INET = 2;
    public const int AF_INET6 = 23;
    public const uint NO_ERROR = 0;
    public const uint ERROR_INSUFFICIENT_BUFFER = 122;

    public enum TcpState
    {
        Closed = 1,
        Listen = 2,
        SynSent = 3,
        SynRcvd = 4,
        Established = 5,
        FinWait1 = 6,
        FinWait2 = 7,
        CloseWait = 8,
        Closing = 9,
        LastAck = 10,
        TimeWait = 11,
        DeleteTcb = 12
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_UDPROW_OWNER_PID
    {
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwOwningPid;
    }
}

// ============================================================
// Console Output Helpers
// ============================================================

internal static class Output
{
    public static void Success(string msg)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine(msg);
        Console.ResetColor();
    }

    public static void Warning(string msg)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine(msg);
        Console.ResetColor();
    }

    public static void Error(string msg)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine(msg);
        Console.ResetColor();
    }

    public static void Info(string msg)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(msg);
        Console.ResetColor();
    }

    public static void Muted(string msg)
    {
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine(msg);
        Console.ResetColor();
    }

    public static void Table(string[] headers, List<string[]> rows)
    {
        if (rows.Count == 0) return;

        var widths = new int[headers.Length];
        for (int i = 0; i < headers.Length; i++)
            widths[i] = headers[i].Length;

        foreach (var row in rows)
            for (int i = 0; i < Math.Min(row.Length, widths.Length); i++)
                widths[i] = Math.Max(widths[i], (row[i] ?? "").Length);

        // Header
        Console.ForegroundColor = ConsoleColor.White;
        for (int i = 0; i < headers.Length; i++)
            Console.Write(headers[i].PadRight(widths[i] + 2));
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        for (int i = 0; i < headers.Length; i++)
            Console.Write(new string('─', widths[i]) + "  ");
        Console.WriteLine();
        Console.ResetColor();

        // Rows
        foreach (var row in rows)
        {
            for (int i = 0; i < headers.Length; i++)
            {
                string val = i < row.Length ? (row[i] ?? "") : "";
                Console.Write(val.PadRight(widths[i] + 2));
            }
            Console.WriteLine();
        }
    }

    public static bool Confirm(string prompt)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write($"{prompt} [y/N] ");
        Console.ResetColor();
        var key = Console.ReadLine()?.Trim().ToLowerInvariant();
        return key == "y" || key == "yes";
    }
}

// ============================================================
// Safety Service — Three-Tier Protection
// ============================================================

internal static class SafetyService
{
    private static readonly HashSet<string> ImmortalProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Idle", "System Idle Process", "smss", "csrss", "wininit",
        "services", "lsass", "winlogon", "svchost", "dwm", "fontdrvhost",
        "lsaiso", "MsMpEng", "Registry", "Memory Compression", "MemCompression",
        "conhost", "SecurityHealthService", "NtosKrnl", "Kernel32",
        "WmiPrvSE", "spoolsv", "wlanext", "WUDFHost",
        "Secure System", "ntoskrnl"
    };

    private static readonly HashSet<string> AutoRestartProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer", "ShellExperienceHost", "StartMenuExperienceHost",
        "SearchHost", "SearchApp", "RuntimeBroker", "Taskmgr",
        "ApplicationFrameHost", "Widgets", "WidgetService",
        "TextInputHost", "SystemSettings"
    };

    public static SafetyTier Classify(string processName)
    {
        // Strip .exe suffix for matching
        string name = processName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? processName[..^4]
            : processName;

        if (ImmortalProcesses.Contains(name))
            return SafetyTier.Immortal;

        if (AutoRestartProcesses.Contains(name))
            return SafetyTier.AutoRestart;

        return SafetyTier.Allowed;
    }

    public static KillAction GetAction(SafetyTier tier) => tier switch
    {
        SafetyTier.Immortal => KillAction.Skip,
        SafetyTier.AutoRestart => KillAction.Restart,
        _ => KillAction.Kill
    };

    public static async Task RelaunchProcess(ProcessTarget target)
    {
        string name = target.Name.ToLowerInvariant().Replace(".exe", "");

        if (name == "explorer")
        {
            await RelaunchExplorer();
            return;
        }

        // Many Tier 2 processes auto-restart via Windows infrastructure.
        // Give Windows 3 seconds to restart them automatically.
        await Task.Delay(3000);

        // Verify if the process has restarted
        var running = Process.GetProcessesByName(target.Name.Replace(".exe", ""));
        if (running.Length > 0)
        {
            Output.Success($"  [ RESTARTED ] {target.Name} (PID {running[0].Id}) — auto-restarted by Windows");
            return;
        }

        // Attempt manual restart if we have the executable path
        if (!string.IsNullOrEmpty(target.ExecutablePath) && File.Exists(target.ExecutablePath))
        {
            try
            {
                var psi = new ProcessStartInfo(target.ExecutablePath)
                {
                    UseShellExecute = true,
                    WorkingDirectory = Path.GetDirectoryName(target.ExecutablePath) ?? ""
                };
                Process.Start(psi);
                Output.Success($"  [ RESTARTED ] {target.Name} — manually relaunched from {target.ExecutablePath}");
            }
            catch (Exception ex)
            {
                Output.Error($"  [ FAILED ] Could not restart {target.Name}: {ex.Message}");
            }
        }
        else
        {
            Output.Warning($"  [ WARN ] {target.Name} did not auto-restart and no executable path is available.");
        }
    }

    private static async Task RelaunchExplorer()
    {
        // Explorer requires special handling with retry logic
        for (int attempt = 1; attempt <= 3; attempt++)
        {
            try
            {
                var psi = new ProcessStartInfo("explorer.exe")
                {
                    UseShellExecute = true
                };
                Process.Start(psi);
                await Task.Delay(2000);

                var running = Process.GetProcessesByName("explorer");
                if (running.Length > 0)
                {
                    Output.Success($"  [ RESTARTED ] explorer.exe (PID {running[0].Id}) — attempt {attempt}");
                    return;
                }
            }
            catch (Exception ex)
            {
                Output.Warning($"  Explorer restart attempt {attempt} failed: {ex.Message}");
            }

            if (attempt < 3)
            {
                Output.Muted($"  Retrying explorer restart ({attempt + 1}/3)...");
                await Task.Delay(2000);
            }
        }

        Output.Error("  [ FAILED ] explorer.exe could not be restarted after 3 attempts.");
        Output.Warning("  You may need to restart explorer manually: press Ctrl+Shift+Esc → File → Run → explorer.exe");
    }
}

// ============================================================
// Process Tree Service
// ============================================================

internal static class ProcessTreeService
{
    private static Dictionary<int, ProcessInfo>? _processMap;
    private static Dictionary<int, List<int>>? _childMap;

    public static void BuildProcessTree()
    {
        _processMap = new Dictionary<int, ProcessInfo>();
        _childMap = new Dictionary<int, List<int>>();

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath FROM Win32_Process");

            foreach (ManagementObject obj in searcher.Get())
            {
                int pid = Convert.ToInt32(obj["ProcessId"]);
                int ppid = Convert.ToInt32(obj["ParentProcessId"]);
                string name = obj["Name"]?.ToString() ?? "";
                string? cmdLine = obj["CommandLine"]?.ToString();
                string? exePath = obj["ExecutablePath"]?.ToString();

                _processMap[pid] = new ProcessInfo(pid, ppid, name, cmdLine, exePath);

                if (!_childMap.ContainsKey(ppid))
                    _childMap[ppid] = [];

                _childMap[ppid].Add(pid);
            }
        }
        catch (Exception ex)
        {
            Output.Error($"Failed to build process tree via WMI: {ex.Message}");
        }
    }

    public static List<int> GetDescendants(int pid)
    {
        if (_childMap is null) BuildProcessTree();

        var descendants = new List<int>();
        var queue = new Queue<int>();
        queue.Enqueue(pid);

        while (queue.Count > 0)
        {
            int current = queue.Dequeue();
            if (_childMap!.TryGetValue(current, out var children))
            {
                foreach (int child in children)
                {
                    descendants.Add(child);
                    queue.Enqueue(child);
                }
            }
        }

        return descendants;
    }

    public static ProcessInfo? GetProcessInfo(int pid)
    {
        if (_processMap is null) BuildProcessTree();
        return _processMap!.GetValueOrDefault(pid);
    }

    public static string? GetExecutablePath(int pid)
    {
        return GetProcessInfo(pid)?.ExecutablePath;
    }

    public static string? GetCommandLine(int pid)
    {
        return GetProcessInfo(pid)?.CommandLine;
    }

    public static void InvalidateCache()
    {
        _processMap = null;
        _childMap = null;
    }
}

// ============================================================
// Pattern Matcher
// ============================================================

internal static class PatternMatcher
{
    public static List<Process> FindMatching(string pattern)
    {
        var allProcesses = Process.GetProcesses();
        var matched = new List<Process>();

        // Determine match mode
        if (pattern.StartsWith('/') && pattern.EndsWith('/') && pattern.Length > 2)
        {
            // Regex mode: /pattern/
            string regexStr = pattern[1..^1];
            var regex = new Regex(regexStr, RegexOptions.IgnoreCase | RegexOptions.Compiled);
            foreach (var p in allProcesses)
            {
                if (regex.IsMatch(p.ProcessName))
                    matched.Add(p);
                else
                    p.Dispose();
            }
        }
        else if (pattern.Contains('*') || pattern.Contains('?'))
        {
            // Glob mode: convert to regex
            string regexStr = "^" + Regex.Escape(pattern).Replace("\\*", ".*").Replace("\\?", ".") + "$";
            var regex = new Regex(regexStr, RegexOptions.IgnoreCase | RegexOptions.Compiled);
            foreach (var p in allProcesses)
            {
                if (regex.IsMatch(p.ProcessName))
                    matched.Add(p);
                else
                    p.Dispose();
            }
        }
        else
        {
            // Try exact match first
            foreach (var p in allProcesses)
            {
                if (string.Equals(p.ProcessName, pattern, StringComparison.OrdinalIgnoreCase))
                    matched.Add(p);
            }

            // If no exact match, fall back to substring/partial match
            if (matched.Count == 0)
            {
                foreach (var p in allProcesses)
                {
                    if (p.ProcessName.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        matched.Add(p);
                    else
                        p.Dispose();
                }
            }
            else
            {
                // Dispose non-matched
                foreach (var p in allProcesses)
                {
                    if (!matched.Contains(p))
                        p.Dispose();
                }
            }
        }

        return matched;
    }

    public static bool IsMatch(string processName, string pattern)
    {
        if (pattern.StartsWith('/') && pattern.EndsWith('/') && pattern.Length > 2)
        {
            string regexStr = pattern[1..^1];
            return Regex.IsMatch(processName, regexStr, RegexOptions.IgnoreCase);
        }

        if (pattern.Contains('*') || pattern.Contains('?'))
        {
            string regexStr = "^" + Regex.Escape(pattern).Replace("\\*", ".*").Replace("\\?", ".") + "$";
            return Regex.IsMatch(processName, regexStr, RegexOptions.IgnoreCase);
        }

        return string.Equals(processName, pattern, StringComparison.OrdinalIgnoreCase)
            || processName.Contains(pattern, StringComparison.OrdinalIgnoreCase);
    }
}

// ============================================================
// Kill Command — Core Execution Engine
// ============================================================

internal static class KillCommand
{
    public static async Task<int> Execute(KillRequest request)
    {
        if (request.Targets.Count == 0)
        {
            Output.Warning("No processes matched.");
            return 3;
        }

        // Expand tree if requested
        var allTargets = new List<ProcessTarget>(request.Targets);
        if (request.KillTree)
        {
            ProcessTreeService.BuildProcessTree();
            var expanded = new List<ProcessTarget>();
            var seenPids = new HashSet<int>();

            foreach (var target in request.Targets)
            {
                if (seenPids.Add(target.Pid))
                    expanded.Add(target);

                var descendants = ProcessTreeService.GetDescendants(target.Pid);
                foreach (int childPid in descendants)
                {
                    if (!seenPids.Add(childPid)) continue;

                    try
                    {
                        var proc = Process.GetProcessById(childPid);
                        var tier = SafetyService.Classify(proc.ProcessName);
                        var info = ProcessTreeService.GetProcessInfo(childPid);
                        expanded.Add(new ProcessTarget(
                            childPid, proc.ProcessName, tier,
                            SafetyService.GetAction(tier),
                            info?.ExecutablePath, info?.CommandLine));
                    }
                    catch { /* process already exited */ }
                }
            }

            allTargets = expanded;
        }

        // Display summary
        Console.WriteLine();
        Output.Info($"  {request.Reason} — {allTargets.Count} process(es) targeted:");
        Console.WriteLine();

        var rows = new List<string[]>();
        foreach (var t in allTargets)
        {
            string action = t.Action switch
            {
                KillAction.Skip => "SKIP (Immortal)",
                KillAction.Restart => "KILL + RESTART",
                KillAction.Kill => "KILL",
                _ => "UNKNOWN"
            };
            rows.Add([t.Pid.ToString(), t.Name, t.Tier.ToString(), action]);
        }
        Output.Table(["PID", "Name", "Tier", "Action"], rows);
        Console.WriteLine();

        if (request.DryRun)
        {
            Output.Muted("  (Dry run — no processes were terminated)");
            return 0;
        }

        // Confirm unless forced
        if (!request.Force)
        {
            int killCount = allTargets.Count(t => t.Action != KillAction.Skip);
            if (!Output.Confirm($"Terminate {killCount} process(es)?"))
            {
                Output.Muted("  Aborted.");
                return 0;
            }
        }

        // Sort: kill children first (higher PID tends to be child, but use tree order)
        var toKill = allTargets.Where(t => t.Action != KillAction.Skip).ToList();
        var toRestart = new List<ProcessTarget>();
        int killed = 0;
        int failed = 0;
        int skipped = allTargets.Count(t => t.Action == KillAction.Skip);

        // Log skipped
        foreach (var t in allTargets.Where(t => t.Action == KillAction.Skip))
            Output.Warning($"  [ IMMORTAL ] Skipping {t.Name} (PID {t.Pid}) — protected system core");

        // Kill in reverse order (children first when tree mode)
        if (request.KillTree)
            toKill.Reverse();

        foreach (var target in toKill)
        {
            try
            {
                var proc = Process.GetProcessById(target.Pid);
                proc.Kill(entireProcessTree: false);
                await WaitForExitAsync(proc, 5000);

                if (target.Action == KillAction.Restart)
                {
                    Output.Success($"  [ KILLED ] {target.Name} (PID {target.Pid}) — will restart");
                    toRestart.Add(target);
                }
                else
                {
                    Output.Success($"  [ KILLED ] {target.Name} (PID {target.Pid})");
                }
                killed++;
            }
            catch (ArgumentException)
            {
                Output.Muted($"  [ GONE ] {target.Name} (PID {target.Pid}) — already exited");
                killed++;
            }
            catch (Win32Exception ex)
            {
                Output.Error($"  [ DENIED ] {target.Name} (PID {target.Pid}) — {ex.Message}");
                failed++;
            }
            catch (InvalidOperationException)
            {
                Output.Muted($"  [ GONE ] {target.Name} (PID {target.Pid}) — already exited");
                killed++;
            }
            catch (Exception ex)
            {
                Output.Error($"  [ ERROR ] {target.Name} (PID {target.Pid}) — {ex.Message}");
                failed++;
            }
        }

        // Restart Tier 2 processes
        foreach (var target in toRestart)
        {
            await SafetyService.RelaunchProcess(target);
        }

        // Summary
        Console.WriteLine();
        Output.Info($"  Summary: {killed} killed, {skipped} skipped (immortal), {failed} failed");

        if (failed > 0 && killed == 0) return 2;
        if (failed > 0) return 1;
        return 0;
    }

    private static async Task WaitForExitAsync(Process proc, int timeoutMs)
    {
        try
        {
            using var cts = new CancellationTokenSource(timeoutMs);
            await proc.WaitForExitAsync(cts.Token);
        }
        catch (OperationCanceledException) { }
        catch (InvalidOperationException) { }
    }

    public static List<ProcessTarget> BuildTargets(List<Process> processes)
    {
        var targets = new List<ProcessTarget>();
        ProcessTreeService.BuildProcessTree();

        foreach (var proc in processes)
        {
            try
            {
                var tier = SafetyService.Classify(proc.ProcessName);
                var info = ProcessTreeService.GetProcessInfo(proc.Id);
                targets.Add(new ProcessTarget(
                    proc.Id, proc.ProcessName, tier,
                    SafetyService.GetAction(tier),
                    info?.ExecutablePath, info?.CommandLine));
            }
            catch { /* process exited */ }
        }

        return targets;
    }
}

// ============================================================
// Argument Parser
// ============================================================

internal sealed class ArgParser
{
    private readonly string[] _args;
    public List<string> Positional { get; } = [];

    private readonly Dictionary<string, string?> _flags = new(StringComparer.OrdinalIgnoreCase);

    public ArgParser(string[] args)
    {
        _args = args;
        Parse();
    }

    private void Parse()
    {
        for (int i = 0; i < _args.Length; i++)
        {
            string arg = _args[i];

            if (arg.StartsWith("--") || (arg.StartsWith('-') && arg.Length == 2 && !char.IsDigit(arg[1])))
            {
                string key = arg.TrimStart('-').ToLowerInvariant();

                // Check if next arg is a value (not another flag)
                if (i + 1 < _args.Length && !_args[i + 1].StartsWith('-'))
                {
                    _flags[key] = _args[i + 1];
                    i++;
                }
                else
                {
                    _flags[key] = null;
                }
            }
            else
            {
                Positional.Add(arg);
            }
        }
    }

    public bool HasFlag(params string[] names)
        => names.Any(n => _flags.ContainsKey(n.TrimStart('-').ToLowerInvariant()));

    public string? GetValue(params string[] names)
    {
        foreach (var n in names)
        {
            string key = n.TrimStart('-').ToLowerInvariant();
            if (_flags.TryGetValue(key, out var val))
                return val;
        }
        return null;
    }

    public bool Force => HasFlag("force", "f");
    public bool DryRun => HasFlag("dry-run", "n");
    public bool Tree => HasFlag("tree", "t");
    public bool Help => HasFlag("help", "h", "?");

    public int GetInt(string name, int defaultValue)
    {
        var val = GetValue(name);
        return val != null && int.TryParse(val, out int result) ? result : defaultValue;
    }

    public double GetDouble(string name, double defaultValue)
    {
        var val = GetValue(name);
        return val != null && double.TryParse(val, out double result) ? result : defaultValue;
    }
}

// ============================================================
// Subcommand: Restart
// ============================================================

internal static class RestartCommand
{
    public static async Task<int> Run(string[] args)
    {
        var parser = new ArgParser(args);
        if (parser.Help || parser.Positional.Count == 0)
        {
            Console.WriteLine("Usage: killall restart <process_name> [--force]");
            Console.WriteLine("Forcefully kill and restart a process by name.");
            return 0;
        }

        string pattern = parser.Positional[0];
        var processes = PatternMatcher.FindMatching(pattern);

        if (processes.Count == 0)
        {
            Output.Warning($"No processes matching '{pattern}' found.");
            return 3;
        }

        // Capture exe paths before killing
        ProcessTreeService.BuildProcessTree();
        var restartInfos = new List<(string Name, string? ExePath, string? CmdLine)>();

        foreach (var proc in processes)
        {
            var info = ProcessTreeService.GetProcessInfo(proc.Id);
            restartInfos.Add((proc.ProcessName, info?.ExecutablePath, info?.CommandLine));
        }

        // Kill all instances
        var targets = KillCommand.BuildTargets(processes);
        var request = new KillRequest(targets, parser.Tree, parser.Force, parser.DryRun,
            $"Restart '{pattern}'");

        int result = await KillCommand.Execute(request);
        if (parser.DryRun) return result;

        // Wait for processes to fully exit
        await Task.Delay(1000);

        // Restart
        Console.WriteLine();
        Output.Info("  Restarting...");

        foreach (var (name, exePath, cmdLine) in restartInfos)
        {
            if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
            {
                Output.Warning($"  Cannot restart {name}: executable path not available.");
                continue;
            }

            try
            {
                var psi = new ProcessStartInfo(exePath)
                {
                    UseShellExecute = true,
                    WorkingDirectory = Path.GetDirectoryName(exePath) ?? ""
                };
                var started = Process.Start(psi);
                if (started != null)
                    Output.Success($"  [ STARTED ] {name} (PID {started.Id}) from {exePath}");
            }
            catch (Exception ex)
            {
                Output.Error($"  [ FAILED ] Could not restart {name}: {ex.Message}");
            }
        }

        return result;
    }
}

// ============================================================
// Subcommand: GPU
// ============================================================

internal static class GpuCommand
{
    public static async Task<int> Run(string[] args)
    {
        var parser = new ArgParser(args);
        if (parser.Help)
        {
            Console.WriteLine("Usage: killall gpu [--threshold <percent>] [--force] [--dry-run]");
            Console.WriteLine("Terminate all user-level processes currently using the GPU.");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  --threshold N  Minimum GPU utilization % to target (default: 1)");
            return 0;
        }

        double threshold = parser.GetDouble("threshold", 1.0);

        Output.Info("  Scanning for GPU-using processes...");

        var gpuPids = new Dictionary<int, double>();

        // Method 1: WMI GPU Performance Counters (Windows 10 1809+)
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT * FROM Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine");

            foreach (ManagementObject obj in searcher.Get())
            {
                string? instanceName = obj["Name"]?.ToString();
                if (instanceName is null) continue;

                var match = Regex.Match(instanceName, @"pid_(\d+)_");
                if (!match.Success) continue;

                int pid = int.Parse(match.Groups[1].Value);
                double utilization = Convert.ToDouble(obj["UtilizationPercentage"] ?? 0);

                if (gpuPids.ContainsKey(pid))
                    gpuPids[pid] += utilization;
                else
                    gpuPids[pid] = utilization;
            }
        }
        catch
        {
            Output.Warning("  GPU performance counters not available. Falling back to module detection.");
        }

        // Method 2: Fallback — detect processes that loaded GPU-related DLLs
        if (gpuPids.Count == 0)
        {
            gpuPids = DetectGpuByModules();
        }

        // Filter by threshold and exclude system processes
        var selfPid = Environment.ProcessId;
        var matchedProcesses = new List<Process>();

        foreach (var (pid, util) in gpuPids)
        {
            if (pid == selfPid || pid == 0) continue;
            if (util < threshold && gpuPids.Count > 0 && gpuPids.Values.Max() > 0) continue;

            try
            {
                var proc = Process.GetProcessById(pid);
                if (SafetyService.Classify(proc.ProcessName) != SafetyTier.Immortal)
                    matchedProcesses.Add(proc);
            }
            catch { /* process gone */ }
        }

        if (matchedProcesses.Count == 0)
        {
            Output.Warning("  No user-level GPU-using processes found above threshold.");
            return 3;
        }

        // Show GPU usage table
        Console.WriteLine();
        var rows = new List<string[]>();
        foreach (var proc in matchedProcesses)
        {
            double util = gpuPids.GetValueOrDefault(proc.Id);
            rows.Add([proc.Id.ToString(), proc.ProcessName, $"{util:F1}%"]);
        }
        Output.Table(["PID", "Name", "GPU %"], rows);

        var targets = KillCommand.BuildTargets(matchedProcesses);
        return await KillCommand.Execute(new KillRequest(targets, parser.Tree, parser.Force, parser.DryRun,
            "GPU-using processes"));
    }

    private static Dictionary<int, double> DetectGpuByModules()
    {
        var gpuDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "d3d11.dll", "d3d12.dll", "d3d9.dll", "dxgi.dll",
            "vulkan-1.dll", "nvapi64.dll", "amdxc64.dll",
            "nvcuda.dll", "cudart64_*.dll", "opencl.dll",
            "nvoglv64.dll", "atig6pxx.dll", "atiuxpag.dll"
        };

        var result = new Dictionary<int, double>();
        int selfPid = Environment.ProcessId;

        foreach (var proc in Process.GetProcesses())
        {
            if (proc.Id == selfPid || proc.Id == 0) continue;

            try
            {
                foreach (ProcessModule module in proc.Modules)
                {
                    string modName = module.ModuleName ?? "";
                    if (gpuDlls.Contains(modName) ||
                        gpuDlls.Any(d => d.Contains('*') &&
                            modName.StartsWith(d.Split('*')[0], StringComparison.OrdinalIgnoreCase)))
                    {
                        result[proc.Id] = 0; // Unknown utilization, mark as GPU-using
                        break;
                    }
                }
            }
            catch { /* access denied or 32/64 mismatch */ }
            finally { proc.Dispose(); }
        }

        return result;
    }
}

// ============================================================
// Subcommand: Network Apps
// ============================================================

internal static class NetworkAppsCommand
{
    public static async Task<int> Run(string[] args)
    {
        var parser = new ArgParser(args);
        if (parser.Help)
        {
            Console.WriteLine("Usage: killall networkapps [--force] [--dry-run]");
            Console.WriteLine("Terminate all user-level processes with active network connections.");
            return 0;
        }

        Output.Info("  Scanning for processes with active network connections...");

        var networkPids = new HashSet<int>();
        var connectionDetails = new Dictionary<int, List<string>>();

        // Get TCP connections
        GetTcpConnections(networkPids, connectionDetails);

        // Get UDP endpoints
        GetUdpEndpoints(networkPids, connectionDetails);

        // Filter to user-level processes
        int selfPid = Environment.ProcessId;
        var matchedProcesses = new List<Process>();

        foreach (int pid in networkPids)
        {
            if (pid == 0 || pid == 4 || pid == selfPid) continue;

            try
            {
                var proc = Process.GetProcessById(pid);
                if (SafetyService.Classify(proc.ProcessName) == SafetyTier.Immortal)
                {
                    proc.Dispose();
                    continue;
                }
                matchedProcesses.Add(proc);
            }
            catch { /* process gone */ }
        }

        if (matchedProcesses.Count == 0)
        {
            Output.Warning("  No user-level processes with network connections found.");
            return 3;
        }

        Console.WriteLine();
        var rows = new List<string[]>();
        foreach (var proc in matchedProcesses)
        {
            var conns = connectionDetails.GetValueOrDefault(proc.Id);
            string connStr = conns != null ? string.Join("; ", conns.Take(3)) : "";
            if (conns != null && conns.Count > 3) connStr += $" (+{conns.Count - 3} more)";
            rows.Add([proc.Id.ToString(), proc.ProcessName, connStr]);
        }
        Output.Table(["PID", "Name", "Connections"], rows);

        var targets = KillCommand.BuildTargets(matchedProcesses);
        return await KillCommand.Execute(new KillRequest(targets, parser.Tree, parser.Force, parser.DryRun,
            "Network-connected processes"));
    }

    private static void GetTcpConnections(HashSet<int> pids, Dictionary<int, List<string>> details)
    {
        foreach (int af in new[] { NativeMethods.AF_INET, NativeMethods.AF_INET6 })
        {
            int bufferSize = 0;
            uint ret = NativeMethods.GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true,
                af, NativeMethods.TcpTableClass.TCP_TABLE_OWNER_PID_ALL, 0);

            if (ret != NativeMethods.ERROR_INSUFFICIENT_BUFFER && ret != NativeMethods.NO_ERROR)
                continue;

            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
            try
            {
                ret = NativeMethods.GetExtendedTcpTable(buffer, ref bufferSize, true,
                    af, NativeMethods.TcpTableClass.TCP_TABLE_OWNER_PID_ALL, 0);

                if (ret != NativeMethods.NO_ERROR) continue;

                int numEntries = Marshal.ReadInt32(buffer);
                IntPtr rowPtr = buffer + 4;
                int rowSize = Marshal.SizeOf<NativeMethods.MIB_TCPROW_OWNER_PID>();

                if (af == NativeMethods.AF_INET)
                {
                    for (int i = 0; i < numEntries; i++)
                    {
                        var row = Marshal.PtrToStructure<NativeMethods.MIB_TCPROW_OWNER_PID>(rowPtr);
                        int pid = (int)row.dwOwningPid;
                        var state = (NativeMethods.TcpState)row.dwState;

                        if (state == NativeMethods.TcpState.Established)
                        {
                            pids.Add(pid);
                            if (!details.ContainsKey(pid))
                                details[pid] = [];

                            var localAddr = new IPAddress(row.dwLocalAddr);
                            int localPort = IPAddress.NetworkToHostOrder((short)(row.dwLocalPort & 0xFFFF));
                            var remoteAddr = new IPAddress(row.dwRemoteAddr);
                            int remotePort = IPAddress.NetworkToHostOrder((short)(row.dwRemotePort & 0xFFFF));

                            details[pid].Add($"TCP {localAddr}:{Math.Abs(localPort)}→{remoteAddr}:{Math.Abs(remotePort)}");
                        }

                        rowPtr += rowSize;
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    private static void GetUdpEndpoints(HashSet<int> pids, Dictionary<int, List<string>> details)
    {
        int bufferSize = 0;
        uint ret = NativeMethods.GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, true,
            NativeMethods.AF_INET, NativeMethods.UdpTableClass.UDP_TABLE_OWNER_PID, 0);

        if (ret != NativeMethods.ERROR_INSUFFICIENT_BUFFER && ret != NativeMethods.NO_ERROR)
            return;

        IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            ret = NativeMethods.GetExtendedUdpTable(buffer, ref bufferSize, true,
                NativeMethods.AF_INET, NativeMethods.UdpTableClass.UDP_TABLE_OWNER_PID, 0);

            if (ret != NativeMethods.NO_ERROR) return;

            int numEntries = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = buffer + 4;
            int rowSize = Marshal.SizeOf<NativeMethods.MIB_UDPROW_OWNER_PID>();

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<NativeMethods.MIB_UDPROW_OWNER_PID>(rowPtr);
                int pid = (int)row.dwOwningPid;

                if (pid != 0)
                {
                    pids.Add(pid);
                    if (!details.ContainsKey(pid))
                        details[pid] = [];

                    var localAddr = new IPAddress(row.dwLocalAddr);
                    int localPort = IPAddress.NetworkToHostOrder((short)(row.dwLocalPort & 0xFFFF));
                    details[pid].Add($"UDP {localAddr}:{Math.Abs(localPort)}");
                }

                rowPtr += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }
}

// ============================================================
// Subcommand: Hung
// ============================================================

internal static class HungCommand
{
    public static async Task<int> Run(string[] args)
    {
        var parser = new ArgParser(args);
        if (parser.Help)
        {
            Console.WriteLine("Usage: killall hung [--force] [--dry-run]");
            Console.WriteLine("Terminate all 'Not Responding' applications.");
            return 0;
        }

        Output.Info("  Scanning for hung (Not Responding) windows...");

        var hungPids = new HashSet<int>();

        // Method 1: EnumWindows + IsHungAppWindow
        NativeMethods.EnumWindows((hWnd, _) =>
        {
            if (!NativeMethods.IsWindowVisible(hWnd))
                return true;

            if (NativeMethods.IsHungAppWindow(hWnd))
            {
                NativeMethods.GetWindowThreadProcessId(hWnd, out uint pid);
                if (pid != 0)
                    hungPids.Add((int)pid);
            }
            else
            {
                // Method 2: SendMessageTimeout with SMTO_ABORTIFHUNG
                var result = NativeMethods.SendMessageTimeout(
                    hWnd, NativeMethods.WM_NULL, UIntPtr.Zero, IntPtr.Zero,
                    NativeMethods.SMTO_ABORTIFHUNG, 1000, out UIntPtr _);

                if (result == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == 0 || error == 1460) // ERROR_TIMEOUT
                    {
                        NativeMethods.GetWindowThreadProcessId(hWnd, out uint pid);
                        if (pid != 0)
                            hungPids.Add((int)pid);
                    }
                }
            }

            return true;
        }, IntPtr.Zero);

        // Also check MainWindowHandle for .NET-accessible processes
        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                if (proc.MainWindowHandle != IntPtr.Zero && !proc.Responding)
                    hungPids.Add(proc.Id);
            }
            catch { }
            finally { proc.Dispose(); }
        }

        int selfPid = Environment.ProcessId;
        hungPids.Remove(selfPid);

        var matchedProcesses = new List<Process>();
        foreach (int pid in hungPids)
        {
            try
            {
                var proc = Process.GetProcessById(pid);
                if (SafetyService.Classify(proc.ProcessName) != SafetyTier.Immortal)
                    matchedProcesses.Add(proc);
                else
                    proc.Dispose();
            }
            catch { /* gone */ }
        }

        if (matchedProcesses.Count == 0)
        {
            Output.Success("  No hung applications detected.");
            return 0;
        }

        Console.WriteLine();
        var rows = matchedProcesses.Select(p => new[] { p.Id.ToString(), p.ProcessName }).ToList();
        Output.Table(["PID", "Name"], rows);

        var targets = KillCommand.BuildTargets(matchedProcesses);
        return await KillCommand.Execute(new KillRequest(targets, parser.Tree, parser.Force, parser.DryRun,
            "Hung applications"));
    }
}

// ============================================================
// Subcommand: RAM Hog
// ============================================================

internal static class RamHogCommand
{
    public static async Task<int> Run(string[] args)
    {
        var parser = new ArgParser(args);
        if (parser.Help)
        {
            Console.WriteLine("Usage: killall ramhog <MB> [--force] [--dry-run] [--top N]");
            Console.WriteLine("Terminate processes using more than the specified MB of RAM.");
            return 0;
        }

        long thresholdMB;
        if (parser.Positional.Count > 0 && long.TryParse(parser.Positional[0], out long mb))
            thresholdMB = mb;
        else
        {
            Output.Error("  Please specify a RAM threshold in MB. Example: killall ramhog 1024");
            return 2;
        }

        int topN = parser.GetInt("top", int.MaxValue);
        int selfPid = Environment.ProcessId;

        Output.Info($"  Scanning for processes using more than {thresholdMB} MB RAM...");

        var candidates = new List<(Process Proc, long WorkingSetMB, long PrivateMB)>();

        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                if (proc.Id == selfPid || proc.Id == 0) { proc.Dispose(); continue; }
                if (SafetyService.Classify(proc.ProcessName) == SafetyTier.Immortal)
                { proc.Dispose(); continue; }

                long wsMB = proc.WorkingSet64 / (1024 * 1024);
                long pmMB = proc.PrivateMemorySize64 / (1024 * 1024);

                if (wsMB >= thresholdMB)
                    candidates.Add((proc, wsMB, pmMB));
                else
                    proc.Dispose();
            }
            catch { proc.Dispose(); }
        }

        candidates = candidates.OrderByDescending(c => c.WorkingSetMB).Take(topN).ToList();

        if (candidates.Count == 0)
        {
            Output.Warning($"  No processes found using more than {thresholdMB} MB RAM.");
            return 3;
        }

        Console.WriteLine();
        var rows = candidates.Select(c =>
            new[] { c.Proc.Id.ToString(), c.Proc.ProcessName,
                    $"{c.WorkingSetMB} MB", $"{c.PrivateMB} MB" }).ToList();
        Output.Table(["PID", "Name", "Working Set", "Private"], rows);

        var targets = KillCommand.BuildTargets(candidates.Select(c => c.Proc).ToList());
        return await KillCommand.Execute(new KillRequest(targets, parser.Tree, parser.Force, parser.DryRun,
            $"RAM hogs (>{thresholdMB} MB)"));
    }
}

// ============================================================
// Subcommand: CPU Hog
// ============================================================

internal static class CpuHogCommand
{
    public static async Task<int> Run(string[] args)
    {
        var parser = new ArgParser(args);
        if (parser.Help)
        {
            Console.WriteLine("Usage: killall cpuhog <percent> [--sample N] [--force] [--dry-run] [--top N]");
            Console.WriteLine("Terminate processes using more than the specified percent CPU.");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  --sample N  Sampling interval in seconds (default: 1)");
            Console.WriteLine("  --top N     Kill only top N offenders");
            return 0;
        }

        double thresholdPercent;
        if (parser.Positional.Count > 0 && double.TryParse(parser.Positional[0], out double pct))
            thresholdPercent = pct;
        else
        {
            Output.Error("  Please specify a CPU threshold in percent. Example: killall cpuhog 80");
            return 2;
        }

        int sampleSeconds = parser.GetInt("sample", 1);
        int topN = parser.GetInt("top", int.MaxValue);
        int selfPid = Environment.ProcessId;
        int cpuCount = Environment.ProcessorCount;

        Output.Info($"  Sampling CPU usage for {sampleSeconds} second(s) ({cpuCount} logical cores)...");

        // Snapshot 1: capture TotalProcessorTime for all accessible processes
        var snapshot1 = new Dictionary<int, (Process Proc, TimeSpan CpuTime)>();
        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                if (proc.Id == 0 || proc.Id == 4 || proc.Id == selfPid) { proc.Dispose(); continue; }
                snapshot1[proc.Id] = (proc, proc.TotalProcessorTime);
            }
            catch { proc.Dispose(); }
        }

        var clockStart = DateTime.UtcNow;
        await Task.Delay(sampleSeconds * 1000);
        var clockEnd = DateTime.UtcNow;
        double elapsedMs = (clockEnd - clockStart).TotalMilliseconds;

        // Snapshot 2: re-read
        var cpuUsage = new List<(Process Proc, double CpuPercent)>();
        foreach (var (pid, (proc, cpuTime1)) in snapshot1)
        {
            try
            {
                proc.Refresh();
                var cpuTime2 = proc.TotalProcessorTime;
                double deltaMs = (cpuTime2 - cpuTime1).TotalMilliseconds;
                double cpuPercent = (deltaMs / elapsedMs / cpuCount) * 100.0;

                if (cpuPercent >= thresholdPercent &&
                    SafetyService.Classify(proc.ProcessName) != SafetyTier.Immortal)
                {
                    cpuUsage.Add((proc, cpuPercent));
                }
                else
                {
                    proc.Dispose();
                }
            }
            catch { proc.Dispose(); }
        }

        cpuUsage = cpuUsage.OrderByDescending(c => c.CpuPercent).Take(topN).ToList();

        if (cpuUsage.Count == 0)
        {
            Output.Warning($"  No processes found using more than {thresholdPercent}% CPU.");
            return 3;
        }

        Console.WriteLine();
        var rows = cpuUsage.Select(c =>
            new[] { c.Proc.Id.ToString(), c.Proc.ProcessName, $"{c.CpuPercent:F1}%" }).ToList();
        Output.Table(["PID", "Name", "CPU %"], rows);

        var targets = KillCommand.BuildTargets(cpuUsage.Select(c => c.Proc).ToList());
        return await KillCommand.Execute(new KillRequest(targets, parser.Tree, parser.Force, parser.DryRun,
            $"CPU hogs (>{thresholdPercent}%)"));
    }
}

// ============================================================
// Subcommand: LLM
// ============================================================

internal static class LlmCommand
{
    private static readonly HashSet<string> KnownLlmProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "ollama", "ollama_llama_server", "ollama-runner",
        "llama-server", "llama-cli", "llama-cpp", "llama",
        "llamafile",
        "koboldcpp",
        "lms", "LM Studio",
        "text-generation-webui", "text-generation",
        "oobabooga",
        "vllm",
        "localai",
        "tgi", "text-generation-inference",
        "tritonserver",
        "comfyui", "stable-diffusion-webui",
        "whisper", "whisper-server",
        "jan", "gpt4all", "faraday",
        "lmstudio"
    };

    private static readonly string[] CommandLinePatterns =
    [
        @"\.gguf",
        @"transformers",
        @"torch\.cuda",
        @"--model\b",
        @"text-generation-webui",
        @"llama\.cpp",
        @"koboldcpp",
        @"oobabooga",
        @"vllm\.entrypoints",
        @"localai",
        @"ollama\s+serve",
        @"huggingface",
        @"--load-in-4bit",
        @"--load-in-8bit",
        @"auto-gptq",
        @"exllama",
        @"ctransformers"
    ];

    public static async Task<int> Run(string[] args)
    {
        var parser = new ArgParser(args);
        if (parser.Help)
        {
            Console.WriteLine("Usage: killall llm [--force] [--dry-run]");
            Console.WriteLine("Terminate all local LLM/AI inference processes.");
            Console.WriteLine();
            Console.WriteLine("Detected process names include:");
            foreach (var name in KnownLlmProcesses.Order().Take(15))
                Console.WriteLine($"  - {name}");
            Console.WriteLine("  ... and more (including command-line pattern detection)");
            return 0;
        }

        Output.Info("  Scanning for LLM/AI processes...");

        ProcessTreeService.BuildProcessTree();
        int selfPid = Environment.ProcessId;
        var matchedProcesses = new List<Process>();
        var matchReasons = new Dictionary<int, string>();

        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                if (proc.Id == selfPid || proc.Id == 0) { proc.Dispose(); continue; }
                if (SafetyService.Classify(proc.ProcessName) == SafetyTier.Immortal)
                { proc.Dispose(); continue; }

                // Check by process name
                if (KnownLlmProcesses.Contains(proc.ProcessName))
                {
                    matchedProcesses.Add(proc);
                    matchReasons[proc.Id] = "Process name match";
                    continue;
                }

                // Check by command line
                var info = ProcessTreeService.GetProcessInfo(proc.Id);
                if (info?.CommandLine is not null)
                {
                    foreach (var pattern in CommandLinePatterns)
                    {
                        if (Regex.IsMatch(info.CommandLine, pattern, RegexOptions.IgnoreCase))
                        {
                            matchedProcesses.Add(proc);
                            matchReasons[proc.Id] = $"Command line: {pattern}";
                            break;
                        }
                    }

                    if (matchReasons.ContainsKey(proc.Id)) continue;
                }

                // Check if it's a Python process running LLM-related code
                if (proc.ProcessName.Equals("python", StringComparison.OrdinalIgnoreCase) ||
                    proc.ProcessName.Equals("python3", StringComparison.OrdinalIgnoreCase) ||
                    proc.ProcessName.StartsWith("python3.", StringComparison.OrdinalIgnoreCase))
                {
                    if (info?.CommandLine is not null)
                    {
                        foreach (var pattern in CommandLinePatterns)
                        {
                            if (Regex.IsMatch(info.CommandLine, pattern, RegexOptions.IgnoreCase))
                            {
                                matchedProcesses.Add(proc);
                                matchReasons[proc.Id] = $"Python LLM: {pattern}";
                                break;
                            }
                        }
                    }

                    if (!matchReasons.ContainsKey(proc.Id))
                        proc.Dispose();
                    continue;
                }

                proc.Dispose();
            }
            catch { proc.Dispose(); }
        }

        if (matchedProcesses.Count == 0)
        {
            Output.Success("  No LLM/AI processes detected.");
            return 0;
        }

        Console.WriteLine();
        var rows = matchedProcesses.Select(p =>
        {
            long ramMB = 0;
            try { ramMB = p.WorkingSet64 / (1024 * 1024); } catch { }
            return new[] { p.Id.ToString(), p.ProcessName,
                $"{ramMB} MB", matchReasons.GetValueOrDefault(p.Id, "") };
        }).ToList();
        Output.Table(["PID", "Name", "RAM", "Reason"], rows);

        var targets = KillCommand.BuildTargets(matchedProcesses);
        return await KillCommand.Execute(new KillRequest(targets, parser.Tree, parser.Force, parser.DryRun,
            "LLM/AI processes"));
    }
}

// ============================================================
// Subcommand: Game
// ============================================================

internal static class GameCommand
{
    private static readonly HashSet<string> KnownGameProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        // Launchers and platforms
        "steam", "steamwebhelper", "steamservice", "GameOverlayUI",
        "EpicGamesLauncher", "EpicWebHelper",
        "Origin", "OriginWebHelperService", "OriginThinSetupInternal",
        "EADesktop", "EABackgroundService", "EAConnect_microsoft",
        "Battle.net", "Agent", "BlizzardError",
        "GalaxyClient", "GOG Galaxy", "GalaxyClientService",
        "UbisoftConnect", "UplayWebCore", "upc",
        "Playnite.DesktopApp", "Playnite.FullscreenApp",
        "RiotClientServices", "RiotClientCrashHandler", "RiotClientUx",
        // Common game engines / processes
        "UnrealCEFSubProcess",
        "CrashReportClient",
        "BEService", "BEDaisy", // BattlEye
        "EasyAntiCheat", "EasyAntiCheat_EOS",
        "vgc", "vgtray", // Vanguard anti-cheat
        // Streaming/capture often associated with gaming
        "obs64", "obs32",
        "GeForceExperience", "NVIDIA Share", "nvcontainer"
    };

    private static readonly string[] GamePathPatterns =
    [
        @"\\Steam\\steamapps\\",
        @"\\Epic Games\\",
        @"\\GOG Games\\",
        @"\\Riot Games\\",
        @"\\Ubisoft\\",
        @"\\Battle\.net\\",
        @"\\Origin Games\\",
        @"\\EA Games\\",
        @"\\Program Files.*\\Games\\",
        @"\\Xbox\\",
        @"\\WindowsApps\\.*game",
    ];

    private static readonly HashSet<string> GameModules = new(StringComparer.OrdinalIgnoreCase)
    {
        "UnityPlayer.dll",
        "steam_api64.dll", "steam_api.dll",
        "GameOverlayRenderer64.dll", "GameOverlayRenderer.dll",
        "XInput1_4.dll", "XInput1_3.dll", "XInput9_1_0.dll",
        "dinput8.dll",
        "d3d12.dll",
        "bink2w64.dll",
        "fmod.dll", "fmodstudio.dll",
        "PhysX3_x64.dll",
        "eossdk-win64-shipping.dll",
        "galaxypeer64.dll"
    };

    public static async Task<int> Run(string[] args)
    {
        var parser = new ArgParser(args);
        if (parser.Help)
        {
            Console.WriteLine("Usage: killall game [--force] [--dry-run]");
            Console.WriteLine("Terminate all game-related processes including launchers and engines.");
            return 0;
        }

        Output.Info("  Scanning for game-related processes...");

        ProcessTreeService.BuildProcessTree();
        int selfPid = Environment.ProcessId;
        var matchedProcesses = new List<Process>();
        var matchReasons = new Dictionary<int, string>();

        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                if (proc.Id == selfPid || proc.Id == 0 || proc.Id == 4) { proc.Dispose(); continue; }
                if (SafetyService.Classify(proc.ProcessName) == SafetyTier.Immortal)
                { proc.Dispose(); continue; }

                // Check by process name
                if (KnownGameProcesses.Contains(proc.ProcessName))
                {
                    matchedProcesses.Add(proc);
                    matchReasons[proc.Id] = "Known game process";
                    continue;
                }

                // Check by executable path
                var info = ProcessTreeService.GetProcessInfo(proc.Id);
                if (info?.ExecutablePath is not null)
                {
                    foreach (var pathPattern in GamePathPatterns)
                    {
                        if (Regex.IsMatch(info.ExecutablePath, pathPattern, RegexOptions.IgnoreCase))
                        {
                            matchedProcesses.Add(proc);
                            matchReasons[proc.Id] = $"Game path: {pathPattern.Replace(@"\\", "\\")}";
                            goto NextProcess;
                        }
                    }
                }

                // Check by loaded modules (more expensive — do last)
                try
                {
                    int gameModuleCount = 0;
                    foreach (ProcessModule module in proc.Modules)
                    {
                        if (GameModules.Contains(module.ModuleName ?? ""))
                            gameModuleCount++;

                        if (gameModuleCount >= 2) // Require at least 2 game-related modules
                        {
                            matchedProcesses.Add(proc);
                            matchReasons[proc.Id] = "Game module detection";
                            goto NextProcess;
                        }
                    }
                }
                catch { /* access denied — skip module check */ }

                proc.Dispose();
                NextProcess:;
            }
            catch { proc.Dispose(); }
        }

        if (matchedProcesses.Count == 0)
        {
            Output.Success("  No game-related processes detected.");
            return 0;
        }

        Console.WriteLine();
        var rows = matchedProcesses.Select(p =>
        {
            long ramMB = 0;
            try { ramMB = p.WorkingSet64 / (1024 * 1024); } catch { }
            return new[] { p.Id.ToString(), p.ProcessName,
                $"{ramMB} MB", matchReasons.GetValueOrDefault(p.Id, "") };
        }).ToList();
        Output.Table(["PID", "Name", "RAM", "Reason"], rows);

        var targets = KillCommand.BuildTargets(matchedProcesses);
        return await KillCommand.Execute(new KillRequest(targets, parser.Tree, parser.Force, parser.DryRun,
            "Game processes"));
    }
}

// ============================================================
// Advanced Filter: --cmdline (Kill by command-line pattern)
// ============================================================

internal static class CmdLineFilter
{
    public static List<Process> FindMatching(string pattern)
    {
        ProcessTreeService.BuildProcessTree();
        int selfPid = Environment.ProcessId;
        var matched = new List<Process>();

        bool isRegex = pattern.StartsWith('/') && pattern.EndsWith('/') && pattern.Length > 2;
        Regex? regex = isRegex
            ? new Regex(pattern[1..^1], RegexOptions.IgnoreCase | RegexOptions.Compiled)
            : null;

        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                if (proc.Id == selfPid || proc.Id == 0) { proc.Dispose(); continue; }

                var info = ProcessTreeService.GetProcessInfo(proc.Id);
                if (info?.CommandLine is null) { proc.Dispose(); continue; }

                bool match = regex != null
                    ? regex.IsMatch(info.CommandLine)
                    : info.CommandLine.Contains(pattern, StringComparison.OrdinalIgnoreCase);

                if (match)
                    matched.Add(proc);
                else
                    proc.Dispose();
            }
            catch { proc.Dispose(); }
        }

        return matched;
    }
}

// ============================================================
// Advanced Filter: --module (Kill by loaded DLL)
// ============================================================

internal static class ModuleFilter
{
    public static List<Process> FindMatching(string dllName)
    {
        int selfPid = Environment.ProcessId;
        var matched = new List<Process>();

        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                if (proc.Id == selfPid || proc.Id == 0) { proc.Dispose(); continue; }
                if (SafetyService.Classify(proc.ProcessName) == SafetyTier.Immortal)
                { proc.Dispose(); continue; }

                bool found = false;
                try
                {
                    foreach (ProcessModule module in proc.Modules)
                    {
                        if (string.Equals(module.ModuleName, dllName, StringComparison.OrdinalIgnoreCase))
                        {
                            found = true;
                            break;
                        }
                    }
                }
                catch { /* access denied or 32/64 bit mismatch — skip */ }

                if (found)
                    matched.Add(proc);
                else
                    proc.Dispose();
            }
            catch { proc.Dispose(); }
        }

        return matched;
    }
}

// ============================================================
// Advanced Filter: --port (Kill by port)
// ============================================================

internal static class PortFilter
{
    public static List<Process> FindMatching(string portSpec)
    {
        int portStart, portEnd;

        if (portSpec.Contains('-'))
        {
            var parts = portSpec.Split('-', 2);
            if (!int.TryParse(parts[0], out portStart) || !int.TryParse(parts[1], out portEnd))
            {
                Output.Error($"  Invalid port range: {portSpec}");
                return [];
            }
        }
        else if (int.TryParse(portSpec, out int single))
        {
            portStart = portEnd = single;
        }
        else
        {
            Output.Error($"  Invalid port: {portSpec}");
            return [];
        }

        var matchedPids = new HashSet<int>();

        // Scan TCP connections
        ScanTcpPorts(matchedPids, portStart, portEnd);

        // Scan UDP endpoints
        ScanUdpPorts(matchedPids, portStart, portEnd);

        int selfPid = Environment.ProcessId;
        matchedPids.Remove(0);
        matchedPids.Remove(4);
        matchedPids.Remove(selfPid);

        var matched = new List<Process>();
        foreach (int pid in matchedPids)
        {
            try
            {
                var proc = Process.GetProcessById(pid);
                if (SafetyService.Classify(proc.ProcessName) != SafetyTier.Immortal)
                    matched.Add(proc);
                else
                    proc.Dispose();
            }
            catch { /* process gone */ }
        }

        return matched;
    }

    private static void ScanTcpPorts(HashSet<int> pids, int portStart, int portEnd)
    {
        foreach (int af in new[] { NativeMethods.AF_INET, NativeMethods.AF_INET6 })
        {
            int bufferSize = 0;
            uint ret = NativeMethods.GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true,
                af, NativeMethods.TcpTableClass.TCP_TABLE_OWNER_PID_ALL, 0);

            if (ret != NativeMethods.ERROR_INSUFFICIENT_BUFFER && ret != NativeMethods.NO_ERROR)
                continue;

            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
            try
            {
                ret = NativeMethods.GetExtendedTcpTable(buffer, ref bufferSize, true,
                    af, NativeMethods.TcpTableClass.TCP_TABLE_OWNER_PID_ALL, 0);
                if (ret != NativeMethods.NO_ERROR) continue;

                if (af == NativeMethods.AF_INET)
                {
                    int numEntries = Marshal.ReadInt32(buffer);
                    IntPtr rowPtr = buffer + 4;
                    int rowSize = Marshal.SizeOf<NativeMethods.MIB_TCPROW_OWNER_PID>();

                    for (int i = 0; i < numEntries; i++)
                    {
                        var row = Marshal.PtrToStructure<NativeMethods.MIB_TCPROW_OWNER_PID>(rowPtr);
                        int localPort = Math.Abs(IPAddress.NetworkToHostOrder((short)(row.dwLocalPort & 0xFFFF)));

                        if (localPort >= portStart && localPort <= portEnd)
                            pids.Add((int)row.dwOwningPid);

                        rowPtr += rowSize;
                    }
                }
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
    }

    private static void ScanUdpPorts(HashSet<int> pids, int portStart, int portEnd)
    {
        int bufferSize = 0;
        uint ret = NativeMethods.GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, true,
            NativeMethods.AF_INET, NativeMethods.UdpTableClass.UDP_TABLE_OWNER_PID, 0);

        if (ret != NativeMethods.ERROR_INSUFFICIENT_BUFFER && ret != NativeMethods.NO_ERROR)
            return;

        IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            ret = NativeMethods.GetExtendedUdpTable(buffer, ref bufferSize, true,
                NativeMethods.AF_INET, NativeMethods.UdpTableClass.UDP_TABLE_OWNER_PID, 0);
            if (ret != NativeMethods.NO_ERROR) return;

            int numEntries = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = buffer + 4;
            int rowSize = Marshal.SizeOf<NativeMethods.MIB_UDPROW_OWNER_PID>();

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<NativeMethods.MIB_UDPROW_OWNER_PID>(rowPtr);
                int localPort = Math.Abs(IPAddress.NetworkToHostOrder((short)(row.dwLocalPort & 0xFFFF)));

                if (localPort >= portStart && localPort <= portEnd)
                    pids.Add((int)row.dwOwningPid);

                rowPtr += rowSize;
            }
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }
}

// ============================================================
// Advanced Filter: --window (Kill by window title)
// ============================================================

internal static class WindowFilter
{
    public static List<Process> FindMatching(string pattern)
    {
        bool isRegex = pattern.StartsWith('/') && pattern.EndsWith('/') && pattern.Length > 2;
        Regex? regex = isRegex
            ? new Regex(pattern[1..^1], RegexOptions.IgnoreCase | RegexOptions.Compiled)
            : null;

        var matchedPids = new HashSet<int>();

        NativeMethods.EnumWindows((hWnd, _) =>
        {
            int len = NativeMethods.GetWindowTextLength(hWnd);
            if (len <= 0) return true;

            var sb = new System.Text.StringBuilder(len + 1);
            NativeMethods.GetWindowText(hWnd, sb, sb.Capacity);
            string title = sb.ToString();

            bool match = regex != null
                ? regex.IsMatch(title)
                : title.Contains(pattern, StringComparison.OrdinalIgnoreCase);

            if (match)
            {
                NativeMethods.GetWindowThreadProcessId(hWnd, out uint pid);
                if (pid != 0)
                    matchedPids.Add((int)pid);
            }

            return true;
        }, IntPtr.Zero);

        int selfPid = Environment.ProcessId;
        matchedPids.Remove(selfPid);

        var matched = new List<Process>();
        foreach (int pid in matchedPids)
        {
            try
            {
                var proc = Process.GetProcessById(pid);
                if (SafetyService.Classify(proc.ProcessName) != SafetyTier.Immortal)
                    matched.Add(proc);
                else
                    proc.Dispose();
            }
            catch { /* process gone */ }
        }

        return matched;
    }
}

// ============================================================
// Advanced Filter: --parent (Kill by parent PID or name)
// ============================================================

internal static class ParentFilter
{
    public static List<Process> FindMatching(string parentSpec)
    {
        ProcessTreeService.BuildProcessTree();
        int selfPid = Environment.ProcessId;
        var parentPids = new HashSet<int>();

        if (int.TryParse(parentSpec, out int ppid))
        {
            parentPids.Add(ppid);
        }
        else
        {
            // Resolve name to PIDs
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    if (string.Equals(proc.ProcessName, parentSpec, StringComparison.OrdinalIgnoreCase))
                        parentPids.Add(proc.Id);
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }

        if (parentPids.Count == 0)
        {
            Output.Warning($"  No parent process found matching '{parentSpec}'.");
            return [];
        }

        // Find all processes whose ParentProcessId matches
        var matched = new List<Process>();
        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                if (proc.Id == selfPid || proc.Id == 0) { proc.Dispose(); continue; }

                var info = ProcessTreeService.GetProcessInfo(proc.Id);
                if (info != null && parentPids.Contains(info.ParentPid))
                    matched.Add(proc);
                else
                    proc.Dispose();
            }
            catch { proc.Dispose(); }
        }

        return matched;
    }
}

// ============================================================
// Help System
// ============================================================

internal static class HelpCommand
{
    public static void ShowHelp()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(@"
  ╔═══════════════════════════════════════════════════════════════╗
  ║  killall — Windows 11 Intelligent Process Termination Tool   ║
  ╚═══════════════════════════════════════════════════════════════╝");
        Console.ResetColor();

        Console.WriteLine(@"
  USAGE
    killall <pattern> [options]       Kill processes matching a name/pattern
    killall <subcommand> [options]    Run a specialized kill command

  PATTERN MATCHING
    killall notepad                   Exact name match (case-insensitive)
    killall note                      Partial/substring match (fallback)
    killall note*                     Glob wildcard match
    killall /note.*pad/               Regex match (enclosed in slashes)

  OPTIONS
    -t, --tree                        Kill entire process tree (children first)
    -f, --force                       Skip confirmation prompt
    -n, --dry-run                     Show what would be killed without acting
    -h, --help                        Show this help

  ADVANCED FILTERS (combinable with pattern, --tree, --force, --dry-run)
    --cmdline <pattern>               Kill by command-line substring or /regex/
    --module <dllname>                Kill by loaded DLL/module name
    --port <N> or <start-end>         Kill by listening/connected port (TCP/UDP)
    --window <title>                  Kill by window title substring or /regex/
    --parent <pid or name>            Kill children of a given parent process

  SUBCOMMANDS
    killall restart <name>            Kill and restart a process
    killall gpu [--threshold N]       Kill GPU-consuming processes (default >1%)
    killall networkapps               Kill processes with active network connections
    killall hung                      Kill all 'Not Responding' applications
    killall ramhog <MB>               Kill processes using more than N MB RAM
    killall cpuhog <percent>          Kill processes using more than N% CPU
                   [--sample N]         (sampling interval in seconds, default 1)
    killall llm                       Kill all local LLM/AI inference processes
    killall game                      Kill all game processes and launchers

  SUBCOMMAND OPTIONS
    --threshold N                     GPU/CPU/RAM threshold value
    --top N                           Kill only top N offenders (ramhog/cpuhog)
    --sample N                        CPU sampling interval in seconds (cpuhog)
    --force, -f                       Skip confirmation on any subcommand
    --dry-run, -n                     Preview mode on any subcommand");

        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine(@"
  SAFETY — THREE-TIER PROTECTION MODEL");
        Console.ResetColor();

        Console.WriteLine(@"
    Tier 1 — IMMORTAL (Hard Block)
      Critical Windows system processes that are NEVER terminated.
      Includes: System, csrss, lsass, winlogon, svchost, dwm, smss,
                wininit, services, fontdrvhost, MsMpEng, and others.
      These processes are essential for OS stability. Killing them
      would cause an immediate BSOD or system crash.");

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("    Tier 2 — AUTO-RESTART");
        Console.ResetColor();
        Console.WriteLine(@" (Watchdog)
      Essential Windows 11 UI processes that will be automatically
      restarted after termination. Includes: explorer.exe,
      ShellExperienceHost, StartMenuExperienceHost, SearchHost,
      RuntimeBroker, Taskmgr, ApplicationFrameHost, Widgets.
      Explorer.exe has special retry logic (up to 3 attempts).");

        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write("    Tier 3 — ALLOWED");
        Console.ResetColor();
        Console.WriteLine(@" (Normal Kill)
      All other processes. Terminated normally with confirmation.");

        Console.WriteLine(@"
  GPU DETECTION
    Primary: Windows Performance Counters (GPU Engine) via WMI
    Fallback: Loaded module detection (d3d11, d3d12, vulkan, CUDA)
    Supports NVIDIA, AMD, and Intel GPUs on Windows 10 1809+

  NETWORK DETECTION
    Uses iphlpapi.dll P/Invoke (GetExtendedTcpTable/GetExtendedUdpTable)
    Enumerates all TCP (ESTABLISHED) and UDP connections per process
    Supports both IPv4 and IPv6

  HUNG APP DETECTION
    Uses IsHungAppWindow (user32.dll) and SendMessageTimeout
    with SMTO_ABORTIFHUNG flag for reliable detection
    Also checks Process.Responding for .NET-accessible processes

  TREE KILL (--tree)
    Builds a complete parent-child process map via WMI Win32_Process.
    Recursively collects all descendants. Kills children first, then
    parent (bottom-up). Tier 1 processes in the tree are skipped.
    Tier 2 processes are killed and restarted.

  EXAMPLES
    killall notepad                   Kill all Notepad instances
    killall chrome --tree             Kill Chrome and all child processes
    killall /fire.*fox/ -f            Regex kill Firefox, skip confirmation
    killall hung                      Kill all hung/frozen applications
    killall ramhog 2048               Kill processes using >2 GB RAM
    killall cpuhog 90 --top 3         Kill top 3 CPU hogs above 90%
    killall gpu --threshold 5         Kill processes using >5% GPU
    killall llm -f                    Force-kill all LLM processes
    killall game --dry-run            Preview game processes to kill

  ADVANCED FILTER EXAMPLES
    killall --cmdline ""--model""       Kill processes with --model in args
    killall --cmdline /http\.server/  Kill Python http.server instances
    killall --module d3d12.dll        Kill all processes using Direct3D 12
    killall --module torch_cuda.dll   Kill CUDA-accelerated processes
    killall --port 8080               Kill process owning port 8080
    killall --port 5000-6000          Kill processes on ports 5000-6000
    killall --window ""Crash Reporter"" Kill windows titled Crash Reporter
    killall --window /Incognito/      Kill windows matching regex
    killall --parent explorer         Kill all children of explorer.exe
    killall --parent 1234 --tree      Kill children of PID 1234 + subtrees

  NOTE: Some operations require Administrator privileges.
  Run from an elevated terminal for full functionality.
");
    }
}

// ============================================================
// Program — Entry Point
// ============================================================

internal static class Program
{
    static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;

        if (args.Length == 0)
        {
            HelpCommand.ShowHelp();
            return 0;
        }

        string first = args[0].ToLowerInvariant();

        // Help flags
        if (first is "-h" or "--help" or "-?" or "help")
        {
            HelpCommand.ShowHelp();
            return 0;
        }

        // Check for admin rights and warn
        CheckAdminRights();

        // Route subcommands
        string[] subArgs = args.Length > 1 ? args[1..] : [];

        return first switch
        {
            "restart" => await RestartCommand.Run(subArgs),
            "gpu" => await GpuCommand.Run(subArgs),
            "networkapps" => await NetworkAppsCommand.Run(subArgs),
            "hung" => await HungCommand.Run(subArgs),
            "ramhog" => await RamHogCommand.Run(subArgs),
            "cpuhog" => await CpuHogCommand.Run(subArgs),
            "llm" => await LlmCommand.Run(subArgs),
            "game" => await GameCommand.Run(subArgs),
            _ => await RunPatternKill(args)
        };
    }

    private static async Task<int> RunPatternKill(string[] args)
    {
        var parser = new ArgParser(args);

        // Check for advanced filters first
        string? cmdlineVal = parser.GetValue("cmdline");
        string? moduleVal = parser.GetValue("module");
        string? portVal = parser.GetValue("port");
        string? windowVal = parser.GetValue("window");
        string? parentVal = parser.GetValue("parent");

        bool hasAdvancedFilter = cmdlineVal != null || moduleVal != null ||
                                 portVal != null || windowVal != null || parentVal != null;

        List<Process> processes;
        string reason;

        if (hasAdvancedFilter)
        {
            // Collect matches from all specified filters (union)
            var seenPids = new HashSet<int>();
            processes = [];
            reason = "Advanced filter";

            if (cmdlineVal != null)
            {
                reason = $"Command-line '{cmdlineVal}'";
                foreach (var p in CmdLineFilter.FindMatching(cmdlineVal))
                    if (seenPids.Add(p.Id)) processes.Add(p); else p.Dispose();
            }

            if (moduleVal != null)
            {
                reason = $"Module '{moduleVal}'";
                foreach (var p in ModuleFilter.FindMatching(moduleVal))
                    if (seenPids.Add(p.Id)) processes.Add(p); else p.Dispose();
            }

            if (portVal != null)
            {
                reason = $"Port {portVal}";
                foreach (var p in PortFilter.FindMatching(portVal))
                    if (seenPids.Add(p.Id)) processes.Add(p); else p.Dispose();
            }

            if (windowVal != null)
            {
                reason = $"Window '{windowVal}'";
                foreach (var p in WindowFilter.FindMatching(windowVal))
                    if (seenPids.Add(p.Id)) processes.Add(p); else p.Dispose();
            }

            if (parentVal != null)
            {
                reason = $"Parent '{parentVal}'";
                foreach (var p in ParentFilter.FindMatching(parentVal))
                    if (seenPids.Add(p.Id)) processes.Add(p); else p.Dispose();
            }

            // If a positional pattern is also specified, intersect with it
            if (parser.Positional.Count > 0)
            {
                string pattern = parser.Positional[0];
                processes = processes.Where(p => PatternMatcher.IsMatch(p.ProcessName, pattern)).ToList();
                reason += $" + pattern '{pattern}'";
            }
        }
        else
        {
            if (parser.Positional.Count == 0)
            {
                Output.Error("  No process name or pattern specified.");
                return 2;
            }

            string pattern = parser.Positional[0];
            processes = PatternMatcher.FindMatching(pattern);
            reason = $"Pattern '{pattern}'";
        }

        if (processes.Count == 0)
        {
            Output.Warning($"  No processes matched ({reason}).");
            return 3;
        }

        var targets = KillCommand.BuildTargets(processes);
        return await KillCommand.Execute(new KillRequest(
            targets, parser.Tree, parser.Force, parser.DryRun, reason));
    }

    private static void CheckAdminRights()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            if (!principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
            {
                Output.Muted("  (Running without Administrator privileges — some processes may be inaccessible)");
                Console.WriteLine();
            }
        }
        catch { /* ignore on failure */ }
    }
}
