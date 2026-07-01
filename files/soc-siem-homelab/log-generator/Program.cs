using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Threading;

namespace SiemLab.LogGenerator;

/// <summary>
/// Custom application log generator for the SIEM home lab.
///
/// Emits syslog-style "CustomApp" authentication events that are parsed by a
/// custom Wazuh decoder (detections/decoders/local_decoder.xml) and evaluated
/// by custom correlation rules (detections/rules/local_rules.xml).
///
/// Emitted line format (must stay in sync with the decoder regex):
///   MMM dd HH:mm:ss &lt;HOST&gt; CustomApp: action=&lt;A&gt; user=&lt;U&gt; srcip=&lt;IP&gt; reason=&lt;R&gt;
/// e.g.
///   Jun 07 14:03:11 APPSRV CustomApp: action=LOGIN_FAILED user=jdoe srcip=10.10.10.20 reason=bad_password
/// </summary>
internal static class Program
{
    private static readonly string[] DefaultUsers = { "jdoe", "asmith", "svc_backup", "mwilson" };

    private static int Main(string[] args)
    {
        var opts = Options.Parse(args);
        if (opts is null)
        {
            PrintUsage();
            return 1;
        }

        Console.WriteLine($"[log-generator] scenario={opts.Scenario} output=\"{opts.OutputPath}\" " +
                          $"host={opts.Host} count={opts.Count} delay={opts.DelayMs}ms srcip={opts.SrcIp}");

        try
        {
            EnsureOutputDirectory(opts.OutputPath);
            switch (opts.Scenario)
            {
                case Scenario.Baseline:   RunBaseline(opts);   break;
                case Scenario.BruteForce: RunBruteForce(opts); break;
                case Scenario.Compromise: RunCompromise(opts); break;
                case Scenario.Mixed:      RunMixed(opts);      break;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[log-generator] error: {ex.Message}");
            return 2;
        }

        Console.WriteLine("[log-generator] done.");
        return 0;
    }

    /// <summary>Normal, low-volume traffic with a small percentage of noise failures.</summary>
    private static void RunBaseline(Options o)
    {
        var rnd = new Random();
        for (int i = 0; i < o.Count; i++)
        {
            string user = o.Users[rnd.Next(o.Users.Count)];
            string ip = $"10.10.10.{rnd.Next(20, 60)}";
            bool fail = rnd.Next(100) < 10; // ~10% benign failures
            Emit(o, fail ? "LOGIN_FAILED" : "LOGIN_SUCCESS", user, ip, fail ? "bad_password" : "ok");
            Sleep(o.DelayMs);
        }
    }

    /// <summary>Many failed logins from a single source IP -> fires correlation rule 100102.</summary>
    private static void RunBruteForce(Options o)
    {
        var rnd = new Random();
        for (int i = 0; i < o.Count; i++)
        {
            string user = o.Users[rnd.Next(o.Users.Count)];
            Emit(o, "LOGIN_FAILED", user, o.SrcIp, "bad_password");
            Sleep(o.DelayMs);
        }
    }

    /// <summary>
    /// A brute-force burst against one user followed by a SUCCESS from the same
    /// source -> escalates through rule 100102 (brute force) to 100103 (compromise).
    /// </summary>
    private static void RunCompromise(Options o)
    {
        var rnd = new Random();
        string target = o.Users[rnd.Next(o.Users.Count)];
        int burst = Math.Max(o.Count, 6); // need at least the rule's frequency threshold
        for (int i = 0; i < burst; i++)
        {
            Emit(o, "LOGIN_FAILED", target, o.SrcIp, "bad_password");
            Sleep(o.DelayMs);
        }
        Emit(o, "LOGIN_SUCCESS", target, o.SrcIp, "ok");
    }

    /// <summary>Baseline noise, then brute force, then a compromise sequence.</summary>
    private static void RunMixed(Options o)
    {
        RunBaseline(o);
        RunBruteForce(o);
        RunCompromise(o);
    }

    private static void Emit(Options o, string action, string user, string srcip, string reason)
    {
        string ts = DateTime.Now.ToString("MMM dd HH:mm:ss", CultureInfo.InvariantCulture);
        string line = $"{ts} {o.Host} CustomApp: action={action} user={user} srcip={srcip} reason={reason}";
        File.AppendAllText(o.OutputPath, line + Environment.NewLine);
        Console.WriteLine(line);
    }

    private static void EnsureOutputDirectory(string path)
    {
        string? dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            Directory.CreateDirectory(dir);
    }

    private static void Sleep(int ms)
    {
        if (ms > 0) Thread.Sleep(ms);
    }

    private static void PrintUsage()
    {
        Console.WriteLine(@"
CustomApp log generator (SIEM home lab)

Usage:
  dotnet run -- [options]

Options:
  --scenario <name>   baseline | bruteforce | compromise | mixed   (default: bruteforce)
  --output <path>     Log file the Wazuh agent watches
                      (default: /var/log/customapp.log on Linux, C:\logs\customapp.log on Windows)
  --host <name>       Hostname tag written into each line                (default: APPSRV)
  --srcip <ip>        Attacker source IP for brute-force/compromise      (default: 10.10.10.20)
  --users <u1,u2,..>  Comma-separated user pool                          (default: jdoe,asmith,svc_backup,mwilson)
  --count <n>         Number of events (per phase for 'mixed')           (default: 8)
  --delay <ms>        Delay between events in milliseconds               (default: 2000)
  --help              Show this help

Examples:
  dotnet run -- --scenario bruteforce --srcip 10.10.10.20 --count 8
  dotnet run -- --scenario compromise --output /var/log/customapp.log
  dotnet run -- --scenario baseline --count 30 --delay 500
");
    }
}

internal enum Scenario { Baseline, BruteForce, Compromise, Mixed }

internal sealed class Options
{
    public Scenario Scenario { get; init; } = Scenario.BruteForce;
    public string OutputPath { get; init; } = DefaultOutputPath();
    public string Host { get; init; } = "APPSRV";
    public string SrcIp { get; init; } = "10.10.10.20";
    public IReadOnlyList<string> Users { get; init; } = new[] { "jdoe", "asmith", "svc_backup", "mwilson" };
    public int Count { get; init; } = 8;
    public int DelayMs { get; init; } = 2000;

    private static string DefaultOutputPath() =>
        OperatingSystem.IsWindows() ? @"C:\logs\customapp.log" : "/var/log/customapp.log";

    /// <summary>Parses argv. Returns null on --help or invalid input.</summary>
    public static Options? Parse(string[] args)
    {
        var scenario = Scenario.BruteForce;
        string output = DefaultOutputPath();
        string host = "APPSRV";
        string srcip = "10.10.10.20";
        var users = new List<string> { "jdoe", "asmith", "svc_backup", "mwilson" };
        int count = 8;
        int delay = 2000;

        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i].ToLowerInvariant();
            string? Next() => (i + 1 < args.Length) ? args[++i] : null;

            switch (a)
            {
                case "--help" or "-h":
                    return null;

                case "--scenario":
                    string? s = Next();
                    if (s is null || !Enum.TryParse(s, true, out scenario))
                    {
                        Console.Error.WriteLine($"Invalid --scenario value: {s}");
                        return null;
                    }
                    break;

                case "--output":  output = Next() ?? output; break;
                case "--host":    host = Next() ?? host; break;
                case "--srcip":   srcip = Next() ?? srcip; break;

                case "--users":
                    string? u = Next();
                    if (!string.IsNullOrWhiteSpace(u))
                        users = new List<string>(u.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
                    break;

                case "--count":
                    if (!int.TryParse(Next(), out count) || count < 1)
                    {
                        Console.Error.WriteLine("--count must be a positive integer.");
                        return null;
                    }
                    break;

                case "--delay":
                    if (!int.TryParse(Next(), out delay) || delay < 0)
                    {
                        Console.Error.WriteLine("--delay must be a non-negative integer.");
                        return null;
                    }
                    break;

                default:
                    Console.Error.WriteLine($"Unknown argument: {args[i]}");
                    return null;
            }
        }

        return new Options
        {
            Scenario = scenario,
            OutputPath = output,
            Host = host,
            SrcIp = srcip,
            Users = users,
            Count = count,
            DelayMs = delay
        };
    }
}
