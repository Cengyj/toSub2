# Legacy fallback only. The current scheduled task uses windows-daemon.py via pythonw.exe.
param(
    [Parameter(Mandatory = $true)]
    [string]$ConfigPath
)

$ErrorActionPreference = 'Stop'
$config = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
Set-Location -LiteralPath $config.ProjectRoot
$env:NODE_ENV = 'production'
$env:TOSUB2_PYTHON = $config.PythonPath
$env:ONBOARDING_OUTPUT_ROOT = $config.OutputRoot
$env:ONBOARDING_HOST = $config.Host
$env:PATH = (Split-Path -Parent $config.NodePath) + ';' + $env:PATH
$logRoot = $config.LogRoot
New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
New-Item -ItemType Directory -Path $config.OutputRoot -Force | Out-Null
$supervisorLog = Join-Path $logRoot 'supervisor.log'
$child = $null

# Closing the supervisor (including Task Scheduler termination) must close the
# complete node/Python/esbuild process tree. Windows jobs enforce this in-kernel.
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class ToSub2ProcessJob {
    [StructLayout(LayoutKind.Sequential)]
    struct BasicLimits {
        public long ProcessTime, JobTime;
        public uint Flags;
        public UIntPtr MinimumWorkingSet, MaximumWorkingSet;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass, SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct IoCounters {
        public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct ExtendedLimits {
        public BasicLimits Basic;
        public IoCounters Io;
        public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetInformationJobObject(IntPtr job, int type, ref ExtendedLimits limits, uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);
    public static IntPtr Create() {
        IntPtr job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        ExtendedLimits limits = new ExtendedLimits();
        limits.Basic.Flags = 0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if (!SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(limits))) {
            int error = Marshal.GetLastWin32Error();
            CloseHandle(job);
            throw new Win32Exception(error);
        }
        return job;
    }
    public static void Assign(IntPtr job, IntPtr process) {
        if (!AssignProcessToJobObject(job, process))
            throw new Win32Exception(Marshal.GetLastWin32Error());
    }
}
'@

function Write-SupervisorLog([string]$Message) {
    if ((Test-Path -LiteralPath $supervisorLog) -and (Get-Item -LiteralPath $supervisorLog).Length -gt 5MB) {
        Move-Item -LiteralPath $supervisorLog -Destination ($supervisorLog + '.previous') -Force
    }
    Add-Content -LiteralPath $supervisorLog -Value ('[{0}] {1}' -f (Get-Date -Format o), $Message) -Encoding UTF8
}

try {
    while ($true) {
        $job = [IntPtr]::Zero
        try {
            foreach ($name in @('console-out.log', 'console-error.log')) {
                $log = Join-Path $logRoot $name
                if (Test-Path -LiteralPath $log) {
                    Move-Item -LiteralPath $log -Destination ($log + '.previous') -Force
                }
            }
            $job = [ToSub2ProcessJob]::Create()
            $child = Start-Process -FilePath $config.NodePath -ArgumentList @(
                'src/console-server.mjs', '--host', $config.Host, '--port', [string]$config.Port
            ) -WorkingDirectory $config.ProjectRoot -WindowStyle Hidden -PassThru `
                -RedirectStandardOutput (Join-Path $logRoot 'console-out.log') `
                -RedirectStandardError (Join-Path $logRoot 'console-error.log')
            [ToSub2ProcessJob]::Assign($job, $child.Handle)
            Write-SupervisorLog ('Started node PID {0} on {1}:{2}' -f $child.Id, $config.Host, $config.Port)
            $child.WaitForExit()
            Write-SupervisorLog ('Node PID {0} exited with code {1}; restarting in 5 seconds.' -f $child.Id, $child.ExitCode)
        } catch {
            Write-SupervisorLog ('Launch error: {0}; retrying in 5 seconds.' -f $_.Exception.Message)
        } finally {
            if ($job -ne [IntPtr]::Zero) {
                [ToSub2ProcessJob]::CloseHandle($job) | Out-Null
            }
            if ($null -ne $child) {
                if (-not $child.HasExited) {
                    Stop-Process -Id $child.Id -Force -ErrorAction SilentlyContinue
                }
                $child.Dispose()
                $child = $null
            }
        }
        Start-Sleep -Seconds 5
    }
} finally {
    if ($null -ne $child -and -not $child.HasExited) {
        Stop-Process -Id $child.Id -Force -ErrorAction SilentlyContinue
    }
}
