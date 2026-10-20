param(
    [Parameter(Mandatory = $true)][ValidateRange(1, 2147483647)][int]$TargetPid,
    [Parameter(Mandatory = $true)][string]$ExpectedExecutable,
    [Parameter(Mandatory = $true)][string]$OutputFile
)
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'Window inventory requires Windows.' }
$expectedPath = [IO.Path]::GetFullPath($ExpectedExecutable)
$targetProcess = [Diagnostics.Process]::GetProcessById($TargetPid)
try {
    $startedAt = $targetProcess.StartTime.ToUniversalTime()
    if (-not [string]::Equals($targetProcess.MainModule.FileName, $expectedPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The PID does not match the explicitly expected staged executable.'
    }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public static class WirefitWindowInventory {
    private delegate bool EnumWindow(IntPtr window, IntPtr argument);
    [DllImport("user32.dll")] private static extern bool EnumWindows(EnumWindow callback, IntPtr argument);
    [DllImport("user32.dll")] private static extern bool EnumChildWindows(IntPtr parent, EnumWindow callback, IntPtr argument);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] private static extern int GetClassName(IntPtr window, StringBuilder text, int count);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] private static extern int GetWindowText(IntPtr window, StringBuilder text, int count);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll")] private static extern IntPtr GetAncestor(IntPtr window, uint flags);
    [DllImport("kernel32.dll")] private static extern void SetLastError(uint error);
    [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern IntPtr SendMessageTimeout(IntPtr window, uint message, UIntPtr count, StringBuilder text, uint flags, uint milliseconds, out UIntPtr result);
    public sealed class Row {
        public string handle {get;set;} public string parent_handle {get;set;}
        public uint thread_id {get;set;} public uint process_id {get;set;}
        public string class_name {get;set;} public string text {get;set;}
        public bool visible {get;set;} public bool text_query_timed_out {get;set;}
        public string text_query_status {get;set;} public int? text_query_error_code {get;set;}
        public bool text_at_buffer_limit {get;set;}
    }
    public sealed class Inventory {
        public List<Row> windows {get;set;} = new List<Row>();
        public bool truncated {get;set;} = false;
    }
    public static Inventory Read(uint process) {
        var output=new Inventory();
        Func<IntPtr,IntPtr,bool> add=(window,parent)=> {
            uint owner; uint thread=GetWindowThreadProcessId(window,out owner);
            if(owner!=process) return true;
            if(output.windows.Count>=256) {output.truncated=true;return false;}
            var text=new StringBuilder(513);var name=new StringBuilder(129);
            GetClassName(window,name,name.Capacity);GetWindowText(window,text,text.Capacity);
            bool timedOut=false;string status="caption";int? error=null;
            if(text.Length==0) {
                UIntPtr length;
                SetLastError(0);
                bool succeeded=SendMessageTimeout(window,0x000D,(UIntPtr)text.Capacity,text,0x0002,20,out length)!=IntPtr.Zero;
                status=succeeded?"wm_gettext":"failed";
                if(!succeeded) {error=Marshal.GetLastWin32Error();timedOut=error==1460;}
            }
            output.windows.Add(new Row {handle="0x"+window.ToInt64().ToString("x"),
                parent_handle=parent==IntPtr.Zero?null:"0x"+GetAncestor(window,1).ToInt64().ToString("x"),
                process_id=owner,thread_id=thread,class_name=name.ToString(),text=text.ToString(),
                visible=IsWindowVisible(window),text_query_timed_out=timedOut,text_query_status=status,
                text_query_error_code=error,text_at_buffer_limit=text.Length==text.Capacity-1});
            return true;
        };
        EnumWindow top=(window,argument)=> {
            uint owner;GetWindowThreadProcessId(window,out owner);
            if(owner!=process) return true;
            if(!add(window,IntPtr.Zero)) return false;
            EnumWindow child=(control,unused)=>add(control,window);
            EnumChildWindows(window,child,IntPtr.Zero);
            return !output.truncated;
        };
        EnumWindows(top,IntPtr.Zero);
        return output;
    }
}
'@
    $inventory = [WirefitWindowInventory]::Read([uint32]$TargetPid)
    $targetProcess.Refresh()
    if ($targetProcess.HasExited -or $targetProcess.StartTime.ToUniversalTime() -ne $startedAt) {
        throw 'Target lifetime changed during window inventory; no result published.'
    }
    $receipt = [ordered]@{
        schema_version = 1
        kind = 'path_bound_window_inventory'
        observed_at = [DateTime]::UtcNow.ToString('o')
        pid = $TargetPid
        executable = $expectedPath
        process_started_at = $startedAt.ToString('o')
        scope = 'window metadata and bounded WM_GETTEXT only; no clicks or input'
        inventory = $inventory
    }
    $outputPath = [IO.Path]::GetFullPath($OutputFile)
    $stream = [IO.File]::Open($outputPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try {
        $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(($receipt | ConvertTo-Json -Depth 8) + [Environment]::NewLine)
        $stream.Write($bytes, 0, $bytes.Length)
    } finally { $stream.Dispose() }
    $receipt | ConvertTo-Json -Depth 8
} finally { $targetProcess.Dispose() }
