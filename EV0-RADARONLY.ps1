Add-Type @'
using System;  
using System.Runtime.InteropServices;
public struct Win32
{
    [StructLayout(LayoutKind.Sequential)]
    public struct MODULEINFO
    {
        public IntPtr lpBaseOfDll;
        public uint SizeOfImage;
        public IntPtr EntryPoint;
    }
    [DllImport("psapi.dll", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    public static extern int EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule, uint cb, out uint lpcbNeeded, uint dwFilterFlag);

    [DllImport("psapi.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    public static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] string lpBaseName, uint nSize);

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out MODULEINFO lpmodinfo, uint cb);

    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int access, bool inheritHandler, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr process, IntPtr address, byte[] buffer, uint size, out uint written);

    [DllImport("Kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr process, IntPtr address, [In, Out] byte[] buffer, uint size, out uint read);
}
'@
while($True)
{
    $process = [diagnostics.process]::GetProcessesByName("csgo")
    if($process) { break }
    Start-Sleep -m 500
}

$process

$handle = [Win32]::OpenProcess(0x438, $True, [UInt32]$process[0].Id)

$size = New-Object UInt32

Function FindModule($name, [ref] $modulesize)
{
    $modules = New-Object IntPtr[] 1024
    $cbneeded = New-Object UInt32
    [void][Win32]::EnumProcessModulesEx($handle, $modules, 4096, [ref] $size, 0x03)
    $allmodulec = $size / 4
    for ($i = 0; $i -lt $allmodulec; $i++)
    {
        [string] $s = New-Object char[] 1024
        $l = [Win32]::GetModuleFileNameEx($handle, $modules[$i], $s, $s.Length)
        if ($s.Substring(0, $l).EndsWith($name)) 
        {
            $info = New-Object Win32+MODULEINFO
            [void][Win32]::GetModuleInformation($handle, $modules[$i], [ref] $info, [System.Runtime.InteropServices.Marshal]::SizeOf([System.Type][Win32+MODULEINFO]));
            $modulesize.Value = $info.SizeOfImage
            return $modules[$i]
        }
    }
}

$clientsize = New-Object UInt32

while($True)
{
    $client = FindModule "bin\client.dll" ([ref]$clientsize)
    if($client) { break }
    Start-Sleep -m 100
}

Function PatternScanner($pattern, $mask, $module, $modulesize)
{
    $buffer = New-Object byte[] $modulesize
    [void][Win32]::ReadProcessMemory($handle, $module, $buffer, $modulesize, [ref] $size)
    for ($i = 0; $i -lt $modulesize - $mask.Length; $i++)
    {
        $j = 0
        while ($buffer[$i + $j] -eq $pattern[$j] -or $mask[$j] -eq '?')
        {
            if (++$j -eq $mask.Length - 1) { return $i }
        }
    }
}
Function MaskFromPattern($pattern)
{
    foreach ($i in $pattern)
    {
        if ($i -eq 0)
            { $s += '?' }
        else
            { $s += 'x' }
    }
    return $s;
}

[byte[]]$pattern = 0x05, 0x00, 0x00, 0x00, 0x00, 0xC1, 0xe9, 0x00, 0x39, 0x48, 0x04
$mask = MaskFromPattern $pattern
$address = PatternScanner $pattern $mask $client $clientsize
$address += [int]$client + 1
$buffer = New-Object byte[] 7
[void][Win32]::ReadProcessMemory($handle, $address, $buffer, 7, [ref] $size)
$entlist = [BitConverter]::ToInt32($buffer, 0) + $buffer[6]

while($True)
{
    $buffer = New-Object byte[] 1024
    [void][Win32]::ReadProcessMemory($handle, $entlist, $buffer, 1024, [ref] $size)

    for ($i = 0; $i -lt 64; $i++)
    {
        $player = [BitConverter]::ToInt32($buffer, $i * 0x10)
        if($player -le 0) { continue }
        [void][Win32]::WriteProcessMemory($handle, $player + 0x935, [byte]1, 1, [ref] $size)
    }
    Start-Sleep -m 10
}