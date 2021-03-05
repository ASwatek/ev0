######################################################################

$bhopkey = 0x20
$triggerkey = 0x04
$trdelay = 100
$afterburst = 1000
$slowaimkey = 0xA4
$slowaim = 0.3
$sleep = 1

######################################################################

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
    [DllImport("psapi.dll")]
    public static extern int EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule, uint cb, out uint lpcbNeeded, uint dwFilterFlag);

    [DllImport("psapi.dll", CharSet = CharSet.Unicode)]
    public static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] string lpBaseName, uint nSize);

    [DllImport("psapi.dll")]
    public static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out MODULEINFO lpmodinfo, uint cb);

    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int access, bool inheritHandler, uint processId);

    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr process, IntPtr address, byte[] buffer, uint size, out uint written);

    [DllImport("Kernel32.dll")]
    public static extern bool ReadProcessMemory(IntPtr process, IntPtr address, [In, Out] byte[] buffer, uint size, out uint read);

    [DllImport("user32.dll")]
    public static extern int GetKeyState(int KeyStates);
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
    $client = FindModule "bin\client.dll" ([ref] $clientsize)
    if($client) { break }
    Start-Sleep -m 100
}

Function PatternScanner($pattern, $mask, $modulesize)
{
    for ($i = 0; $i -lt $modulesize - $mask.Length; $i++)
    {
        $j = 0
        while ($module[$i + $j] -eq $pattern[$j] -or $mask[$j] -eq '?')
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

Function IsKeyDown($key)
{
    return [Convert]::ToBoolean([Win32]::GetKeyState($key) -band 0x8000)
}

$module = New-Object byte[] $clientsize
[void][Win32]::ReadProcessMemory($handle, $client, $module, $clientsize, [ref] $size)

$pattern = 0x8D, 0x34, 0x85, 0x00, 0x00, 0x00, 0x00, 0x89, 0x15, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x41, 0x08, 0x8B, 0x48
$buffer = New-Object byte[] 16
[void][Win32]::ReadProcessMemory($handle, (PatternScanner $pattern (MaskFromPattern $pattern) $clientsize) + [int]$client + 3, $buffer, 16, [ref] $size)
$local = [BitConverter]::ToInt32($buffer, 0) + $buffer[15]
$pattern = 0xA1, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x89, 0x35, 0x00, 0x00, 0x00, 0x00, 0x8D, 0xB7, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x08
$buffer = New-Object byte[] 4
[void][Win32]::ReadProcessMemory($handle, (PatternScanner $pattern (MaskFromPattern $pattern) $clientsize) + [int]$client + 1, $buffer, 4, [ref] $size)
$glowbase = [BitConverter]::ToInt32($buffer, 0)
$pattern = 0x89, 0x15, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x15, 0x00, 0x00, 0x00, 0x00, 0xF6, 0xC2, 0x03, 0x74, 0x03, 0x83, 0xCE, 0x04, 0xA8, 0x04, 0xBF, 0xFD, 0xFF, 0xFF, 0xFF
[void][Win32]::ReadProcessMemory($handle, (PatternScanner $pattern (MaskFromPattern $pattern) $clientsize) + [int]$client + 2, $buffer, 4, [ref] $size)
$attack = [BitConverter]::ToInt32($buffer, 0)
$pattern = 0x56, 0x57, 0x8B, 0xF9, 0xC7, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x0D
[void][Win32]::ReadProcessMemory($handle, (PatternScanner $pattern (MaskFromPattern $pattern) $clientsize) + [int]$client + 6, $buffer, 4, [ref] $size)
$incross = [BitConverter]::ToInt32($buffer, 0)
$pattern = 0x89, 0x15, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x15, 0x00, 0x00, 0x00, 0x00, 0xF6, 0xC2, 0x03, 0x74, 0x03, 0x83, 0xCE, 0x08, 0xA8, 0x08, 0xBF, 0xFD, 0xFF, 0xFF, 0xFF
[void][Win32]::ReadProcessMemory($handle, (PatternScanner $pattern (MaskFromPattern $pattern) $clientsize) + [int]$client + 2, $buffer, 4, [ref] $size)
$jump = [BitConverter]::ToInt32($buffer, 0)
$pattern = 0x7A, 0x2C,0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x81, 0xF9, 0x00, 0x00, 0x00, 0x00, 0x75, 0x0A,0xF3, 0x0F, 0x10, 0x05, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x0F, 0x8B, 0x01,0x8B, 0x40, 0x00,0xFF, 0xD0
[void][Win32]::ReadProcessMemory($handle, (PatternScanner $pattern (MaskFromPattern $pattern) $clientsize) + [int]$client + 20, $buffer, 4, [ref] $size)
$sensitivity = [BitConverter]::ToInt32($buffer, 0)
Remove-Variable pattern
Remove-Variable module

Function GetColor([float]$r, [float]$g, [float]$b, [float]$a)
{
    $color = New-Object byte[] 16
    [Array]::Copy([BitConverter]::GetBytes($r), 0, $color, 0, 4)
    [Array]::Copy([BitConverter]::GetBytes($g), 0, $color, 0x4, 4)
    [Array]::Copy([BitConverter]::GetBytes($b), 0, $color, 0x8, 4)
    [Array]::Copy([BitConverter]::GetBytes($a), 0, $color, 0xC, 4)
    return $color
}

$sens = New-Object byte[] 4
[void][Win32]::ReadProcessMemory($handle, $sensitivity, $sens, 4, [ref] $size)
$ssens = [BitConverter]::GetBytes([float]([BitConverter]::ToSingle($sens, 0) * $slowaim))
$trdelay *= 1000
$afterburst *= 1000
$glowobj = New-Object byte[] 0x34
$glowon = 0x01, 0x00
$color = New-Object byte[] 16
$teamc = GetColor 0 1 0 0.7
$dormantc = GetColor 0.2 0.2 0.2 0.9
$enemylowc = GetColor 1 0 0 1
$enemyc = GetColor 0.5 0 0.5 1
$buffer = New-Object byte[] 8
$localplayer = New-Object byte[] 0x9D
$player = New-Object byte[] 0x99
$plocal = New-Object byte[] 4
$targetb = New-Object byte[] 4


while($True)
{
    [void][Win32]::ReadProcessMemory($handle, $local, $plocal, 4, [ref] $size)
    $localptr = [BitConverter]::ToInt32($plocal, 0)
    if($localptr -ne 0)
    {
        $notrigger = $noslow = $True
		[void][Win32]::ReadProcessMemory($handle, $localptr + 0x64, $localplayer, 0x9D, [ref] $size)
        if(IsKeyDown $bhopkey)
        {
            if($localplayer[0x9C] -eq 0)
            {
                [void][Win32]::WriteProcessMemory($handle, $jump, 0, 1, [ref] $size)
                $jumpoff = $True
            }
            elseif($jumpoff)
            {
                [void][Win32]::WriteProcessMemory($handle, $jump, 1, 1, [ref] $size)
                $jumpoff = $False                
            }
        }
        [void][Win32]::ReadProcessMemory($handle, $localptr + $incross, $targetb, 4, [ref] $size)
        $target = [BitConverter]::ToInt32($targetb, 0)

        [void][Win32]::ReadProcessMemory($handle, $glowbase, $buffer, 8, [ref] $size)
        $glow = [BitConverter]::ToInt32($buffer, 0)
        $glowslength = [BitConverter]::ToInt32($buffer, 4) * 0x34
        $glows = New-Object byte[] $glowslength
        [void][Win32]::ReadProcessMemory($handle, $glow, $glows, $glowslength, [ref] $size)
        for ($i = 0; $i -lt $glowslength; $i+=0x34)
        {
            $ent = [BitConverter]::ToInt32($glows, $i)
            if($ent -eq 0 -or $ent -eq $localptr) { continue }
            [void][Win32]::ReadProcessMemory($handle, $ent + 0x64, $player, 0x99, [ref] $size)
            $id = [BitConverter]::ToInt32($player, 0)
            if($id -lt 1 -or $player[0x8C] -eq 0) { continue }
            elseif($player[0x8C] -eq $localplayer[0x8C] -and ($player[0x98] -ne 0 -or $id -gt 63))
            {
                $color = $teamc
            }
            else
            {
                if ($player[0x98] -ne 0) 
                {
                    if($player[0x85] -eq 1)
                    {
                        $color = $dormantc
                    }
                    else
                    {
                        [void][Win32]::WriteProcessMemory($handle, $ent + 0x935, 1, 1, [ref] $size)
                        if($id -eq $target)
                        {
                            if (IsKeyDown $triggerkey) { $notrigger = $False }
                            if (IsKeyDown $slowaimkey) { $noslow = $False }
                        }
                        if($player[0x98] -lt 25)
                        {
                            $color = $enemylowc
                        }
                        else
                        {
                            $color = $enemyc
                        }
                    }
                }
                elseif($id -gt 63)
                {
                    $color = $enemylowc
                }
                else { continue }
            }

            $diff = $False
            for($j = 0; $j -lt 16; $j++)
            {
                if($color[$j] -ne $glows[$i + $j])
                {
                    $diff = $True
                    break
                }
            }
            if($diff)
            {
                [void][Win32]::WriteProcessMemory($handle, $glow + $i + 0x4, $color, 16, [ref] $size)
                [void][Win32]::WriteProcessMemory($handle, $glow + $i + 0x24, $glowon, 2, [ref] $size)
            }
        }

        if($notrigger)
        {
            if($attackon -and -not $afterb)
            {
                $trend = [DateTime]::Now.Ticks + $afterburst
                $afterb = $True
            }
            if($afterb -and $trend -le [DateTime]::Now.Ticks)
            {
                [void][Win32]::WriteProcessMemory($handle, $attack, 0, 1, [ref] $size)
                $attackon = $afterb = $False
            }
            $delayb = $True
        }
        else
        {
            if($delayb)
            {
                $trstart = [DateTime]::Now.Ticks + $trdelay
                $delayb = $False
            }
            if(-not $attackon -and $trstart -lt [DateTime]::Now.Ticks)
            {
                [void][Win32]::WriteProcessMemory($handle, $attack, 1, 1, [ref] $size)
                $attackon = $True
            }
        }
        if($noslow -and $slowon)
        {
            [void][Win32]::WriteProcessMemory($handle, $sensitivity, $sens, 4, [ref] $size)
            $slowon = $False
        }
        elseif(-not ($noslow -or $slowon))
        {
            [void][Win32]::WriteProcessMemory($handle, $sensitivity, $ssens, 4, [ref] $size)
            $slowon = $True
        }
    }
    Start-Sleep -m $sleep
}