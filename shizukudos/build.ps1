param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'build'),
    [switch]$HistoricalFixture
)

$ErrorActionPreference = 'Stop'
if (-not $HistoricalFixture) {
    if ($env:OS -eq 'Windows_NT') {
        throw 'The current DOS10 source build requires the Linux toolchain. Use WSL/Linux: python3 shizukudos/tools/shz.py build. The retired 0.1 fixture is opt-in.'
    }
    $currentPython = (Get-Command python3 -ErrorAction Stop).Source
    & $currentPython (Join-Path $PSScriptRoot 'tools/shz.py') build --profile dos10
    if ($LASTEXITCODE -ne 0) { throw 'DOS10 build failed.' }
    return
}
$assembler = (Get-Command nasm -ErrorAction Stop).Source
$python = (Get-Command python -ErrorAction Stop).Source
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$boot = Join-Path $OutputDirectory 'boot.bin'
$stage2 = Join-Path $OutputDirectory 'stage2.bin'
$demo = Join-Path $OutputDirectory 'demo.com'
$retDemo = Join-Path $OutputDirectory 'ret.com'
$stdDemo = Join-Path $OutputDirectory 'std.com'
$image = Join-Path $OutputDirectory 'shizukudos.img'
& $assembler -f bin (Join-Path $PSScriptRoot 'boot.asm') -o $boot
if ($LASTEXITCODE -ne 0) { throw 'Failed to assemble boot sector.' }
& $assembler -f bin '-I' "$PSScriptRoot/" (Join-Path $PSScriptRoot 'stage2.asm') -o $stage2
if ($LASTEXITCODE -ne 0) { throw 'Failed to assemble stage2.' }
& $assembler -f bin (Join-Path $PSScriptRoot 'tests\demo_com.asm') -o $demo
if ($LASTEXITCODE -ne 0) { throw 'Failed to assemble demo COM program.' }
& $assembler -f bin (Join-Path $PSScriptRoot 'tests\ret_com.asm') -o $retDemo
if ($LASTEXITCODE -ne 0) { throw 'Failed to assemble near-RET COM program.' }
& $assembler -f bin (Join-Path $PSScriptRoot 'tests\std_com.asm') -o $stdDemo
if ($LASTEXITCODE -ne 0) { throw 'Failed to assemble STD COM program.' }
& $python (Join-Path $PSScriptRoot 'build_image.py') --historical-fixture $boot $stage2 $image --demo $demo --ret-demo $retDemo --std-demo $stdDemo
if ($LASTEXITCODE -ne 0) { throw 'Failed to build FAT12 image.' }
Write-Output $image
