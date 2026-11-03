[CmdletBinding()]
param(
    [ValidateSet('x86', 'amd64', 'all')]
    [string]$Architecture = 'all',
    [string]$Python = 'python'
)
$ErrorActionPreference = 'Stop'
$fixtureRoot = Split-Path -Parent $PSScriptRoot
$targets = if ($Architecture -eq 'all') { @('x86', 'amd64') } else { @($Architecture) }

function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Program failed with exit code $LASTEXITCODE"
    }
}

Push-Location -LiteralPath $fixtureRoot
try {
    foreach ($arch in $targets) {
        Invoke-Checked 'cmake' @('--preset', $arch)
        Invoke-Checked 'cmake' @('--build', '--preset', $arch, '--clean-first')
        $report = Join-Path $fixtureRoot "build/$arch/verification.xml"
        Invoke-Checked 'ctest' @('--preset', $arch, '--output-junit', $report)
        Invoke-Checked 'cmake' @('--install', "build/$arch", '--config', 'Release',
                                 '--prefix', (Join-Path $fixtureRoot 'bin'))
        Invoke-Checked $Python @('scripts/manifest.py', '--architecture', $arch,
                                 '--test-report', $report)
    }
} finally {
    Pop-Location
}
