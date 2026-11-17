param(
  [Parameter(Mandatory = $true)][string]$Output,
  [ValidateSet('Pilot', 'Main')][string]$Mode = 'Main',
  [switch]$KeepStack
)

$ErrorActionPreference = 'Stop'

function Invoke-Checked {
  param([string]$Program, [string[]]$Arguments)
  & $Program @Arguments
  if ($LASTEXITCODE -ne 0) { throw "$Program failed (exit $LASTEXITCODE)" }
}

function New-LocalSecret {
  return [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
}

$repo = Split-Path -Parent $PSScriptRoot
$outputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Output)
$separator = [IO.Path]::DirectorySeparatorChar
if ($outputPath.TrimEnd($separator) -eq $repo -or $outputPath.StartsWith($repo + $separator, [StringComparison]::OrdinalIgnoreCase)) {
  throw 'Choose an output directory outside the repository'
}
if (Test-Path -LiteralPath $outputPath) { throw "Output directory already exists: $outputPath" }

Push-Location -LiteralPath $repo
try {
  if (Invoke-Checked git @('status', '--porcelain')) { throw 'Run from a clean clone of the measurement tag' }
  Invoke-Checked docker @('version', '--format', '{{.Server.Version}}')
  New-Item -ItemType Directory -Path $outputPath | Out-Null
  Invoke-Checked npm @('ci', '--no-audit', '--no-fund')

  $pilot = $Mode -eq 'Pilot'
  $sessions = if ($pilot) { 1 } else { 5 }
  $env:BENCH_ITER = if ($pilot) { '5' } else { '100' }
  $env:BENCH_WARMUP = if ($pilot) { '3' } else { '10' }
  for ($session = 1; $session -le $sessions; $session++) {
    $env:BENCH_SESSION = "$session"
    $env:BENCH_OUTPUT = Join-Path $outputPath "session-$session"
    Invoke-Checked npm -Arguments @('run', 'benchmark:final', '--', '--evaluation')
  }

  $project = 'klt-eval-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
  $env:BENCH_COMPOSE_PROJECT = $project
  $env:CREDENTIAL_IMAGE = "${project}:local"
  $env:POSTGRES_PASSWORD = New-LocalSecret
  $env:MASTER_KMS_KEY = New-LocalSecret
  $env:WALLET_STORAGE_KEY = New-LocalSecret
  $env:SESSION_SECRET = New-LocalSecret
  $env:RECEIPT_SECRET = New-LocalSecret
  $env:DEMO_PASSWORD = New-LocalSecret
  $env:ISSUER_BIND_PORT = '18041'
  $env:VERIFIER_BIND_PORT = '18042'
  $env:WALLET_BIND_PORT = '18040'
  $env:POSTGRES_BIND_PORT = '15432'
  $env:REDIS_BIND_PORT = '6379'
  $env:ISSUER_PUBLIC_URL = 'http://localhost:18041'
  $env:VERIFIER_PUBLIC_URL = 'http://localhost:18042'
  $env:COMPOSE_WALLET_URL = 'http://localhost:18040'
  $env:STATUS_CACHE_MODE = 'ETAG_REVALIDATE'

  try {
    Invoke-Checked docker @('compose', '-p', $project, 'up', '--build', '-d', '--wait')
    $env:BENCH_OUTPUT = Join-Path $outputPath 'stack'
    $env:BENCH_CONCURRENCY = if ($pilot) { '1,5' } else { '1,5,20,50' }
    $env:BENCH_BATCHES = if ($pilot) { '2' } else { '10' }
    Invoke-Checked npm -Arguments @('exec', '--', 'tsx', 'src/evaluation/http.ts')

    $evidence = New-Item -ItemType Directory -Path (Join-Path $outputPath 'checks')
    $report = Join-Path $evidence.FullName 'vitest.json'
    Invoke-Checked npm @('run', 'typecheck') | Tee-Object -FilePath (Join-Path $evidence.FullName 'typecheck.txt')
    Invoke-Checked npm -Arguments @('run', 'test', '--', '--reporter=json', "--outputFile=$report")

    # Recreate only the disposable project's data before the lifecycle checks.
    Invoke-Checked docker @('compose', '-p', $project, 'down', '--volumes')
    Invoke-Checked docker @('compose', '-p', $project, 'up', '-d', '--wait')
    Invoke-Checked npm -Arguments @('run', 'check:compose', '--', 'before-recreate') |
      Tee-Object -FilePath (Join-Path $evidence.FullName 'before-recreate.txt')
    Invoke-Checked docker @('compose', '-p', $project, 'up', '-d', '--force-recreate', '--no-deps', '--wait', 'issuer-service', 'wallet-pwa')
    Invoke-Checked npm -Arguments @('run', 'check:compose', '--', 'after-recreate') |
      Tee-Object -FilePath (Join-Path $evidence.FullName 'after-recreate.txt')
  } catch {
    & docker compose -p $project logs --tail 60 2>&1 |
      Out-File -LiteralPath (Join-Path $outputPath 'compose-failure.txt') -Encoding utf8
    throw
  } finally {
    if ($KeepStack) {
      Write-Host "Retained disposable project $project"
    } else {
      Invoke-Checked docker @('compose', '-p', $project, 'down', '--volumes')
    }
  }
  Invoke-Checked python @('scripts/summarize-evaluation.py', $outputPath, (Join-Path $outputPath 'summary'))
} finally {
  Pop-Location
}
