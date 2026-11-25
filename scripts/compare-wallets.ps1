param([Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference = 'Stop'
$result = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Output)
if ((Test-Path $result) -or !(Test-Path (Split-Path $result) -PathType Container)) {
  throw 'Choose a new result filename in an existing directory.'
}
$project = 'wallet-eval-' + [guid]::NewGuid().ToString('N').Substring(0,12)
Push-Location (Split-Path $PSScriptRoot -Parent)
$started = $false
try {
  docker version --format '{{.Server.Version}}'
  if ($LASTEXITCODE) { throw 'Docker Linux engine is unavailable.' }
  $env:WALLET_BENCH_PROJECT = $project
  $env:CREDENTIAL_IMAGE = "${project}:local"
  foreach ($key in 'POSTGRES_PASSWORD','DEMO_PASSWORD','SESSION_SECRET','RECEIPT_SECRET','MASTER_KMS_KEY','WALLET_STORAGE_KEY') {
    Set-Item "env:$key" ([guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N'))
  }
  $env:ISSUER_BIND_PORT='18441'
  $env:VERIFIER_BIND_PORT='18442'
  $env:WALLET_BIND_PORT='18440'
  $env:REDIS_BIND_PORT='18443'
  $env:POSTGRES_BIND_PORT='18444'
  $env:ISSUER_PUBLIC_URL='http://localhost:18441'
  $env:VERIFIER_PUBLIC_URL='http://localhost:18442'
  $env:STATUS_CACHE_MODE='ETAG_REVALIDATE'
  $started = $true
  docker compose -p $project up --build -d --wait
  if ($LASTEXITCODE) { throw 'Benchmark stack failed to start.' }
  node scripts/compare-wallets.mjs $result
  if ($LASTEXITCODE) { throw 'Measurement failed.' }
} finally {
  if ($started) { docker compose -p $project down -v }
  Pop-Location
}
