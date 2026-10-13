
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function New-RandomBytes([int]$Count) {
    $bytes = New-Object 'System.Byte[]' $Count
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) }
    finally { $rng.Dispose() }
    return ,$bytes
}

function ConvertTo-Hex([byte[]]$Bytes) {
    return ([System.BitConverter]::ToString($Bytes)).Replace('-', '').ToLowerInvariant()
}

function Assert-Success([string]$Step) {
    if ($LASTEXITCODE -ne 0) { throw "$Step failed (exit code $LASTEXITCODE)." }
}

Write-Host '=== ZPR-2: Windows startup ===' -ForegroundColor Cyan
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker not found. Start Docker Desktop and try again.'
}
docker info --format '{{.ServerVersion}}' | Out-Null
Assert-Success 'Docker Engine check'

if (-not (Test-Path -LiteralPath '.env')) {
    $jwt = ConvertTo-Hex (New-RandomBytes 32)
    $blind = ConvertTo-Hex (New-RandomBytes 32)
    $fernet = [Convert]::ToBase64String((New-RandomBytes 32)).Replace('+','-').Replace('/','_')
    $admin = ConvertTo-Hex (New-RandomBytes 12)
    $teacher = ConvertTo-Hex (New-RandomBytes 12)
    $student = ConvertTo-Hex (New-RandomBytes 12)

    $envLines = @(
        "JWT_SECRET_KEY=$jwt"
        "ENCRYPTION_KEY=$fernet"
        "BLIND_INDEX_KEY=$blind"
        "SEED_ADMIN_PASSWORD=$admin"
        "SEED_TEACHER_PASSWORD=$teacher"
        "SEED_STUDENT_PASSWORD=$student"
    )
    $envLines | Set-Content -LiteralPath '.env' -Encoding Ascii
    @("admin: $admin", "teacher: $teacher", "student: $student") |
        Set-Content -LiteralPath 'LOCAL_TEST_PASSWORDS.txt' -Encoding Ascii
    Write-Host 'Private .env and LOCAL_TEST_PASSWORDS.txt created.' -ForegroundColor Green
} else {
    Write-Host 'Existing .env found; keeping its keys unchanged.' -ForegroundColor Yellow
}

$required = @('JWT_SECRET_KEY','ENCRYPTION_KEY','BLIND_INDEX_KEY','SEED_ADMIN_PASSWORD','SEED_TEACHER_PASSWORD','SEED_STUDENT_PASSWORD')
$envText = Get-Content -LiteralPath '.env'
foreach ($name in $required) {
    if (-not ($envText | Where-Object { $_ -match ('^' + [regex]::Escape($name) + '=.+$') })) {
        throw "Missing $name in .env. Do not delete .env if you already have encrypted data."
    }
}

New-Item -ItemType Directory -Force -Path 'nginx/certs', 'data' | Out-Null
if (-not (Test-Path -LiteralPath 'nginx/certs/selfsigned.crt') -or
    -not (Test-Path -LiteralPath 'nginx/certs/selfsigned.key')) {
    Write-Host 'Generating a self-signed HTTPS certificate...'
    $certDir = (Resolve-Path -LiteralPath 'nginx/certs').Path
    docker run --rm --mount "type=bind,source=$certDir,target=/certs" alpine/openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /certs/selfsigned.key -out /certs/selfsigned.crt -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
    Assert-Success 'Certificate generation'
}

Write-Host 'Building and starting Docker services...'
docker compose up -d --build
Assert-Success 'Docker Compose startup'

Write-Host 'Running database migrations...'
docker compose exec -T api alembic upgrade head
Assert-Success 'Alembic migration'

Write-Host 'Creating test accounts...'
docker compose exec -T api python -m app.seed
Assert-Success 'Database seed'

Write-Host ''
Write-Host '=== Startup completed ===' -ForegroundColor Green
Write-Host 'Swagger: https://localhost/docs'
Write-Host 'Test passwords: LOCAL_TEST_PASSWORDS.txt (PRIVATE; do not upload)'
docker compose ps

