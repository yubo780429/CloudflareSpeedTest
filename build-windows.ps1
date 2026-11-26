$ErrorActionPreference = 'Stop'
$env:CGO_ENABLED = '0'
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'

$goVersion = (& go version 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { throw "无法执行 Go：$goVersion" }
if ($goVersion -notmatch 'go1\.(\d+)') { throw "无法识别 Go 版本：$goVersion" }
if ([int]$Matches[1] -lt 26) {
    throw "本项目依赖 quic-go v0.66.0，需要 Go 1.26 或更新版本。当前：$goVersion"
}

Write-Host "Using $goVersion"
go mod tidy
if ($LASTEXITCODE -ne 0) { throw "go mod tidy 失败，退出码：$LASTEXITCODE" }
go build -trimpath -ldflags "-s -w" -o cfst-dualbench-windows-amd64.exe .
if ($LASTEXITCODE -ne 0) { throw "go build 失败，退出码：$LASTEXITCODE" }
Write-Host "Build completed: $PWD\cfst-dualbench-windows-amd64.exe" -ForegroundColor Green
