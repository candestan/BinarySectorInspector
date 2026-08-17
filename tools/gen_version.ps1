param(
    [Parameter(Mandatory = $true)][string]$Repo,
    [Parameter(Mandatory = $true)][string]$Out
)

$ErrorActionPreference = "Continue"
$repo = $Repo.TrimEnd("\", "/")

function GitOut([string[]]$gitArgs) {
    $old = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    $o = & git -C $repo @gitArgs 2>$null
    $code = $LASTEXITCODE
    $ErrorActionPreference = $old
    $text = ""
    if ($null -ne $o) {
        if ($o -is [array]) { $text = ($o -join "`n") }
        else { $text = [string]$o }
    }
    return @{ Code = $code; Text = $text.Trim() }
}

$commit = (GitOut @("rev-parse", "HEAD")).Text
$short = (GitOut @("rev-parse", "--short=9", "HEAD")).Text
$count = (GitOut @("rev-list", "--count", "HEAD")).Text
$diff = GitOut @("diff-index", "--quiet", "HEAD", "--")

if (-not $commit) { $commit = "unknown" }
if (-not $short) { $short = "unknown" }
if (-not ($count -match '^\d+$')) { $count = "0" }

$dirty = 0
if ($diff.Code -ne 0) { $dirty = 1 }

$time = Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz"

$utf8 = New-Object System.Text.UTF8Encoding $false
$lines = @(
    "#pragma once",
    "#define BSI_BUILD_NUMBER $count",
    "#define BSI_GIT_COMMIT `"$commit`"",
    "#define BSI_GIT_COMMIT_SHORT `"$short`"",
    "#define BSI_GIT_DIRTY $dirty",
    "#define BSI_BUILD_TIME `"$time`"",
    "#define BSI_VERSION_DOTTED `"1.0.0.$count`""
)
$content = ($lines -join "`r`n") + "`r`n"
[System.IO.File]::WriteAllText($Out, $content, $utf8)
exit 0
