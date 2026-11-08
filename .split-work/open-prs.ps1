$ErrorActionPreference = 'Stop'
$credentialRequest = "protocol=https`nhost=github.com`n`n"
$credentialLines = $credentialRequest | git credential fill
if ($LASTEXITCODE -ne 0) { throw 'GitHub Git authentication was unavailable.' }
$passwordEntry = @($credentialLines | Where-Object { $_.StartsWith('password=') })
if ($passwordEntry.Count -ne 1) { throw 'GitHub Git authentication returned no usable credential.' }
$githubToken = $passwordEntry[0].Substring(9)
$headers = @{
    Authorization = 'Bearer ' + $githubToken
    Accept = 'application/vnd.github+json'
    'X-GitHub-Api-Version' = '2022-11-28'
    'User-Agent' = 'AutoSprings-library-split'
}

function Open-SplitPullRequest([string]$repository, [string]$payloadFile) {
    $payload = Get-Content -LiteralPath $payloadFile -Raw | ConvertFrom-Json
    $headQuery = [Uri]::EscapeDataString('AutoSprings:' + $payload.head)
    $existing = Invoke-RestMethod -Headers $headers -Uri "https://api.github.com/repos/AutoSprings/$repository/pulls?state=open&head=$headQuery"
    if ($existing.Count -gt 0) { return $existing[0] }
    return Invoke-RestMethod -Method Post -Headers $headers -ContentType 'application/json' -Uri "https://api.github.com/repos/AutoSprings/$repository/pulls" -Body ($payload | ConvertTo-Json -Depth 10)
}

$authPr = Open-SplitPullRequest 'AutoAuth' (Join-Path $PSScriptRoot 'auth-pr.json')
if (-not $authPr.html_url) { throw 'AutoAuth pull request did not return a URL.' }
Write-Output ('AutoAuth: ' + $authPr.html_url)
$limitPayloadFile = Join-Path $PSScriptRoot 'limit-pr-ready.json'
$limitPayload = Get-Content -LiteralPath $limitPayloadFile -Raw | ConvertFrom-Json
$limitPayload.body = $limitPayload.body.Replace('https://github.com/AutoSprings/AutoAuth/tree/split/authentication-only', $authPr.html_url)
$limitPayload | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $limitPayloadFile -Encoding UTF8
$limitPr = Open-SplitPullRequest 'AutoLimit' $limitPayloadFile
if (-not $limitPr.html_url) { throw 'AutoLimit pull request did not return a URL.' }
Write-Output ('AutoLimit: ' + $limitPr.html_url)
$authPayload = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'auth-pr.json') -Raw | ConvertFrom-Json
$authBody = $authPayload.body.Replace('https://github.com/AutoSprings/AutoLimit/tree/split/independent-library', $limitPr.html_url)
$null = Invoke-RestMethod -Method Patch -Headers $headers -ContentType 'application/json' -Uri "https://api.github.com/repos/AutoSprings/AutoAuth/pulls/$($authPr.number)" -Body (@{body=$authBody} | ConvertTo-Json)
@{
    autoauth = @{ url=$authPr.html_url; number=$authPr.number; sha=$authPr.head.sha }
    autolimit = @{ url=$limitPr.html_url; number=$limitPr.number; sha=$limitPr.head.sha }
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'pr-results.json') -Encoding UTF8
