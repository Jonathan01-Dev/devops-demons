param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("A", "B")]
    [string]$Role,

    [string]$ExePath = "python main.py",
    [int]$Port = 9001
)

$ErrorActionPreference = "Stop"

function Invoke-Archipel {
    param([string]$Args)
    if ($ExePath -eq "python main.py") {
        Invoke-Expression "$ExePath $Args"
    } else {
        & $ExePath $Args.Split(" ")
    }
}

$keysDir = ".keys-$($Role.ToLower())"
$trustDb = ".archipel/trust-$($Role.ToLower()).json"

Write-Host "[node-$Role] generating keys..."
Invoke-Archipel "keygen --out-dir $keysDir"

Write-Host "[node-$Role] opening firewall on TCP $Port..."
netsh advfirewall firewall add rule name="Archipel S2 $Port" dir=in action=allow protocol=TCP localport=$Port | Out-Null

Write-Host "[node-$Role] starting secure server on 0.0.0.0:$Port ..."
Invoke-Archipel "s2-server --host 0.0.0.0 --port $Port --keys-dir $keysDir --trust-db $trustDb"

