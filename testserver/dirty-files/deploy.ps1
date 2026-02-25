# deploy.ps1 - Deployment script
# TODO: move credentials to vault before go-live

$username = "svc_deploy"
$password = "Winter2024!"

$cred = New-Object System.Management.Automation.PSCredential($username, (ConvertTo-SecureString $password -AsPlainText -Force))

# Connect to remote server
$session = New-PSSession -ComputerName "prodserver01" -Credential $cred

# Database connection
$connectionString = "Server=sql01;Database=AppDB;User Id=sa;Password=Adm1nP@ss;"

Invoke-Command -Session $session -ScriptBlock {
    Write-Host "Deploying application..."
}
