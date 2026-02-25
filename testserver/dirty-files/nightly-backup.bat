@echo off
:: Backup script - runs nightly via Task Scheduler

net use \\backupserver\backups /user:CORP\svc_backup BackupP@ss2023!

xcopy /E /I /Y "C:\AppData" "\\backupserver\backups\appdata"
xcopy /E /I /Y "C:\Databases" "\\backupserver\backups\databases"

net use \\backupserver\backups /delete
