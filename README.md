# PendingFileRenameOperations + Junctions EDR Disable

Credit goes to [sixtyvividtails](https://x.com/sixtyvividtails) for the ideas demonstrated.

PendingFileRenameOperations allows applications to create file rename operations by creating a registry entry under the `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager`. Initially I attempted to create this entry, pointing it towards the EDR binary as such in PowerShell, based on the StackOverflow thread https://superuser.com/questions/1700602/using-powershell-to-add-an-entry-to-pendingfilerenameoperations-without-disrup.

```powershell
new-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -Value $($((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations) + "\??\C:\Program Files\<EDR_PATH>.exe`0`0") -type MultiString -Force | Out-Null
```

This works for AVs/EDRs without anti-tampering. Security products with anti-tampering can use [CmRegisterCallbackEx](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-cmregistercallbackex) to monitor and block registry operations from the kernel. A kernel driver could block registry keys from being created if they referenced their core services.

Using a reparse point (junction) - kudos again to sixtyvividtails - we can create a junction from:

`C:\program-files` -> `C:\Program Files\` 

And yet again we can create our `PendingFileRenameOperations`, pointing the key at the EDR binary pathed through our junction, something that most EDRs do not check. All of this of course requires Admin privileges. On the next reboot, any core EDR binaries will be renamed to "", in turn being deleted.

## Credit

- https://x.com/sixtyvividtails
- https://superuser.com/questions/1700602/using-powershell-to-add-an-entry-to-pendingfilerenameoperations-without-disrup
- https://learn.microsoft.com/en-us/sysinternals/downloads/junction

