Install-Module -Name VMware.PowerCLI -Scope AllUsers -AllowClobber

Get-PowerCLIConfiguration
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore




Get-AlarmDefinition -PipelineVariable alarm | `
ForEach-Object -Process {

    Get-AlarmAction -AlarmDefinition $_ -PipelineVariable action |
    ForEach-Object -Process {
        Get-AlarmActionTrigger -AlarmAction $_ |
        select @{N='Alarm';E={$alarm.Name}},
            @{N='Description';E={$alarm.Description}},
            @{N='Enabled';E={$alarm.Enabled}},
            @{N='Last Modified';E={$alarm.ExtensionData.Info.LastModifiedTime}},
            @{N='Last Modified By';E={$alarm.ExtensionData.Info.LastModifiedUser}},
            @{N='Entity';E={$alarm.Entity}},
            @{N='Expression';E={
                ($alarm.ExtensionData.Info.Expression.Expression |
                ForEach-Object -Process {"{0} ({1}) - {2} - {3}" -f $_.EventType,
                                                                    $_.EventTypeId,
                                                                    $_.ObjectType,
                                                                    ([VMware.Vim.ManagedEntityStatus]$_.Status.value__)}) -join '|'
            }},
            @{N='Trigger';E={
                "{0}:{1}->{2} (Repeat={3})" -f $action.ActionType,
                                               $_.StartStatus,
                                               $_.EndStatus,
                                               $_.Repeat
            }},
            @{N='To';E={if ($action.ActionType -eq 'SendEmail') {$action.To}}},
            @{N='CC';E={if ($action.ActionType -eq 'SendEmail') {$action.CC}}},
            @{N='Subject';E={if ($action.ActionType -eq 'SendEmail') {$action.Subject}}},
            @{N='Body';E={if ($action.ActionType -eq 'SendEmail') {$action.Body}}}
    }

} | Export-Csv -Path .\report.csv -NoTypeInformation -UseCulture
