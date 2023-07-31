$oldEmail = 'Support@PathForwardIT.com'
$newEmail = 'pfitalerts@pathforwardit.com'

foreach ($alarm in Get-AlarmDefinition){
    $action = Get-AlarmAction -AlarmDefinition $alarm
    $mail = $action | Where-Object {$_.ActionType -eq 'SendEmail' -and $_.To -contains $oldEmail}

    Remove-AlarmAction -AlarmAction $mail -Confirm:$false
    New-AlarmAction -AlarmDefinition $alarm -Email -To $newEmail -Subject $mail.Subject -Confirm:$false

}

