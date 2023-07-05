$modules = 'Microsoft.graph','ExchangeOnlineManagement', 'MicrosoftTeams','Microsoft.Online.SharePoint.PowerShell'
$installed = @((Get-Module $modules -ListAvailable).Name | Select-Object -Unique)
$notInstalled = Compare-Object $modules $installed -PassThru

if ($notInstalled) { # At least one module is missing.

  # Prompt for installing the missing ones.
  $promptText = @"
  The following modules aren't currently installed:
  
$($notInstalled -join "`n")
  
  Would you like to install them now?
"@

  $choice = Read-Host -Prompt $promptText
  
  if ($choice -ne 'Y') { Write-Warning 'Aborted.'; exit 1 }
  
  # Install the missing modules now.
  Install-Module $notInstalled -Scope CurrentUser -AllowClobber -Force
}

Import-Module $modules


$RequiredScopes = @("DeviceManagementApps.ReadWrite.All", "User.ReadWrite.All","Application.ReadWrite.All", "Group.ReadWrite.All", "Policy.ReadWrite.ConditionalAccess", "DeviceManagementConfiguration.ReadWrite.All", "DeviceManagementServiceConfig.ReadWrite.All","Directory.Read.All","Directory.ReadWrite.All","RoleManagement.Read.Directory","RoleManagement.ReadWrite.Directory", "UserAuthenticationMethod.ReadWrite.All","Policy.ReadWrite.Authorization","EntitlementManagement.ReadWrite.All","Policy.ReadWrite.AuthenticationFlows","Policy.Read.All")

Connect-MgGraph -Scopes $RequiredScopes
$IntuneServicePrincipal = "d4ebce55-015a-49b5-a083-c84d1797ae8c"
$ServiceIDCheck = Get-MgServicePrincipal -Filter "APPID eq '$IntuneServicePrincipal'"
if ($null -eq $ServiceIDCheck) {
  New-MgServicePrincipal -AppId $IntuneServicePrincipal

            Write-Host "Created Intune Service Principal"
        } else {
            Write-Host "Skipped Intune Service Principal because it already exists."
        }

$StandardCAGroups= @(
    "SG365_Exclude_CA001: Require multi-factor authentication for admins",
    "SG365_Exclude_CA002: Default Block - Travel Users Exclusion",
    "SG365_Exclude_CA003: Block legacy authentication",
    "SG365_Exclude_CA004: Require multi-factor authentication for allusers_Restricted",
    "SG365_Exclude_CA005: Require multi-factor authentication for guest access",
    "SG365_Exclude_CA006: Require multi-factor authentication for Azure management",
    "SG365_Exclude_CA009: Require compliant or hybrid Azure AD joined device for admins_Restricted",
    "SG365_Exclude_CA009.5: Require Compliant Device - Windows Devices_Restricted",
    "SG365_Exclude_CA009.6: Require Compliant Device - MacOS_Testing-Only",
    "SG365_Exclude_CA009.7: Require Compliant Device - IOS-Android_Testing-Only",
    "SG365_Exclude_CA009.8: Require Compliant Device - Linux_Testing-Only",
    "SG365_Exclude_CA010: Block access for unknown or unsupported device platform",
    "SG365_Exclude_CA011: Require Intune Mobile Device App Protection Policy",
    "SG365_Exclude_CA012: Block MFA Enrollment from Non Trusted Locations",
    "SG365_Exclude_CA013: Email Encryption External User Access",
    "SG365_Exclude_CA014: Default Block - Travel Policy"
    
)
ForEach ($Group in $StandardCAGroups){
   # check if group exists
   $GroupCheck = Get-MgGroup -Filter "displayName eq '$group'"
   #$GroupCheck = get-mggroup -Property Displayname | Where-Object DisplayName eq $($Group) 
  
   #if not exists then create it
  If(!$GroupCheck){
      $params = @{
         Description = "standard CA exclusion group"
         DisplayName = "$Group"
         MailEnabled = $false
         MailNickname = (Get-Random)
         SecurityEnabled = $true
      }
      New-MgGroup -BodyParameter $params | Out-Null
        Write-Host "$Group was created"
    }else{
        Write-Host "Skipped $Group Already Exists"
 }
}


$Domain = (get-MgDomain | where-Object -Property ID -like "*.onMicrosoft.com").id

$BreakGlassAccounts =@(
"zEmergencyAdmin"
"zEmergencyAdmin2"
)


ForEach ($user in $BreakGlassAccounts){
 # check if User exists
 $UserCheck = get-mguser | Where-Object -Property UserPrincipalName -CMatch $User
 #$UserCheck = get-mgUser -Property Displayname | Where-Object DisplayName eq $($User)
 #if not exists then create it
 if ($null -eq $UserCheck){
     #Create Password for Account
     $PasswordProfile = @{
         Password = Read-Host 'Paste 150 Charecter Password from Passportal for' $User -AsSecureString
     }
     New-MgUser -DisplayName "$user" -PasswordProfile $PasswordProfile `
     -AccountEnabled -MailNickName "$user" `
     -UserPrincipalName ($user + "@" + $domain)
     write-output "Users are being created, please wait 20 seconds"
     Start-Sleep -Seconds 20
     write-host "Assiging Authentication Methods"
$Z1 = (get-mguser | Where-Object -Property UserPrincipalName -CMatch zEmergencyAdmin).id 
forEach ($ID in $Z1){
    New-MgUserAuthenticationEmailMethod -UserId $ID -EmailAddress "theadmins@pathforwardit.com"
    $params = @{
        "@odata.type" = "#microsoft.graph.unifiedRoleAssignment"
        RoleDefinitionId = "62e90394-69f5-4237-9190-012177145e10"
        PrincipalId = "$ID"
        DirectoryScopeId = "/"
    }
    New-MgRoleManagementDirectoryRoleAssignment -BodyParameter $params | Out-Null
}
     }
 else{
    Write-host "$User Already Exists"
    $Z1 = (get-mguser | Where-Object -Property UserPrincipalName -CMatch zEmergencyAdmin).id 
 }
}

$params = @{
	allowExternalIdentitiesToLeave = $true
}
#Update-MgPolicyExternalIdentityPolicy -BodyParameter $params | Out-Null

#$params = @{
	#guestUserRoleId = "2af84b1e-32c8-42b7-82bc-daa82404023b"
	#allowInvitesFrom = "adminsAndGuestInviters"
#}

Update-MgPolicyAuthorizationPolicy -BodyParameter $params | Out-Null

$params = @{
	selfServiceSignUp = @{
		isEnabled = $false
	}
}
Update-MgPolicyAuthenticationFlowPolicy -BodyParameter $params | Out-Null

#Create Named Locations for Conditional Access 
$CountryNameLocations =@(
    "Allowed Countries"
    "Travel Countries"
)

foreach($Location in $CountryNameLocations){

$namedLocation = Get-MgIdentityConditionalAccessNamedLocation -Filter "DisplayName eq '$Location'"
if ($null -eq $namedLocation) {
    $body = @{
        "@odata.type" = "#microsoft.graph.countryNamedLocation" 
        DisplayName = $Location 
        CountriesAndRegions = @("US") 
        IncludeUnknownCountriesAndRegions = $false 
    }
    $namedLocation = New-MgIdentityConditionalAccessNamedLocation -BodyParameter $body | Out-Null
    Write-Host "Created named location $Location."
} else {
    Write-Host "Skipped named location $location because it already exists."
}
}

###################   Admin MFA Policy ############
$PolicyName = "CA001: Require multi-factor authentication for admins"
$Checkpolicy = Get-MgIdentityConditionalAccessPolicy -Filter "DisplayName eq '$PolicyName'"
$ExcludeCAGroups = Get-MgGroup -top 999 -Filter "startswith(DisplayName,'SG365_Exclude_CA001: Require multi-factor authentication for admins')" | Select-Object ID
if ($null -eq $Checkpolicy) {
  $params = @{
    DisplayName = "$policyName"
    State = "disabled"
    Conditions = @{
      ClientAppTypes = @(
        "mobileAppsAndDesktopClients"
        "browser"
      )
      Applications = @{
        IncludeApplications = @(
          "All"
        )
      }
      users = @{
        ExcludeUsers =@(
          $Z1
         )
        IncludeRoles = @(
          "62e90394-69f5-4237-9190-012177145e10",
          "194ae4cb-b126-40b2-bd5b-6091b380977d",
          "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
          "29232cdf-9323-42fd-ade2-1d097af3e4de",
          "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
          "729827e3-9c14-49f7-bb1b-9608f156bbb8",
          "b0f54661-2d74-4c50-afa3-1ec803f12efe",
          "fe930be7-5e62-47db-91af-98c3a49a38b1",
          "c4e39bd9-1100-46d3-8c65-fb160da0071f",
          "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
          "158c047a-c907-4556-b7ef-446551a6b5f7",
          "966707d0-3269-4727-9be2-8c3a10f19b9d",
          "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
          "e8611ab8-c189-46e8-94e1-60213ab1f814",
          "fdd7a751-b60b-444a-984c-02652fe8fa1c",
          "a9ea8996-122f-4c74-9520-8edcd192826c",
          "44367163-eba1-44c3-98af-f5787879f96a",
          "7698a772-787b-4ac8-901f-60d6b08affd2",
          "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
          "2b745bdf-0803-4d80-aa65-822c4493daac",
          "11648597-926c-4cf3-9c36-bcebb0ba8dcc",
          "5f2222b1-57c3-48ba-8ad5-d4759f1fde6f"
         )
         ExcludeGroups = @(
          $ExcludeCAGroups.Id
         )
      }
      Locations = @{
        IncludeLocations = @(
          "All"
        )
        ExcludeLocations = @(
          "AllTrusted"
        )
      }
     }
     grantControls = @{
      operator = "OR"
      builtInControls = @(
      )
      customAuthenticationFactors = @(
      )
      termsOfUse = @(
      )
      authenticationStrength = @{
        id = "00000000-0000-0000-0000-000000000002"
      }
    }
  }
  
  New-MgIdentityConditionalAccessPolicy -BodyParameter $params | Out-Null
            Write-Host "Created policy $PolicyName."
        } else {
            Write-Host "Skipped policy $PolicyName because it already exists."
        }


###################   Default Block Policy ########
$PolicyName = "CA002: Default Block - Travel Users Exclusion"
$Checkpolicy = Get-MgIdentityConditionalAccessPolicy -Filter "DisplayName eq '$PolicyName'"
$ExcludeCAGroups = Get-MgGroup -top 999 -Filter "startswith(DisplayName,'SG365_Exclude_CA002: Default Block - Travel Users Exclusion')" | Select-Object ID
$AllowedCountriesNamedLocation = Get-MgIdentityConditionalAccessNamedLocation -Filter "startswith(DisplayName,'Allowed Countries')" | Select-Object ID

if ($null -eq $Checkpolicy) {
  $params = @{
    DisplayName = $PolicyName
    State = "disabled"
    Conditions = @{
      ClientAppTypes = @(
        "All"
      )
      Applications = @{
        IncludeApplications = @(
          "All"
        )
      }
      users = @{
        IncludeUsers = @(
          "All"
         )
         ExcludeUsers =@(
          $Z1
         )
         ExcludeGroups = @(
          $ExcludeCAGroups.Id
         )
      }
      Locations = @{
        IncludeLocations = @(
          "All"
        )
        ExcludeLocations =@(
          $AllowedCountriesNamedLocation.id
        )
      }
     }
     GrantControls = @{
       Operator = "OR"
       BuiltInControls = @(
        "Block"
       )
     }
  }
  New-MgIdentityConditionalAccessPolicy -BodyParameter $params | Out-Null
            Write-Host "Created policy $PolicyName."
        } else {
            Write-Host "Skipped policy $PolicyName because it already exists."
        }


################### Block Legacy Auth Policy ######
$PolicyName = "CA003: Block legacy authentication"
$Checkpolicy = Get-MgIdentityConditionalAccessPolicy -Filter "DisplayName eq '$PolicyName'"
$ExcludeCAGroups = Get-MgGroup -top 999 -Filter "startswith(DisplayName,'SG365_Exclude_CA003: Block legacy authentication')" | Select-Object ID
if ($null -eq $Checkpolicy) {
  $params = @{
    DisplayName = $PolicyName
    State = "disabled"
    Conditions = @{
      ClientAppTypes = @(
          "exchangeActiveSync",
          "other"
      )
      Applications = @{
        IncludeApplications = @(
          "All"
        )
      }
      users = @{
        IncludeUsers = @(
          "All"
         )
        ExcludeGroups = @(
          $ExcludeCAGroups.Id
         )
      }
      Locations = @{
        IncludeLocations = @(
          "All"
        )
        ExcludeLocations = @()
      }
     }
     GrantControls = @{
       Operator = "OR"
       BuiltInControls = @( 
          "Block"
       )
     }
  }
  New-MgIdentityConditionalAccessPolicy -BodyParameter $params | Out-Null
            Write-Host "Created policy $PolicyName."
        } else {
            Write-Host "Skipped policy $PolicyName because it already exists."
        }

################### MFA for All Users Policy #######
$PolicyName = "CA004: Require multi-factor authentication for All Users"
$Checkpolicy = Get-MgIdentityConditionalAccessPolicy -Filter "DisplayName eq '$PolicyName'"
$ExcludeCAGroups = Get-MgGroup -top 999 -Filter "startswith(DisplayName,'SG365_Exclude_CA004: Require multi-factor authentication for allusers_Restricted')" | Select-Object ID
if ($null -eq $Checkpolicy) {
  $params = @{
    DisplayName = $PolicyName
    State = "disabled"
    Conditions = @{
      ClientAppTypes = @(
        "browser", 
        "mobileAppsAndDesktopClients"
      )
      Applications = @{
        IncludeApplications = @(
          "All"
        )
        ExcludeApplications = @(
          "0000000a-0000-0000-c000-000000000000",
          "d4ebce55-015a-49b5-a083-c84d1797ae8c"
        )
      }
      users = @{
        IncludeUsers = @(
          "All"
         )
         ExcludeUsers =@(
          $Z1
         )
         ExcludeGroups = @(
          $ExcludeCAGroups.Id

         )
      }
      Locations = @{
        IncludeLocations = @(
          "All"
        )
        ExcludeLocations = @(
          "AllTrusted"
        )
      }
     }
     grantControls = @{
      operator = "OR"
      builtInControls = @(
      )
      customAuthenticationFactors = @(
      )
      termsOfUse = @(
      )
      authenticationStrength = @{
        id = "00000000-0000-0000-0000-000000000002"
      }
    }
  }
  New-MgIdentityConditionalAccessPolicy -BodyParameter $params | Out-Null
            Write-Host "Created policy $PolicyName."
        } else {
            Write-Host "Skipped policy $PolicyName because it already exists."
        }

################### MFA for Guest Users Policy ######
$PolicyName = "CA005: Require multi-factor authentication for guest access"
$Checkpolicy = Get-MgIdentityConditionalAccessPolicy -Filter "DisplayName eq '$PolicyName'"
$ExcludeCAGroups = Get-MgGroup -top 999 -Filter "startswith(DisplayName,'SG365_Exclude_CA005: Require multi-factor authentication for guest access')" | Select-Object ID
if ($null -eq $Checkpolicy) {
  $params = @{
    DisplayName = $PolicyName
    State = "disabled"
    Conditions = @{
      ClientAppTypes = @(
        "browser", 
        "mobileAppsAndDesktopClients"
      )
      Applications = @{
        IncludeApplications = @(
          "All"
        )
      }
      users = @{
        IncludeUsers = @(
          "GuestsOrExternalUsers"
         )
         ExcludeGroups = @(
          $ExcludeCAGroups.Id
         )
      }
      Locations = @{
        IncludeLocations = @(
          "All"
        )
      }
     }
     GrantControls = @{
      operator = "OR"
      builtInControls = @(
      )
      customAuthenticationFactors = @(
      )
      termsOfUse = @(
      )
      authenticationStrength = @{
        id = "00000000-0000-0000-0000-000000000002"
      }
    }
  }
  New-MgIdentityConditionalAccessPolicy -BodyParameter $params | Out-Null
            Write-Host "Created policy $PolicyName."
        } else {
            Write-Host "Skipped policy $PolicyName because it already exists."
        }

################### MFA for Azure Management Policy ############
$PolicyName = "CA006: Require multi-factor authentication for Azure management"
$Checkpolicy = Get-MgIdentityConditionalAccessPolicy -Filter "DisplayName eq '$PolicyName'"
$ExcludeCAGroups = Get-MgGroup -top 999 -Filter "startswith(DisplayName,'SG365_Exclude_CA006: Require multi-factor authentication for Azure management')" | Select-Object ID
if ($null -eq $Checkpolicy) {
  $params = @{
    DisplayName = $PolicyName
    State = "disabled"
    Conditions = @{
      ClientAppTypes = @(
        "browser", 
        "mobileAppsAndDesktopClients"
      )
      Applications = @{
        IncludeApplications = @(
          "797f4846-ba00-4fd7-ba43-dac1f8f63013"
        )
      }
      users = @{
        IncludeUsers = @(
          "All"
         )
         ExcludeUsers =@(
          $Z1
         )
         ExcludeGroups = @(
          $ExcludeCAGroups.Id
         )
      }
      Locations = @{
        IncludeLocations = @(
          "All"
        )
      }
     }
     GrantControls = @{
      operator = "OR"
      builtInControls = @(
      )
      customAuthenticationFactors = @(
      )
      termsOfUse = @(
      )
      authenticationStrength = @{
        id = "00000000-0000-0000-0000-000000000002"
      }
    }
  }
  New-MgIdentityConditionalAccessPolicy -BodyParameter $params | Out-Null
            Write-Host "Created policy $PolicyName."
        } else {
            Write-Host "Skipped policy $PolicyName because it already exists."
        }

################### Reuire Compliance Device Admins ############
$PolicyName = "CA009: Require compliant or hybrid Azure AD joined device for admins"
$Checkpolicy = Get-MgIdentityConditionalAccessPolicy -Filter "DisplayName eq '$PolicyName'"
$ExcludeCAGroups = Get-MgGroup -top 999 -Filter "startswith(DisplayName,'SG365_Exclude_CA009: Require compliant or hybrid Azure AD joined device for admins_Restricted')" | Select-Object ID
if ($null -eq $Checkpolicy) {
  $params = @{
    DisplayName = $PolicyName
    State = "disabled"
    Conditions = @{
      ClientAppTypes = @(
        "browser", 
        "mobileAppsAndDesktopClients"
      )
      Applications = @{
        IncludeApplications = @(
          "All"
        )
        ExcludeApplications =@(
          "0000000a-0000-0000-c000-000000000000",
          "d4ebce55-015a-49b5-a083-c84d1797ae8c",
          "45a330b1-b1ec-4cc1-9161-9f03992aa49f"
        )
      }
      Platforms =@{
        IncludePlatforms =@(
          "windows"
        )
      }
      users = @{
        ExcludeUsers =@(
          $Z1
         )
        IncludeRoles =@(
          "62e90394-69f5-4237-9190-012177145e10",
          "194ae4cb-b126-40b2-bd5b-6091b380977d",
          "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
          "29232cdf-9323-42fd-ade2-1d097af3e4de",
          "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
          "729827e3-9c14-49f7-bb1b-9608f156bbb8",
          "b0f54661-2d74-4c50-afa3-1ec803f12efe",
          "fe930be7-5e62-47db-91af-98c3a49a38b1",
          "c4e39bd9-1100-46d3-8c65-fb160da0071f",
          "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
          "158c047a-c907-4556-b7ef-446551a6b5f7",
          "966707d0-3269-4727-9be2-8c3a10f19b9d",
          "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
          "e8611ab8-c189-46e8-94e1-60213ab1f814",
          "fdd7a751-b60b-444a-984c-02652fe8fa1c",
          "a9ea8996-122f-4c74-9520-8edcd192826c",
          "44367163-eba1-44c3-98af-f5787879f96a",
          "7698a772-787b-4ac8-901f-60d6b08affd2",
          "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
          "2b745bdf-0803-4d80-aa65-822c4493daac",
          "11648597-926c-4cf3-9c36-bcebb0ba8dcc",
          "5f2222b1-57c3-48ba-8ad5-d4759f1fde6f"
        )
        ExcludeGroups = @(
          $ExcludeCAGroups.Id
         )
      }
     
      Locations = @{
        IncludeLocations = @(
          "All"
        )
      }
     }
     GrantControls = @{
       Operator = "OR"
       BuiltInControls = @(
        "compliantDevice",
        "domainJoinedDevice"
       )
     }
  }
  New-MgIdentityConditionalAccessPolicy -BodyParameter $params | Out-Null
            Write-Host "Created policy $PolicyName."
        } else {
            Write-Host "Skipped policy $PolicyName because it already exists."
        }

################### Require Compliant Device Windows ###########
$PolicyName = "CA009.5: Require Compliant Device - Windows Devices"
$Checkpolicy = Get-MgIdentityConditionalAccessPolicy -Filter "DisplayName eq '$PolicyName'"
$ExcludeCAGroups = Get-MgGroup -top 999 -Filter "startswith(DisplayName,'SG365_Exclude_CA009.5: Require Compliant Device - Windows Devices_Restricted')" | Select-Object ID
if ($null -eq $Checkpolicy) {
  $params = @{
    DisplayName = $PolicyName
    State = "disabled"
    Conditions = @{
      ClientAppTypes = @(
        "browser", 
        "mobileAppsAndDesktopClients"
      )
      Applications = @{
        IncludeApplications = @(
          "All"
        )
        ExcludeApplications =@(
          "0000000a-0000-0000-c000-000000000000",
          "d4ebce55-015a-49b5-a083-c84d1797ae8c",
          "45a330b1-b1ec-4cc1-9161-9f03992aa49f"
        )
      }
      Platforms =@{
        IncludePlatforms =@(
          "windows"
        )
      }
      users = @{
        IncludeUsers = @(
          "All"
         )
         ExcludeUsers =@(
          $Z1
         )
         ExcludeGroups = @(
          $ExcludeCAGroups.Id
         )
      }
      Locations = @{
        IncludeLocations = @(
          "All"
        )
      }
     }
     GrantControls = @{
       Operator = "OR"
       BuiltInControls = @(
         "compliantDevice"
       )
     }
  }
  New-MgIdentityConditionalAccessPolicy -BodyParameter $params | Out-Null
            Write-Host "Created policy $PolicyName."
        } else {
            Write-Host "Skipped policy $PolicyName because it already exists."
        }

################### Require Compliant Device Windows Report Only ###########
$PolicyName = "CA009.5: Require Compliant Device - Windows Devices Report Only"
$Checkpolicy = Get-MgIdentityConditionalAccessPolicy -Filter "DisplayName eq '$PolicyName'"
if ($null -eq $Checkpolicy) {
  $params = @{
    DisplayName = $PolicyName
    State = "enabledForReportingButNotEnforced"
    Conditions = @{
      ClientAppTypes = @(
        "browser", 
        "mobileAppsAndDesktopClients"
      )
      Applications = @{
        IncludeApplications = @(
          "All"
        )
        ExcludeApplications =@(
          "0000000a-0000-0000-c000-000000000000",
          "d4ebce55-015a-49b5-a083-c84d1797ae8c",
          "45a330b1-b1ec-4cc1-9161-9f03992aa49f"
        )
      }
      Platforms =@{
        IncludePlatforms =@(
          "windows"
        )
      }
      users = @{
        IncludeUsers = @(
          "All"
         )
      }
      Locations = @{
        IncludeLocations = @(
          "All"
        )
      }
     }
     GrantControls = @{
       Operator = "OR"
       BuiltInControls = @(
         "compliantDevice"
       )
     }
  }
  New-MgIdentityConditionalAccessPolicy -BodyParameter $params | Out-Null
            Write-Host "Created policy $PolicyName."
        } else {
            Write-Host "Skipped policy $PolicyName because it already exists."
        }

################### Require Compliant Device MacOS   ###########
$PolicyName = "CA009.6: Require Compliant Device - MacOS"
$Checkpolicy = Get-MgIdentityConditionalAccessPolicy -Filter "DisplayName eq '$PolicyName'"
$ExcludeCAGroups = Get-MgGroup -top 999 -Filter "startswith(DisplayName,'SG365_Exclude_CA009.6: Require Compliant Device - MacOS_Testing-Only')" | Select-Object ID
if ($null -eq $Checkpolicy) {
  $params = @{
    DisplayName = $PolicyName
    State = "disabled"
    Conditions = @{
      ClientAppTypes = @(
        "browser", 
        "mobileAppsAndDesktopClients"
      )
      Applications = @{
        IncludeApplications = @(
          "All"
        )
        ExcludeApplications =@(
          "0000000a-0000-0000-c000-000000000000",
          "d4ebce55-015a-49b5-a083-c84d1797ae8c",
          "45a330b1-b1ec-4cc1-9161-9f03992aa49f"
        )
      }
      Platforms =@{
        IncludePlatforms =@(
          "macOS"
        )
      }
      users = @{
        IncludeUsers = @(
          "All"
         )
         ExcludeUsers =@(
          $Z1
         )
         ExcludeGroups = @(
          $ExcludeCAGroups.Id
         )
      }
      Locations = @{
        IncludeLocations = @(
          "All"
        )
      }
     }
     GrantControls = @{
       Operator = "OR"
       BuiltInControls = @(
         "compliantDevice"
       )
     }
  }
  New-MgIdentityConditionalAccessPolicy -BodyParameter $params | Out-Null
            Write-Host "Created policy $PolicyName."
        } else {
            Write-Host "Skipped policy $PolicyName because it already exists."
        }

################### Require Compliant Device MacOS Report Only  ###########
$PolicyName = "CA009.6: Require Compliant Device - MacOS Report Only"
$Checkpolicy = Get-MgIdentityConditionalAccessPolicy -Filter "DisplayName eq '$PolicyName'"
if ($null -eq $Checkpolicy) {
  $params = @{
    DisplayName = $PolicyName
    State = "enabledForReportingButNotEnforced"
    Conditions = @{
      ClientAppTypes = @(
        "browser", 
        "mobileAppsAndDesktopClients"
      )
      Applications = @{
        IncludeApplications = @(
          "All"
        )
        ExcludeApplications =@(
          "0000000a-0000-0000-c000-000000000000",
          "d4ebce55-015a-49b5-a083-c84d1797ae8c",
          "45a330b1-b1ec-4cc1-9161-9f03992aa49f"
        )
      }
      Platforms =@{
        IncludePlatforms =@(
          "macOS"
        )
      }
      users = @{
        IncludeUsers = @(
          "All"
         )
      }
      Locations = @{
        IncludeLocations = @(
          "All"
        )
      }
     }
     GrantControls = @{
       Operator = "OR"
       BuiltInControls = @(
         "compliantDevice"
       )
     }
  }
  New-MgIdentityConditionalAccessPolicy -BodyParameter $params | Out-Null
            Write-Host "Created policy $PolicyName."
        } else {
            Write-Host "Skipped policy $PolicyName because it already exists."
        }

################### Require Compliant Device Policy IOS/ Andriod #############
$PolicyName = "CA009.7: Require Compliant Device IOS-Android"
$Checkpolicy = Get-MgIdentityConditionalAccessPolicy -Filter "DisplayName eq '$PolicyName'"
$ExcludeCAGroups = Get-MgGroup -top 999 -Filter "startswith(DisplayName,'SG365_Exclude_CA009.7: Require Compliant Device - IOS-Android_Testing-Only')" | Select-Object ID
if ($null -eq $Checkpolicy) {
  $params = @{
    DisplayName = $PolicyName
    State = "disabled"
    Conditions = @{
      ClientAppTypes = @(
        "browser", 
        "mobileAppsAndDesktopClients"
      )
      Applications = @{
        IncludeApplications = @(
          "All"
        )
        ExcludeApplications =@(
          "0000000a-0000-0000-c000-000000000000",
          "d4ebce55-015a-49b5-a083-c84d1797ae8c",
          "45a330b1-b1ec-4cc1-9161-9f03992aa49f"
        )
      }
      Platforms =@{
        IncludePlatforms =@(
          "android",
          "iOS"
        )
      }
      users = @{
        IncludeUsers = @(
          "All"
         )
         ExcludeUsers =@(
          $Z1
         )
         ExcludeGroups = @(
          $ExcludeCAGroups.Id
         )
      }
      Locations = @{
        IncludeLocations = @(
          "All"
        )
      }
     }
     GrantControls = @{
       Operator = "OR"
       BuiltInControls = @(
        "compliantDevice"
       )
     }
  }
  New-MgIdentityConditionalAccessPolicy -BodyParameter $params | Out-Null
            Write-Host "Created policy $PolicyName."
        } else {
            Write-Host "Skipped policy $PolicyName because it already exists."
        }

################### Require Compliant Device Policy IOS/ Andriod Report Only #############
$PolicyName = "CA009.7: Require Compliant Device IOS-Android Report Only"
$Checkpolicy = Get-MgIdentityConditionalAccessPolicy -Filter "DisplayName eq '$PolicyName'"
if ($null -eq $Checkpolicy) {
  $params = @{
    DisplayName = $PolicyName
    State = "enabledForReportingButNotEnforced"
    Conditions = @{
      ClientAppTypes = @(
        "browser", 
        "mobileAppsAndDesktopClients"
      )
      Applications = @{
        IncludeApplications = @(
          "All"
        )
        ExcludeApplications =@(
          "0000000a-0000-0000-c000-000000000000",
          "d4ebce55-015a-49b5-a083-c84d1797ae8c",
          "45a330b1-b1ec-4cc1-9161-9f03992aa49f"
        )
      }
      Platforms =@{
        IncludePlatforms =@(
          "android",
          "iOS"
        )
      }
      users = @{
        IncludeUsers = @(
          "All"
         )
      }
      Locations = @{
        IncludeLocations = @(
          "All"
        )
      }
     }
     GrantControls = @{
       Operator = "OR"
       BuiltInControls = @(
        "compliantDevice"
       )
     }
  }
  New-MgIdentityConditionalAccessPolicy -BodyParameter $params | Out-Null
            Write-Host "Created policy $PolicyName."
        } else {
            Write-Host "Skipped policy $PolicyName because it already exists."
        }


################### Require Compliant Device Linuc  ###########
$PolicyName = "CA009.8: Require Compliant Device - Linux"
$Checkpolicy = Get-MgIdentityConditionalAccessPolicy -Filter "DisplayName eq '$PolicyName'"
$ExcludeCAGroups = Get-MgGroup -top 999 -Filter "startswith(DisplayName,'SG365_Exclude_CA009.8: Require Compliant Device - Linux_Testing-Only')" | Select-Object ID
if ($null -eq $Checkpolicy) {
  $params = @{
    DisplayName = $PolicyName
    State = "disabled"
    Conditions = @{
      ClientAppTypes = @(
        "browser", 
        "mobileAppsAndDesktopClients"
      )
      Applications = @{
        IncludeApplications = @(
          "All"
        )
        ExcludeApplications =@(
          "0000000a-0000-0000-c000-000000000000",
          "d4ebce55-015a-49b5-a083-c84d1797ae8c",
          "45a330b1-b1ec-4cc1-9161-9f03992aa49f"
        )
      }
      Platforms =@{
        IncludePlatforms =@(
          "Linux"
        )
      }
      users = @{
        IncludeUsers = @(
          "All"
         )
         ExcludeUsers =@(
          $Z1
         )
         ExcludeGroups = @(
          $ExcludeCAGroups.Id
         )
      }
      Locations = @{
        IncludeLocations = @(
          "All"
        )
      }
     }
     GrantControls = @{
       Operator = "OR"
       BuiltInControls = @(
         "compliantDevice"
       )
     }
  }
  New-MgIdentityConditionalAccessPolicy -BodyParameter $params | Out-Null
            Write-Host "Created policy $PolicyName."
        } else {
            Write-Host "Skipped policy $PolicyName because it already exists."
        }


################### Require App Protection Policy IOS/Andriod ################
$PolicyName = "CA011: Require Intune Mobile Device App Protection Policy"
$Checkpolicy = Get-MgIdentityConditionalAccessPolicy -Filter "DisplayName eq '$PolicyName'"
$ExcludeCAGroups = Get-MgGroup -top 999 -Filter "startswith(DisplayName,'SG365_Exclude_CA011: Require Intune Mobile Device App Protection Polic')" | Select-Object ID
if ($null -eq $Checkpolicy) {
  $params = @{
    DisplayName = $PolicyName
    State = "disabled"
    Conditions = @{
      ClientAppTypes = @(
        "browser", 
          "mobileAppsAndDesktopClients"
      )
      Applications = @{
        IncludeApplications = @(
          "All"
        )
        ExcludeApplications =@(
          "d4ebce55-015a-49b5-a083-c84d1797ae8c"
        )
      }
      Platforms =@{
        IncludePlatforms =@(
          "android",
          "iOS"
        )
      }
      users = @{
        IncludeUsers = @(
          "All"
         )
         ExcludeUsers =@(
          $Z1
         )
        ExcludeGroups = @(
          $ExcludeCAGroups.Id
         )
      }
      Locations = @{
        IncludeLocations = @(
          "All"
        )
      }
     }
     GrantControls = @{
       Operator = "AND"
       BuiltInControls = @(
        "approvedApplication", 
        "compliantApplication"
       )
     }
  }
  New-MgIdentityConditionalAccessPolicy -BodyParameter $params | Out-Null
            Write-Host "Created policy $PolicyName."
        } else {
            Write-Host "Skipped policy $PolicyName because it already exists."
        }

################### Block Unsupported Platforms ##############################
$PolicyName = "CA010: Block access for unknown or unsupported device platform"
$Checkpolicy = Get-MgIdentityConditionalAccessPolicy -Filter "DisplayName eq '$PolicyName'"
$ExcludeCAGroups = Get-MgGroup -top 999 -Filter "startswith(DisplayName,'SG365_Exclude_CA010: Block access for unknown or unsupported device platform')" | Select-Object ID
if ($null -eq $Checkpolicy) {
  $params = @{
    DisplayName = $PolicyName
    State = "disabled"
    Conditions = @{
      ClientAppTypes = @(
        "All"
      )
      Applications = @{
        IncludeApplications = @(
          "All"
        )
      }
      Platforms =@{
        IncludePlatforms =@(
          "All"
        )
        ExcludePlatforms =@(
          "android",
          "iOS",
          "windows",
          "macOS"
        )
      }
      users = @{
        IncludeUsers = @(
          "All"
         )
         ExcludeUsers =@(
          $Z1
         )
         ExcludeGroups = @(
          $ExcludeCAGroups.Id
         )
      }
      Locations = @{
        IncludeLocations = @(
          "All"
        )
      }
     }
     GrantControls = @{
       Operator = "OR"
       BuiltInControls = @(
        "Block"
       )
     }
  }
  New-MgIdentityConditionalAccessPolicy -BodyParameter $params | Out-Null
            Write-Host "Created policy $PolicyName."
        } else {
            Write-Host "Skipped policy $PolicyName because it already exists."
        }

################### Block MFA Enrollment from Non Trusted Locations #######################
$PolicyName = "CA012: Block MFA Enrollment from Non Trusted Locations"
$Checkpolicy = Get-MgIdentityConditionalAccessPolicy -Filter "DisplayName eq '$PolicyName'"
$ExcludeCAGroups = Get-MgGroup -top 999 -Filter "startswith(DisplayName,'SG365_Exclude_CA012: Block MFA Enrollment from Non Trusted Locations')" | Select-Object ID
if ($null -eq $Checkpolicy) {
  $params = @{
    DisplayName = $PolicyName
    State = "disabled"
    Conditions = @{
      ClientAppTypes = @(
        "All"
      )
      Applications = @{
        IncludeUserActions =@(
          "urn:user:registersecurityinfo"
        )
      }
      users = @{
        IncludeUsers = @(
          "All"
         )
         ExcludeGroups = @(
          $ExcludeCAGroups.Id
         )
      }
      Locations = @{
        IncludeLocations = @(
          "All"
        )
        ExcludeLocations =@(
          "AllTrusted"
        )
      }
     }
     GrantControls = @{
       Operator = "OR"
       BuiltInControls = @(
        "Block"
       )
     }
  }
  New-MgIdentityConditionalAccessPolicy -BodyParameter $params | Out-Null
            Write-Host "Created policy $PolicyName."
        } else {
            Write-Host "Skipped policy $PolicyName because it already exists."
        }

#################### Encryptino Allow for External Users Policy ############
$PolicyName = "CA013: Email Encryption External User Access"
$Checkpolicy = Get-MgIdentityConditionalAccessPolicy -Filter "DisplayName eq '$PolicyName'"
$ExcludeCAGroups = Get-MgGroup -top 999 -Filter "startswith(DisplayName,'SG365_Exclude_CA013: Email Encryption External User Access')" | Select-Object ID
if ($null -eq $Checkpolicy) {
  $params = @{
    DisplayName = $PolicyName
    State = "disabled"
    Conditions = @{
      ClientAppTypes = @(
        "All"
      )
      Applications = @{
        IncludeApplications = @(
          "All"
        )
        ExcludeApplications = @(
          "00000012-0000-0000-c000-000000000000"
        )
      }
      users = @{
        IncludeUsers = @(
          "GuestsOrExternalUsers"
         )
         ExcludeGroups = @(
          $ExcludeCAGroups.Id
         )
      }
      Locations = @{
        IncludeLocations = @(
          "All"
        )
        ExcludeLocations =@(
          "AllTrusted"
        )
      }
     }
     GrantControls = @{
       Operator = "OR"
       BuiltInControls = @(
        "Block"
       )
     }
  }
  New-MgIdentityConditionalAccessPolicy -BodyParameter $params | Out-Null
            Write-Host "Created policy $PolicyName."
        } else {
            Write-Host "Skipped policy $PolicyName because it already exists."
        }


#################### Default Block - Travel Policy ##############
$PolicyName = "CA014: Default Block - Travel Policy"
$Checkpolicy = Get-MgIdentityConditionalAccessPolicy -Filter "DisplayName eq '$PolicyName'"
$ExcludeCAGroups = Get-MgGroup -top 999 -Filter "startswith(DisplayName,'SG365_Exclude_CA002: Default Block - Travel Users Exclusion')" | Select-Object ID
$TravelCountriesNamedLocation = Get-MgIdentityConditionalAccessNamedLocation -Filter "startswith(DisplayName,'Travel Countries')" | Select-Object ID
$AllowedCountriesNamedLocation = Get-MgIdentityConditionalAccessNamedLocation -Filter "startswith(DisplayName,'Allowed Countries')" | Select-Object ID
if ($null -eq $Checkpolicy) {
  $params = @{
    DisplayName = $PolicyName
    State = "disabled"
    Conditions = @{
      ClientAppTypes = @(
        "All"
      )
      Applications = @{
        IncludeApplications = @(
          "All"
        )
      }
      users = @{
        IncludeUsers = @(
          $ExcludeCAGroups.Id
         )
         ExcludeUsers =@(
          $Z1
         )
         ExcludeGroups = @(
          $ExcludeCAGroups.Id
         )
      }
      Locations = @{
        IncludeLocations = @(
          "All"
        )
        ExcludeLocations =@(
          $AllowedCountriesNamedLocation.id
          $TravelCountriesNamedLocation.id
        )
      }
     }
     GrantControls = @{
       Operator = "OR"
       BuiltInControls = @(
        "Block"
       )
     }
  }
  New-MgIdentityConditionalAccessPolicy -BodyParameter $params | Out-Null
            Write-Host "Created policy $PolicyName."
        } else {
            Write-Host "Skipped policy $PolicyName because it already exists."
        }

Disconnect-Graph


###########################################################################################################################
#Deploy Microsoft Teams Settings


Connect-MicrosoftTeams 
 
# Turn off Guest Access by Default - Allow as needed
#Set-CsTeamsClientConfiguration -Identity Global -AllowGuestUser $false 

#Set Teams External Access - Block By Default and allow as needed
#Set-CsTenantFederationConfiguration -AllowFederatedUsers $False -AllowTeamsConsumer $False -AllowTeamsConsumerInbound $False -AllowPublicUsers $False


# Set Teams Meeting Lobby Policy
Set-CsTeamsMeetingPolicy -Identity Global -AllowAnonymousUsersToJoinMeeting $true -AutoAdmittedUsers "EveryoneInCompanyExcludingGuests" -AllowAnonymousUsersToStartMeeting $false -AllowPSTNUsersToBypassLobby $false


# Block all Apps in Teams except for PowerBI
$SharepointApp = New-Object -TypeName Microsoft.Teams.Policy.Administration.Cmdlets.Core.DefaultCatalogApp -Property @{Id="2a527703-1f6f-4559-a332-d8a7d288cd88"}
$PowerBIApp = New-Object -TypeName Microsoft.Teams.Policy.Administration.Cmdlets.Core.DefaultCatalogApp -Property @{Id="1c4340de-2a85-40e5-8eb0-4f295368978b"}
$DefaultCatalogAppList = @($SharepointApp,$PowerBIApp)
Set-CsTeamsAppPermissionPolicy -Identity "Global" -DefaultCatalogAppsType AllowedAppList  -DefaultCatalogApps $DefaultCatalogAppList -GlobalCatalogAppsType AllowedAppList -GlobalCatalogApps @() -PrivateCatalogAppsType AllowedAppList -PrivateCatalogApps @()

# Turn off all 3r Party Cloud Storage
Set-CsTeamsClientConfiguration -Identity Global -AllowDropBox $false -AllowEgnyte $false -AllowGoogleDrive $false -AllowBox $false -AllowShareFile $false


Disconnect-MicrosoftTeams

###########################################################################################################################################
#Exchange online 

Connect-ExchangeOnline

Enable-OrganizationCustomization
$licenseUrl = (Get-AadrmConfiguration).LicensingIntranetDistributionPointUrl
    
Set-IRMConfiguration -LicensingLocation @{add=$licenseUrl} -InternalLicensingEnabled $true -AutomaticServiceUpdateEnabled $true -EnablePdfEncryption $true -SimplifiedClientAccessEnabled $true -DecryptAttachmentForEncryptOnly $true -AzureRMSLicensingEnabled $true


New-RemoteDomain -Name PathForward -DomainName pathforwardit.com -AutoReplyEnabled $true -AutoForwardEnabled $true -AllowedOOFType External
