
function createLocalAdmin(){
        
     #Secure Password
     $secureString = "UKbizIT134!!" | ConvertTo-SecureString -AsPlainText -Force

     #Create Local Admin Account
     New-LocalUser -Name "Admin" -Description "UK Business IT Administrator Account" -Password $secureString 

     set-localuser -name "Admin" -PasswordNeverExpires $true 
	
     #Add Local Admin accoun to the Administrators Group
     Add-LocalGroupMember -Group "Administrators" -Member "Admin"

     #Admin Credentials
     Write-Warning "
     Admin Account has been created.

     Local Admin Account Details:

     Username: Admin
     Password: UKbizIT134!!

     "
}


function setPasswordPolicy(){

    #Secure Password
    $newPassword = "Company134!!" | ConvertTo-SecureString -AsPlainText -Force

    #Set Current Users New Password
    Set-LocalUser $env:USERNAME -Password $newPassword -UserMayChangePassword $true
    
    #Set Password Length
    net accounts /minpwlen:12

    #Set Lockout Timer
    net accounts /lockoutwindow:10

    #Set Password Attempts before Lockout
    net accounts /lockoutthreshold:10

    #Download Security Policy
    secedit.exe /export /cfg C:\secconfig.cfg

    #Edit Security Policy
    (Get-Content -path C:\secconfig.cfg -Raw) -replace 'PasswordComplexity = 0', 'PasswordComplexity = 1' | Out-File -FilePath C:\secconfig.cfg
    (Get-Content -path C:\secconfig.cfg -Raw) -replace 'LockoutDuration = 30', 'LockoutDuration = 10' | Out-File -FilePath C:\secconfig.cfg

    #Upload Security Policy with Changes
    secedit.exe /configure /db $env:windir\securitynew.sdb /cfg C:\secconfig.cfg /areas SECURITYPOLICY
    
    #Disable Windows Hello Pin Logon
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowDomainPINLogon" -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowDomainPINLogonFallback" -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowDomainPINLogonPIN" -Value 0

    # Disable all other sign in options
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowSignInOptions" -Name "value" -Value 0

    # Force Change Password at Next Sign-in
    net user $env:USERNAME /logonpasswordchg:yes
   
    #Test NGC path if it exists and remove PINS
    $testPath = Test-Path -Path "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc"    
    
    if($testPath)
    {
    	# Give Administrative Privileges to Files
    	takeown /a /r /d Y /f C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc

	# Deletes Pin Password Files
    	Remove-Item  C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc\* -Recurse
    }

    # Deletes the Security Policy Document Export 
    Remove-Item c:\secconfig.cfg -Recurse -Force

    #Warning message for password Change
    Write-Warning "Current User Password has been changed too:

    Company134!!

    Please Remember this Password for the Next Login!!!

    System Will Require This Password at Next Login as This Will Force a Password Reset!!!
    "
    
}

function defaultPasswordPolicy(){

    #Set Password Length
    net accounts /minpwlen:0

    #Set Lockout Timer
    net accounts /lockoutwindow:0

    #Set Password Attempts before Lockout
    net accounts /lockoutthreshold:0

    #Download Security Policy
    secedit.exe /export /cfg C:\secconfig.cfg

    #Edit Security Policy
    (Get-Content -path C:\secconfig.cfg -Raw) -replace 'PasswordComplexity = 1', 'PasswordComplexity = 0' | Out-File -FilePath C:\secconfig.cfg -Force

    #Upload Security Policy with Changes
    secedit.exe /configure /db $env:windir\securitynew.sdb /cfg C:\secconfig.cfg /areas SECURITYPOLICY

    #Disable Windows Hello Pin
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowDomainPINLogon" -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowDomainPINLogonFallback" -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowDomainPINLogonPIN" -Value 1

    # Enable all other sign in options
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowSignInOptions" -Name "value" -Value 1

    # Deletes the Security Policy Document Export 
    Remove-Item c:\secconfig.cfg -Recurse -Force
}

function restorePoint(){

    Enable-ComputerRestore -Drive "C:\"

    Checkpoint-Computer -Description "RestorePoint" -RestorePointType "MODIFY_SETTINGS" 

    Write-Warning "Restore Point Has Been Created"
}


function allUsersPasswords(){

    $users = Get-Localuser

    #Secure Password
    $newPassword = "Company134!!" | ConvertTo-SecureString -AsPlainText -Force

    #Set Current Users New Password
    $changeUserPasswords = foreach($user in $users)
    {
        if($user.Enabled)
        {
            if($user.Name -ne "Admin")
            {    
                #Set Current Users New Password
                Set-LocalUser $user -Password $newPassword -UserMayChangePassword $true
		net user $user /logonpasswordchg:yes
		Write-Warning ('Username '+  $user.name + ' Password Changed')
            }        
        }
    }

    Write-Warning "All Enabled Users Passwords have been set to Company134!!"
}

function restartSystem(){
    
    $loop2 = 1

    while ($loop2 -eq 1) {
    
    $restartChoice = Read-Host "Would you like the system to restart and allow changes made to this system?`n
    [Y] Yes
    [N] No
    "

    switch($restartChoice){
        
        Y {
            # Restart System to allow changes
            Shutdown /r /t 10
            $loop2 = 0
          }
        N {
            #Warning message to let user know the system needs to restart to allow policy changes
            Write-Warning "`nPlease Be Aware Policy Changes Will Not Take Effect Unless The System Has Restarted`n"
		    $loop2 = 0
          }
	  default { Write-Warning "`nSorry I Didn't Get that?`n" }

    }
}

    
}

function intro {
    
    $loop = 1

    Write-Host "`n
    ==========================================

        //////  //////  ////// Password
       ///  // ///  // ///     Policy
      ///  // ///  // //////   Script
     //////  //////     ///
    ///     ///     //////     CREATED BY AG

    ==========================================
    "

    Write-Host "`nWelcome to the Local Password Policy Script
    `nType in one of the following commands below to start the script."


    $message = "`nThanks for Using the Password Policy Script"

    

    while ($loop -eq 1) {
        
        $choice = Read-Host "
        `n[S] Set Local Password Policy (This Will Change Password Policy to be more STRICT!)
        `n[C] Create a Restore Point (Do This Before Any Changes)
        `n[D] Default Policy Settings (This Will Restore Policy Changes)
        `n[A] Create a Local Admin Account
        `n[N] Change All Users Passwords
        `n[E] Exit Script
        "

         switch ( $choice )
        {
            S { setPasswordPolicy       }
            C { restorePoint            }   
            D { defaultPasswordPolicy   }
            A { createLocalAdmin        }
            N { allUsersPasswords }
            E { $Message 
                $loop = 0               }
            default {Write-Warning "`nSorry i Didnt get that please select one of the below options"}
        }
    }
   
}

intro

restartSystem