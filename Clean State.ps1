###//////////////////Program icon\\\\\\\\\\\\\\\\\\###

    [string]$icoBase64 =`
    "AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAA`
    ABMdv8ATHb/AEx2/wBMdv8FTHb/SEx2/6hMdv/kLl//+w5G//wMRf/lDUX/qQ1G/0oQSP8FDUb/AAxF/wA`
    VS/8ATHb/AEx2/wBMdv8XTHb/kkx2/+5Mdv//MmL//xBI//8MRf//DEX//wxF//8MRf/vDUX/kw5G/xgNR`
    v8ADEX/AEx2/wBMdv8XTHb/sUx2//9Ldv//MWL//w9I//8MRf//DEX//wxF//8MRf//DEX//wxF//8MRf+`
    yDkb/GA1G/wBMdv8FTHb/kkx2//9Ndfv/P17Z/xRG8/8LRf//DEX//wxF//8MRf//DEX//wxF//8MRf//D`
    EX//w1F/5MQSP8FTHb/SEx2/+5Ld///VWzN/2g7Iv9BNGf/EUPv/wtF//8MRf//DEX//wxF//8MRf//DEX`
    //wxF//8MRf/vDUb/Skx2/6hMdv//THb//1Fx5/9vUEb/bzQB/0I0Zv8RQ/D/C0X//wxF//8MRf//DEX//`
    wxF//8MRf//DEX//w1F/6lMdv/kTHb//0x2//9Mdv//UnDf/29QRf9vNAH/QjRm/xFD8P8LRf//DEX//wx`
    F//8MRf//DEX//wxF//8MRf/lTHb/+0x2//9Mdv//THb//0t3//9ScN//b1BF/280Af9CNGb/EUPw/wpF/`
    /8PR/7/C0T//wxF//8MRf//H1P//Ex2//tMdv//THb//0x2//9Mdv//S3f//1Jw3/9vUEX/bzQB/0AyZf8`
    /Y+X/iJ3j/y9e9/8KRP//I1f//0Zy//tMdv/kTHb//0x2//9Mdv//THb//0x2//9Ld///UnDf/21PRf+IX`
    Df/vbi+/9fV0P+msdv/NmT6/0Zx//9Nd//kTHb/qEx2//9Mdv//THb//0x2//9Mdv//THb//0p2//95j+P`
    /5t/b/+jn5f/U0tH/pLHh/1R7/P9Mdv//THb/qEx2/0hMdv/uTHb//0x2//9Mdv//THb//0t1//9fhP//3`
    OX////////+/fz/sL7u/1Z9+/9Ldf//THb/7kx2/0hMdv8FTHb/kkx2//9Mdv//THb//0x2//9Ldv//VHz`
    //6G3///Bz///qb7//1uC//9Ldf//THb//0x2/5JMdv8FTHb/AEx2/xdMdv+xTHb//0x2//9Mdv//THb//`
    0x2//9Ldf//TXf//0t1//9Ldf//THb//0x2/7FMdv8XTHb/AEx2/wBMdv8ATHb/F0x2/5JMdv/uTHb//0x`
    2//9Mdv//THb//0x2//9Mdv//THb/7kx2/5JMdv8XTHb/AEx2/wBMdv8ATHb/AEx2/wBMdv8FTHb/SEx2/`
    6hMdv/kTHb/+0x2//tMdv/kTHb/qEx2/0hMdv8FTHb/AEx2/wBMdv8AAAAAAAAAAAAAAAAAAAAAAAAAAAA`
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="

###\\\\\\\\\\\\\\\\\\\\\\####//////////////////////###

###/////////Externally Developed Functions\\\\\\\\\###

    function Get-installedSoftware
    {
        [cmdletbinding()]
        param
        (
            [parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
            [string[]]
            $ComputerName = $env:computername
        )

        begin
        {
            $UninstallRegKeys = @("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall","SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
        }

        process
        {
            foreach($Computer in $ComputerName)
            {
                Write-Verbose "Working on $Computer"
                if(Test-Connection -ComputerName $Computer -Count 1 -ea 0)
                {
                    foreach($UninstallRegKey in $UninstallRegKeys)
                    {
                        try
                        {
                            $HKLM   = [microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine',$computer)
                            $UninstallRef  = $HKLM.OpenSubKey($UninstallRegKey)
                            $Applications = $UninstallRef.GetSubKeyNames()
                        }
                        catch
                        {
                            Write-Verbose "Failed to read $UninstallRegKey"
                            Continue
			            }
                        foreach ($App in $Applications)
                        {
                            $AppRegistryKey  = $UninstallRegKey + "\\" + $App
                            $AppDetails   = $HKLM.OpenSubKey($AppRegistryKey)
                            $AppGUID   = $App
                            $AppDisplayName  = $($AppDetails.GetValue("DisplayName"))
                            $AppVersion   = $($AppDetails.GetValue("DisplayVersion"))
                            $AppPublisher  = $($AppDetails.GetValue("Publisher"))
                            $AppInstalledDate = $($AppDetails.GetValue("InstallDate"))
                            $AppUninstall  = $($AppDetails.GetValue("UninstallString"))
                                
                            if($UninstallRegKey -match "Wow6432Node")
                            {
                                    $Softwarearchitecture = "x86"
                            }
                            else
                            {
                            $Softwarearchitecture = "x64"
                            }
                            if(!$AppDisplayName)
                            {
                            continue
                            }

                            $OutputObj = New-Object -TypeName PSobject
                            $OutputObj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $Computer.ToUpper()
                            $OutputObj | Add-Member -MemberType NoteProperty -Name AppName -Value $AppDisplayName
                            $OutputObj | Add-Member -MemberType NoteProperty -Name AppVersion -Value $AppVersion
                            $OutputObj | Add-Member -MemberType NoteProperty -Name AppVendor -Value $AppPublisher
                            $OutputObj | Add-Member -MemberType NoteProperty -Name InstalledDate -Value $AppInstalledDate
                            $OutputObj | Add-Member -MemberType NoteProperty -Name UninstallKey -Value $AppUninstall
                            $OutputObj | Add-Member -MemberType NoteProperty -Name AppGUID -Value $AppGUID
                            $OutputObj | Add-Member -MemberType NoteProperty -Name SoftwareArchitecture -Value $Softwarearchitecture
                            $OutputObj
                        }
                    }
                }
            }
        }

        end
        {
            #
        }
    }

###\\\\\\\\\\\\\\\\\\\\\\####//////////////////////###

###//////////Internal-Developed Functions\\\\\\\\\\###

    ###///////////Program Internal Functions\\\\\\\\\\\###

        Function New-LocalUser
        {
            param
            (
                [parameter(Mandatory = $true)]
                [ValidateNotNullOrEmpty()]
                [string]
                $User,
                [parameter(Mandatory = $true)]
                [ValidateNotNullOrEmpty()]
                [string]
                $Passkey
            )

            $Computer = [ADSI]"WinNT://$Env:COMPUTERNAME,Computer"
            
            $labClient = $Computer.Create("User", "$User")
            $labClient.SetPassword("$Passkey")
            $labClient.SetInfo()
            $labClient.FullName = "$User"
            $labClient.SetInfo()
            $labClient.UserFlags = 64 + 65536 # ADS_UF_PASSWD_CANT_CHANGE + ADS_UF_DONT_EXPIRE_PASSWD
            $labClient.SetInfo()
        
            $group = [ADSI]"WinNT://./Users,group"
            $group.Add("WinNT://$user,user")
        }

        function Switch-console
        {
            param
            (
                [parameter(Mandatory = $false)]
                [switch]
                $on
            )
            
            Add-Type -Name Window -Namespace Console -MemberDefinition '
            [DllImport("Kernel32.dll")]
            public static extern IntPtr GetConsoleWindow();
            [DllImport("user32.dll")]
            public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
            '
            $consolePtr = [Console.Window]::GetConsoleWindow()
            
            if ($on)
            {
                [Console.Window]::ShowWindow($consolePtr, 5)
            }
            else
            {
                [Console.Window]::ShowWindow($consolePtr, 0)
            }
        }

        function Set-HideConsole
        {
            param
            (
                [parameter(Mandatory = $false)]
                [switch]
                $off
            )

            $windowcode = '[DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);'
            $asyncwindow = Add-Type -MemberDefinition $windowcode -name Win32ShowWindowAsync -namespace Win32Functions -PassThru
            $process = Get-Process -PID $pid

            If ($off)
            {
                $asyncwindow::ShowWindowAsync(($process).MainWindowHandle, 3)
            }
            else
            {
                $asyncwindow::ShowWindowAsync(($process).MainWindowHandle, 0)
            }
        }

        function close-Winform
        {
            param
            (
                [parameter(Mandatory = $false)]
                [switch]
                $stop
            )

            [System.Windows.Forms.Application]::Exit()

            if ($stop)
            {
                Stop-Process $pid
            }
        }

        Function New-Regkey
        {
            param
            (
                 [parameter(Mandatory = $true)]
                 [ValidateNotNullOrEmpty()]
                 [string]
                 $registryPath,
                 [parameter(Mandatory = $true)]
                 [ValidateNotNullOrEmpty()]
                 [string]
                 $RegName,
                 $Regvalue,
                 [parameter(Mandatory = $true)]
                 [String][ValidateSet("String", "ExpandString", "Binary", "DWord", "MultiString", "QWord", "Unknown")]
                 [ValidateNotNullOrEmpty()]
                 [string]
                 $RegType
            )

            $test = Test-Path $registryPath

            IF ($test -eq $false)
            {
                New-Item -Path $registryPath -Force | Out-Null
                New-ItemProperty -Path $registryPath -Name $Regname -Value $Regvalue -PropertyType $RegType -Force
            }
            ELSE
            {
                New-ItemProperty -Path $registryPath -Name $Regname -Value $Regvalue -PropertyType $RegType -Force
            }
        }

        function Expand-with7z
        {
            param
            (
                [parameter(Mandatory = $true)]
                [ValidateNotNullOrEmpty()]
                [string]
                $ZipPath
            )

            Start-Process -FilePath ".\7za.exe" -Wait -NoNewWindow -ArgumentList "X $ZipPath -aoa"
        }
        function Get-SupportedOs
        {
            $IsSupportedOs = $false
            $osMajor = [Environment]::OSVersion.Version.Major
            $osMinor = [Environment]::OSVersion.Version.Minor
            $winver = $osMajor.ToString() + "." + $osMinor.ToString()

            switch ($winver)
            {
                #WINDOWS 7 = 6.1
                "6.1" {$IsSupportedOs = $true; $script:OsVer = 7}
                #WINDOWS 8 probably 6.2
                #"6.2" {$IsSupportedOs = $true; $script:OsVer = 8}
                #WINDOWS 8.1 = 6.3
                #"6.3" {$IsSupportedOs = $true; $script:OsVer = 8.1}
                #WINDOWS 10 = 10.0
                "10.0" {$IsSupportedOs = $true; $script:OsVer = 10}
                Default {$IsSupportedOs = $false}
            }

            if ($IsSupportedOs -ne $true)
            {
                (new-object -ComObject wscript.shell).Popup("Operating system not supported: (Windows$winver)  Requires windows 7 or 10", 30, "Done")
                close-Winform #-stop
            }
        }

        function Test-SetupzipInplace
        {
            $setupfilescheck = Test-Path ".\Cleanstate-Setup-Files.zip"

            if ($setupfilescheck -eq $true)
            {
                Expand-with7z -ZipPath ".\Cleanstate-Setup-Files.zip"
            }
            else
            {
                (new-object -ComObject wscript.shell).Popup("Setup can not complete: Setup archive could not be found Not Found", 30, "Done")
                close-Winform #-stop
            }
        }

        function Test-FoldersInplace
        {
            $foldersShouldExist =`
            ".\Cleanstate-files",`
            ".\Cleanstate-Programs",`
            ".\Cleanstate-task"
            $Arefoldersmissing = $false
            $missingfolders = $null
            
            foreach ($folder in $foldersShouldExist)
            {
                if (((Test-Path $folder) -eq $true) -and ($Arefoldersmissing -eq $false))
                {
                    $Arefoldersmissing = $false
                }
                elseif ((Test-Path $folder) -eq $false)
                {
                    $Arefoldersmissing = $true
                    $missingfolders += $folder + ", "
                }
            }

            if ($Arefoldersmissing -eq $True)
            {
                (new-object -ComObject wscript.shell).Popup("Setup can not complete: Setup folders: $missingfolder Were Not Found", 30, "Done")
                Remove-SetupFiles
                close-Winform #-stop
            }
        }#

        function Set-checkboxslections
        {
            param
            (
                [parameter(Mandatory = $false)]
                [switch]
                $all,            
                [parameter(Mandatory = $false)]
                [switch]
                $clear
            )

            $numbers = 1..10

            if ($all)
            {
                foreach ($number in $Numbers)
                {
                    $checkbox = "$" + "ckb_" + $number.ToString() + ".checked = " + "`$True"
                    Invoke-Expression $checkbox
                }
            }
            if ($clear)
            {
                foreach ($number in $Numbers)
                {
                    $checkbox = "$" + "ckb_" + $number.ToString() + ".checked = " + "`$false"
                    Invoke-Expression $checkbox
                } 
            }
        }

        function Test-CheckboxSelection
        {
            $checkbox = $null
            $checkboxschecked = "0"
            $numbers = 0..10
            foreach ($number in $Numbers)
            {
                $checkbox = "(" + "$" + "ckb_" + $number.ToString() + ".checked" + " -eq " + "`$True" + ")"
                
                if ((Invoke-Expression $checkbox) -eq $true)
                {
                    $checkboxschecked += $number.ToString()
                }
            }
            return $checkboxschecked.ToCharArray()
        }
        
        Function Remove-SetupFiles
        {
            $foldersToDelete =`
            '.\Cleanstate-files',`
            '.\Cleanstate-Programs',`
            '.\Cleanstate-task'
            
            foreach ($folders in $foldersToDelete) 
            {
                Get-Item $folders | Remove-Item -Force -Recurse 
            }
        }

    ###\\\\\\\\\\\\\\\\\\\\\\####//////////////////////###

    ###/////Functions for installing to windows 10\\\\\###

        Function Switch-AutoLogon
        {
            param
            (
                [switch]
                $on
            )

            [string]$DefaultUserName = "LabClient"
            [string]$DefaultDomainName = ""
            [string]$AutoAdminLogon = 1
            [string]$passkey = "UserPass1"
            [string]$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            [string]$regtype = "String"

            if ($on)
            {
                New-Regkey -registryPath $registryPath -RegName "DefaultUserName" -RegType $regtype -Regvalue "$DefaultUserName"
                New-Regkey -registryPath $registryPath -RegName "DefaultDomainName" -RegType $regtype -Regvalue "$DefaultDomainName"
                New-Regkey -registryPath $registryPath -RegName "AutoAdminLogon" -RegType $regtype -Regvalue "$AutoAdminLogon"
                New-Regkey -registryPath $registryPath-RegName "DefaultPassword" -RegType $regtype -Regvalue "$passkey"
                (new-object -ComObject wscript.shell).Popup("Operation Completed: Autologon Set:ON", 2, "Done")
            }
            else
            {
                New-Regkey -registryPath $registryPath -RegName "DefaultUserName" -RegType $regtype -Regvalue ""
                New-Regkey -registryPath $registryPath -RegName "DefaultDomainName" -RegType $regtype -Regvalue ""
                New-Regkey -registryPath $registryPath -RegName "AutoAdminLogon" -RegType $regtype -Regvalue "0"
                New-Regkey -registryPath $registryPath -RegName "DefaultPassword" -RegType $regtype -Regvalue ""
                (new-object -ComObject wscript.shell).Popup("Operation Completed: Autologon Set:OFF", 2, "Done")
            }
        }#

        Function Install-AdobeReaderDC
        {
            (Start-Process '.\Cleanstate-Programs\AcroRdrDC\setup.exe' -Wait -PassThru).ExitCode
            (new-object -ComObject wscript.shell).Popup("Operation Completed: AdobeReaderDC", 2, "Done")
        }

        Function Install-Liberoffice
        {
            $argumentlist = "/passive ALLUSERS=1 ADDLOCAL=ALL CREATEDESKTOPLINKE=1 REGISTER_ALL_SMO_TYPES=1 UI_LANGS=en REMOVE=gm_o_Onlineupdate RebootYesNo=No"
            (Start-Process -FilePath ".\Cleanstate-Programs\LibreOffice_5.3.3.msi" -Wait -ArgumentList $argumentlist -Passthru).ExitCode
            (new-object -ComObject wscript.shell).Popup("Operation Completed: Liberoffice", 2, "Done")
        }#

        Function Install-Firefox
        {
            (Start-Process '.\Cleanstate-Programs\Firefox Setup 54.0.1.exe' -Wait -ArgumentList "-ms"  -PassThru).ExitCode
            (new-object -ComObject wscript.shell).Popup("Operation Completed: Firefox", 2, "Done")
        }

        Function Switch-LocalAdminNetworkFiltering
        {
            param([switch]$off)

            $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            $regname = "LocalAccountTokenFilterPolicy"
            $RegType = "DWORD"

            if ($off)
            {
                New-Regkey -registryPath $registryPath -RegName $regname -RegType $RegType -Regvalue "0"
            }
            else
            {
                New-Regkey -registryPath $registryPath -RegName $regname -RegType $RegType -Regvalue "1"
            }
            (new-object -ComObject wscript.shell).Popup("Operation Completed: LocalAdminNetworkFilteringSet", 2, "Done")
        }

        Function Import-LocalGroupPolicyLockDown
        {
            Copy-Item -Path ".\Cleanstate-files\windows\system32\GroupPolicyUsers\S-1-5-32-545" -Destination "C:\windows\system32\GroupPolicyUsers" -recurse -force -Verbose
            (new-object -ComObject wscript.shell).Popup("Operation Completed: LocalGroupPolicyLockdown", 2, "Done")
        }

        Function Install-DelProf2
        {
            Copy-Item -Path ".\Cleanstate-programs\DelProf2.exe" -Destination "C:\windows" -recurse -force -Verbose
            (new-object -ComObject wscript.shell).Popup("Operation Completed: DelProf2", 2, "Done")
        }

        Function Import-ProfileCleanupTask
        {
            schtasks /create /TN "clear profile" /xml ".\Cleanstate-task\clear profile.xml"
            schtasks /create /TN "map downloads" /xml ".\Cleanstate-task\map downloads.xml"
            (new-object -ComObject wscript.shell).Popup("Operation Completed: ProfileCleanupTask ", 2, "Done")
        }

        Function Import-ProfileDefaultsetting
        {
            Copy-Item -Path ".\Cleanstate-files\Program Files (x86)" -Destination "C:\" -recurse -force -Verbose
            Copy-Item -Path ".\Cleanstate-files\Users" -Destination "C:\" -recurse -force -Verbose
            (new-object -ComObject wscript.shell).Popup("Operation Completed: Default setting", 2, "Done")
        }

    ###\\\\\\\\\\\\\\\\\\\\\\####//////////////////////###

    ###/////Functions for installing to windows 7\\\\\\###
        #need to be implmented
    ###\\\\\\\\\\\\\\\\\\\\\\####//////////////////////###

    ###///////////Functions for uninstalling\\\\\\\\\\\###

        Function uninstall-AdobeReaderDC
        {
            $getlist = Get-installedSoftware
            $getlist | select-object AppName, AppGuid | where-object {$_.AppName -like "Adobe Acrobat Reader DC"} | Set-Variable -Name AdobeReaderDCguid
            $AdobeReaderDCguid.AppGUID | Set-Variable -Name AdobeReaderDC

            (Start-Process 'msiexec.exe' -Wait -ArgumentList "/x$AdobeReaderDC /qn" -PassThru).ExitCode
            (new-object -ComObject wscript.shell).Popup("Operation Completed: AdobeReaderDC", 2, "Done")
        }#
        
        Function uninstall-Liberoffice
        {
            $getlist = Get-installedSoftware
            $getlist | select-object AppName, AppGuid | where-object {$_.AppName -like "LibreOffice*"} | Set-Variable -Name liberguid
            $liberguid.AppGUID | Set-Variable -Name liber

            (Start-Process 'msiexec.exe' -Wait -ArgumentList "/norestart /quiet /x$liber" -verb "runas" -PassThru).ExitCode
            (new-object -ComObject wscript.shell).Popup("Operation Completed: Liberoffice", 2, "Done")
        }#

        Function Uninstall-Firefox
        {
            (Start-Process "C:\Program Files\Mozilla Firefox\uninstall\helper.exe" -Wait -ArgumentList "/S"  -PassThru).ExitCode
            (new-object -ComObject wscript.shell).Popup("Operation Completed: Uninstalled Firefox", 2, "Done")
        }

        Function Remove-User
        {
            param
            (
                [parameter(Mandatory = $true)]
                [ValidateNotNullOrEmpty()]
                [string]
                $User
            )

            $group = [ADSI]"WinNT://./Users,group"
            $group.Remove("WinNT://$user,user")

            $Computer = [ADSI]"WinNT://$Env:COMPUTERNAME,Computer"
            $Computer.Delete("User", $User)
        }

        Function Remove-DelProf2
        {
            $test = test-path  -Path "C:\windows\DelProf2.exe"

            if ($test -eq $true)
            {
                Remove-Item -Path "C:\windows\DelProf2.exe" -force -Verbose
                (new-object -ComObject wscript.shell).Popup("Operation Completed: Removed DelProf2", 2, "Done")
            }
            else
            {
                (new-object -ComObject wscript.shell).Popup("Operation Completed: DelProf2 not found", 2, "Done")
            }
        }#

        function Remove-ProfileCleanupTask
        {
            schtasks /delete /TN "clear profile" /F
            schtasks /delete /TN "map downloads" /F
            (new-object -ComObject wscript.shell).Popup("Operation Completed: Removed ProfileCleanupTask ", 2, "Done")
        }

        function Remove-LocalGroupPolicyLockDown
        {
            $test = Test-Path "C:\windows\system32\GroupPolicyUsers\S-1-5-32-545"

            if ($test -eq $true)
            {
                remove-Item -Path "C:\windows\system32\GroupPolicyUsers\S-1-5-32-545" -Recurse -Force -Verbose
                (new-object -ComObject wscript.shell).Popup("Operation Completed: Removed LocalGroupPolicyLockdown", 2, "Done")
            }
            else
            {
                (new-object -ComObject wscript.shell).Popup("Operation Completed: LocalGroupPolicyLockdowns where not found", 2, "Done")
            }

        }

        Function Remove-ProfileDefaultsetting
        {
            $PathNeedingTest = `
                "C:\Program Files (x86)\Mozilla Firefox\browser",`
                "C:\Program Files (x86)\Mozilla Firefox\defaults",`
                "C:\Users\Default\AppData\Roaming\LibreOffice",`
                "C:\Users\Default\AppData\Roaming\Mozilla"

            $PathTested = foreach ($PathToTest in $PathNeedingTest)
            {
                 test-path $PathToTest
            }

            if ($PathTested -contains $true) {
                foreach ($path in $PathNeedingTest)
                {
                    Remove-Item -Path $path -Force -Recurse -Verbose
                }
                (new-object -ComObject wscript.shell).Popup("Operation Completed: Removed Default settings", 2, "Done")
            }
            else
            {
                (new-object -ComObject wscript.shell).Popup("Operation Completed: No default settings where found", 2, "Done")
            }
        }#

    ###\\\\\\\\\\\\\\\\\\\\\\####//////////////////////###

###\\\\\\\\\\\\\\\\\\\\\\####//////////////////////###

###////////////////Gui intergration\\\\\\\\\\\\\\\\###

    Add-Type -AssemblyName System.Windows.Forms
    #Switch-console
    #Set-HideConsole

###\\\\\\\\\\\\\\\\\\\\\\####//////////////////////###

###///////////////////Gui design\\\\\\\\\\\\\\\\\\\###

    ###////////////////main window body\\\\\\\\\\\\\\\\###

        $Window = New-Object system.Windows.Forms.Form
        $Window.Text = "Clean State Setup"
        $Window.TopMost = $false
        $Window.AutoSize = $true
        $Window.Width = 500
        $Window.Height = 320
        $Window.StartPosition = "CenterScreen"
        $Window.FormBorderStyle = 'FixedSingle'
        $Window.MaximizeBox = $false
        $Window.BackColor = 'ControlDarkDark'
        $Window.Icon = ([System.Drawing.Icon](New-Object System.Drawing.Icon((New-Object System.IO.MemoryStream(($$ = [System.Convert]::FromBase64String("$icoBase64")), 0, $$.Length)))))

    ###\\\\\\\\\\\\\\\\\\\\\\####//////////////////////###

    ###///////////////////CheckBoxs\\\\\\\\\\\\\\\\\\\\###

        $ckb_0 = New-Object system.windows.Forms.CheckBox
        $ckb_0.Text = "Select All"
        $ckb_0.AutoSize = $true
        $ckb_0.Width = 95
        $ckb_0.Height = 20
        $ckb_0.location = new-object system.drawing.point(6, 20)
        $ckb_0.Font = "Microsoft Sans Serif,10"
        $Window.controls.Add($ckb_0)

        $ckb_1 = New-Object system.windows.Forms.CheckBox
        $ckb_1.Text = "Create LabClient user"
        $ckb_1.AutoSize = $true
        $ckb_1.Width = 95
        $ckb_1.Height = 20
        $ckb_1.location = new-object system.drawing.point(6, 40)
        $ckb_1.Font = "Microsoft Sans Serif,10"
        $Window.controls.Add($ckb_1)

        $ckb_2 = New-Object system.windows.Forms.CheckBox
        $ckb_2.Text = "Autologon of LabClient"
        $ckb_2.AutoSize = $true
        $ckb_2.Width = 95
        $ckb_2.Height = 20
        $ckb_2.location = new-object system.drawing.point(6, 60)
        $ckb_2.Font = "Microsoft Sans Serif,10"
        $Window.controls.Add($ckb_2)

        $ckb_3 = New-Object system.windows.Forms.CheckBox
        $ckb_3.Text = "Network access to computers for local admin"
        $ckb_3.AutoSize = $true
        $ckb_3.Width = 95
        $ckb_3.Height = 20
        $ckb_3.location = new-object system.drawing.point(6, 80)
        $ckb_3.Font = "Microsoft Sans Serif,10"
        $Window.controls.Add($ckb_3)

        $ckb_4 = New-Object system.windows.Forms.CheckBox
        $ckb_4.Text = "Local Group non-admin lock down Policies"
        $ckb_4.AutoSize = $true
        $ckb_4.Width = 95
        $ckb_4.Height = 20
        $ckb_4.location = new-object system.drawing.point(6, 100)
        $ckb_4.Font = "Microsoft Sans Serif,10"
        $Window.controls.Add($ckb_4)

        $ckb_5 = New-Object system.windows.Forms.CheckBox
        $ckb_5.Text = "AdobeReaderDC"
        $ckb_5.AutoSize = $true
        $ckb_5.Width = 95
        $ckb_5.Height = 20
        $ckb_5.location = new-object system.drawing.point(6, 120)
        $ckb_5.Font = "Microsoft Sans Serif,10"
        $Window.controls.Add($ckb_5)

        $ckb_6 = New-Object system.windows.Forms.CheckBox
        $ckb_6.Text = "Liberoffice suite"
        $ckb_6.AutoSize = $true
        $ckb_6.Width = 95
        $ckb_6.Height = 20
        $ckb_6.location = new-object system.drawing.point(6, 140)
        $ckb_6.Font = "Microsoft Sans Serif,10"
        $Window.controls.Add($ckb_6)

        $ckb_7 = New-Object system.windows.Forms.CheckBox
        $ckb_7.Text = "Modzilla Firefox"
        $ckb_7.AutoSize = $true
        $ckb_7.Width = 95
        $ckb_7.Height = 20
        $ckb_7.location = new-object system.drawing.point(6, 160)
        $ckb_7.Font = "Microsoft Sans Serif,10"
        $Window.controls.Add($ckb_7)

        $ckb_8 = New-Object system.windows.Forms.CheckBox
        $ckb_8.Text = "DelProf2 (Need for clearing Profiles)"
        $ckb_8.AutoSize = $true
        $ckb_8.Width = 95
        $ckb_8.Height = 20
        $ckb_8.location = new-object system.drawing.point(6, 180)
        $ckb_8.Font = "Microsoft Sans Serif,10"
        $Window.controls.Add($ckb_8)

        $ckb_9 = New-Object system.windows.Forms.CheckBox
        $ckb_9.Text = "Profile Task (Required for clearing Profiles)"
        $ckb_9.AutoSize = $true
        $ckb_9.Width = 95
        $ckb_9.Height = 20
        $ckb_9.location = new-object system.drawing.point(6, 200)
        $ckb_9.Font = "Microsoft Sans Serif,10"
        $Window.controls.Add($ckb_9)

        $ckb_10 = New-Object system.windows.Forms.CheckBox
        $ckb_10.Text = "Default Profile settings (required to Bypass Program First Runs)"
        $ckb_10.AutoSize = $true
        $ckb_10.Width = 95
        $ckb_10.Height = 20
        $ckb_10.location = new-object system.drawing.point(6, 220)
        $ckb_10.Font = "Microsoft Sans Serif,10"
        $Window.controls.Add($ckb_10)

    ###\\\\\\\\\\\\\\\\\\\\\\####//////////////////////###

    ###////////////////////Buttons\\\\\\\\\\\\\\\\\\\\\###
        $install = New-Object system.windows.Forms.Button
        $install.Text = "Install"
        $install.Width = 85
        $install.Height = 20
        $install.location = new-object system.drawing.point(6, 250)
        $install.Font = "Microsoft Sans Serif,10"
        $Window.controls.Add($install)

        $uninstall = New-Object system.windows.Forms.Button
        $uninstall.Text = "Uninstall"
        $uninstall.Width = 85
        $uninstall.Height = 20
        $uninstall.location = new-object system.drawing.point(385, 250)
        $uninstall.Font = "Microsoft Sans Serif,10"
        $Window.controls.Add($uninstall)

    ###\\\\\\\\\\\\\\\\\\\\\\####//////////////////////###

    ###/////////////////////Label\\\\\\\\\\\\\\\\\\\\\\###

        $label1 = New-Object system.windows.Forms.Label
        $label1.Text = "Clean State Items"
        $label1.AutoSize = $true
        $label1.Width = 25
        $label1.Height = 10
        $label1.location = new-object system.drawing.point(6, 2)
        $label1.Font = "Microsoft Sans Serif,10"
        $Window.controls.Add($label1)

    ###\\\\\\\\\\\\\\\\\\\\\\####//////////////////////###

###\\\\\\\\\\\\\\\\\\\\\\####//////////////////////###

###/////////////////Program logic\\\\\\\\\\\\\\\\\\###

    Get-SupportedOs
    (new-object -ComObject wscript.shell).Popup("CleanState Setup Files Extracting this could take a min", 2, "Done")
    Test-SetupzipInplace
    Test-FoldersInplace

    $ckb_0.Add_Click({
        if ($ckb_0.Checked -eq $true)
        {
            Set-checkboxslections -all
        }
        else
        {
            Set-checkboxslections -clear
        }
    })

    $install.Add_Click({
        if ($OsVer -eq 10)
        {
            $NothingWasSelected = $false
            $checkboxschecked = $null
            $checkboxschecked = (Test-CheckboxSelection)

            switch ($checkboxschecked)
            {
                "1" {New-LocalUser -User 'labClient' -Passkey 'UserPass1'}
                "2" {Switch-AutoLogon -on}
                "3" {Switch-LocalAdminNetworkFiltering -off}
                "4" {Import-LocalGroupPolicyLockDown}
                "5" {Install-AdobeReaderDC}
                "6" {Install-Liberoffice}                
                "7" {Install-Firefox}
                "8" {Install-DelProf2}
                "9" {Import-ProfileCleanupTask}
                "10" {Import-ProfileDefaultsetting}
            }

            if (($checkboxschecked -contains "0") -and ($checkboxschecked.Length -eq 1)) 
            {
                (new-object -ComObject wscript.shell).Popup("Nothing was selected", 2, "Done")
                $NothingWasSelected = $true
            }

            if ($NothingWasSelected -eq $false)
            {
                (new-object -ComObject wscript.shell).Popup("Selected Operations have Completed", 2, "Done")
                Set-checkboxslections -clear
            }
        }
        <#
        win 7 need to be implmented
        if  ($OsVer -eq 7)
        {
            $NothingWasSelected = $false
            $checkboxschecked = $null
            $checkboxschecked = (Test-CheckboxSelection)

            switch ($checkboxschecked)
            {
                "1" {New-LocalUser -User 'labClient' -Passkey 'UserPass1'}
                "2" {Switch-AutoLogon -on}
                "3" {Switch-LocalAdminNetworkFiltering -off}
                "4" {Import-LocalGroupPolicyLockDown}
                "5" {Install-AdobeReaderDC}
                "6" {Install-Liberoffice}                
                "7" {Install-Firefox}
                "8" {Install-DelProf2}
                "9" {Import-ProfileCleanupTask}
                "10" {Import-ProfileDefaultsetting}
            }

            if (($checkboxschecked -contains "0") -and ($checkboxschecked.Length -eq 1)) 
            {
                (new-object -ComObject wscript.shell).Popup("Nothing was selected", 2, "Done")
                $NothingWasSelected = $true
            }

            if ($NothingWasSelected -eq $false)
            {
                (new-object -ComObject wscript.shell).Popup("Selected Operations have Completed", 2, "Done")
                Set-checkboxslections -clear
            }
        }
        #>
    })

    $uninstall.Add_Click({

        $NothingWasSelected = $false 
        $checkboxschecked = $null
        $checkboxschecked = (Test-CheckboxSelection)

        switch ($checkboxsChecked)
        {
            "1" {Remove-User -User 'labClient'}
            "2" {Switch-AutoLogon}
            "3" {Switch-LocalAdminNetworkFiltering}
            "4" {Remove-LocalGroupPolicyLockDown}
            "5" {uninstall-AdobeReaderDC}
            "6" {uninstall-Liberoffice}               
            "7" {Uninstall-Firefox}
            "8" {Remove-DelProf2}
            "9" {Remove-ProfileCleanupTask}
            "10" {Remove-ProfileDefaultsetting}
        }

        if (($checkboxschecked -contains "0") -and ($checkboxschecked.Length -eq 1))
        {
            (new-object -ComObject wscript.shell).Popup("Nothing was selected", 2, "Done")
            $NothingWasSelected = $true
        }
        if ($NothingWasSelected -eq $false)
        {
            (new-object -ComObject wscript.shell).Popup("Selected Operations have Completed", 2, "Done")
            Set-checkboxslections -clear
        }
    })

###\\\\\\\\\\\\\\\\\\\\\\####//////////////////////###

###///////////Gui concluion intergration\\\\\\\\\\\###

    $Window.Add_Closing({
        (new-object -ComObject wscript.shell).Popup("Cleaning up setup file will take a second", 1, "Done")
        Remove-SetupFiles
        close-Winform #-stop
        Switch-console -on
        Set-HideConsole -off
    })

    $Window.Show()
    $Window.Activate()
    $appContext = New-Object System.Windows.Forms.ApplicationContext
    [void][System.Windows.Forms.Application]::Run($appContext)

###\\\\\\\\\\\\\\\\\\\\\\####//////////////////////###
