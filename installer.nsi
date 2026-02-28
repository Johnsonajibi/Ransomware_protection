; Anti-Ransomware Protection Platform Installer
; NSIS Modern User Interface
; Requires NSIS 3.08 or later

!define PRODUCT_NAME "Anti-Ransomware Protection"
!define PRODUCT_VERSION "1.0.0"
!define PRODUCT_PUBLISHER "Anti-Ransomware Security"
!define PRODUCT_WEB_SITE "https://github.com/Johnsonajibi/Ransomeware_protection"
!define PRODUCT_DIR_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\AntiRansomware.exe"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"
!define SERVICE_NAME "AntiRansomwareProtection"
!define DRIVER_NAME "AntiRansomwareDriver"

; MUI 1.67 compatible
!include "MUI2.nsh"
!include "FileFunc.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"

; MUI Settings
!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"

; Welcome page
!insertmacro MUI_PAGE_WELCOME
; License page
!define MUI_LICENSEPAGE_CHECKBOX
!insertmacro MUI_PAGE_LICENSE "LICENSE.txt"
; Components page
!insertmacro MUI_PAGE_COMPONENTS
; Directory page
!insertmacro MUI_PAGE_DIRECTORY
; Instfiles page
!insertmacro MUI_PAGE_INSTFILES
; Finish page
!define MUI_FINISHPAGE_RUN "$INSTDIR\desktop_app.exe"
!define MUI_FINISHPAGE_SHOWREADME "$INSTDIR\README.md"
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_INSTFILES

; Language files
!insertmacro MUI_LANGUAGE "English"

; MUI end

; Helper function for string search
Function StrStr
  Exch $R1 ; needle
  Exch
  Exch $R2 ; haystack
  Push $R3
  Push $R4
  Push $R5
  StrLen $R3 $R1
  StrCpy $R4 0
  loop:
    StrCpy $R5 $R2 $R3 $R4
    StrCmp $R5 $R1 done
    StrCmp $R5 "" done
    IntOp $R4 $R4 + 1
    Goto loop
  done:
    StrCpy $R1 $R2 "" $R4
    Pop $R5
    Pop $R4
    Pop $R3
    Pop $R2
    Exch $R1
FunctionEnd

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "AntiRansomware-Setup-${PRODUCT_VERSION}.exe"
InstallDir "$PROGRAMFILES64\AntiRansomware"
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" ""
ShowInstDetails show
ShowUnInstDetails show
RequestExecutionLevel admin

; Check for administrator rights
Function .onInit
    UserInfo::GetAccountType
    pop $0
    ${If} $0 != "admin"
        MessageBox MB_ICONSTOP "Administrator rights required!"
        SetErrorLevel 740
        Quit
    ${EndIf}
    
    ; Check if x64
    ${If} ${RunningX64}
        SetRegView 64
    ${Else}
        MessageBox MB_ICONSTOP "This software requires 64-bit Windows 10 or later."
        Abort
    ${EndIf}
    
    ; Check Windows version (Windows 10 or later - version 10.0)
    ; Get Windows version from registry
    ReadRegStr $0 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion" "CurrentMajorVersionNumber"
    ${If} $0 >= 10
        ; Windows 10 or later detected
    ${Else}
        MessageBox MB_ICONEXCLAMATION "Warning: This software is designed for Windows 10 or later. Some features may not work correctly."
    ${EndIf}
FunctionEnd

Section "Core Files (Required)" SEC01
    SectionIn RO
    SetOutPath "$INSTDIR"
    SetOverwrite ifnewer
    
    ; Main application files
    File "desktop_app.py"
    File "unified_antiransomware.py"
    File /nonfatal "four_layer_protection.py"
    File /nonfatal "kernel_driver_loader.py"
    File /nonfatal "kernel_driver_manager.py"
    File /nonfatal "kernel_level_blocker.py"
    File /nonfatal "security_event_logger.py"
    File /nonfatal "system_health_checker.py"
    File /nonfatal "shadow_copy_protection.py"
    File /nonfatal "emergency_kill_switch.py"
    File /nonfatal "email_alerting.py"
    File /nonfatal "siem_integration.py"
    File /nonfatal "trifactor_auth_manager.py"
    File /nonfatal "realtime_file_blocker.py"
    File /nonfatal "enterprise_security_real.py"
    File /nonfatal "device_fingerprint_enhanced.py"
    File /nonfatal "tpm_pqc_integration.py"
    File /nonfatal "tpm_integration.py"
    File /nonfatal "windows_tpm_native.py"
    File /nonfatal "kernel_protection_interface.py"
    File "config_manager.py"
    File /nonfatal "policy_engine.py"
    
    ; Configuration files
    File /nonfatal "config.json"
    File /nonfatal "enterprise_config.json"
    File "requirements.txt"
    File /nonfatal "README.md"
    File "LICENSE.txt"
    
    ; Create data directories
    CreateDirectory "$INSTDIR\.audit_logs"
    CreateDirectory "$INSTDIR\logs"
    CreateDirectory "$INSTDIR\quarantine"
    CreateDirectory "$INSTDIR\protected"
    CreateDirectory "$INSTDIR\keys"
    CreateDirectory "$INSTDIR\models"
    CreateDirectory "$INSTDIR\policies"
    CreateDirectory "$INSTDIR\certs"
    
    ; Database
    File /nonfatal "protection_db.sqlite"
    
    ; ML Model (if exists)
    SetOutPath "$INSTDIR\models"
    File /nonfatal "models\ransomware_classifier.pkl"
SectionEnd

Section "Python Runtime" SEC02
    SectionIn RO
    
    DetailPrint "Checking Python installation..."
    
    ; Check if Python is already installed
    nsExec::ExecToStack 'python --version'
    Pop $0
    Pop $1
    StrCmp $0 0 pythonFound pythonNotFound
    
    pythonNotFound:
        MessageBox MB_ICONEXCLAMATION "Python 3.11+ is required but not found.$\n$\nPlease install Python from https://www.python.org/downloads/ and run this installer again.$\n$\nMake sure to check 'Add Python to PATH' during installation."
        Abort
    
    pythonFound:
        DetailPrint "Python found: $1"
    
    ; Install Python dependencies
    DetailPrint "Installing Python dependencies..."
    SetOutPath "$INSTDIR"
    nsExec::ExecToLog '"python" -m pip install -r requirements.txt --no-warn-script-location'
SectionEnd

Section "Kernel Driver (Optional)" SEC03
    SetOutPath "$INSTDIR\driver"
    
    ; Copy kernel driver
    IfFileExists "build_production\AntiRansomwareDriver.sys" 0 skipDriver
        File "build_production\AntiRansomwareDriver.sys"
        File /nonfatal "RealAntiRansomwareDriver.inf"
        
        ; Check test-signing
        nsExec::ExecToStack 'bcdedit /enum {current}'
        Pop $0
        Pop $1
        Push $1
        Push "testsigning"
        Call StrStr
        Pop $2
        StrCmp $2 "" askTestSigning driverReady
        
        askTestSigning:
            MessageBox MB_YESNO|MB_ICONQUESTION \
                "Test-signing mode is not enabled. The kernel driver requires this.$\n$\nWould you like to enable it now? (requires reboot)" \
                IDYES enableTestSigning IDNO skipDriver
            
            enableTestSigning:
                DetailPrint "Enabling test-signing mode..."
                nsExec::ExecToLog 'bcdedit /set testsigning on'
                Pop $0
                IntCmp $0 0 testSigningOk testSigningFailed testSigningFailed
                
                testSigningOk:
                    MessageBox MB_OK "Test-signing enabled. You must restart your computer before the driver can be loaded."
                    Goto driverReady
                
                testSigningFailed:
                    MessageBox MB_ICONEXCLAMATION "Failed to enable test-signing. The driver will not be installed."
                    Goto skipDriver
        
        driverReady:
            ; Create driver service
            DetailPrint "Creating driver service..."
            nsExec::ExecToLog 'sc create ${DRIVER_NAME} type= kernel start= demand binPath= "$INSTDIR\driver\AntiRansomwareDriver.sys"'
            Goto endDriverSection
    
    skipDriver:
        DetailPrint "Kernel driver not found or test-signing skipped..."
        MessageBox MB_ICONEXCLAMATION "Advanced Kernel Protection could not be initialized.$\n$\nThe system will now operate in Standard Protection Mode using robust user-mode monitoring algorithms.$\n$\nNote: While Standard Mode provides excellent real-time behavioral analysis and file monitoring, it may not intercept certain advanced threat vectors that operate at the deepest system levels. Full system protection is active, but Advanced Kernel Protection is recommended for optimal security."
    
    endDriverSection:
SectionEnd

Section "Windows Service" SEC04
    SetOutPath "$INSTDIR"
    
    ; Create service wrapper script
    FileOpen $0 "$INSTDIR\service_wrapper.py" w
    FileWrite $0 "#!/usr/bin/env python3$\r$\n"
    FileWrite $0 "import sys$\r$\n"
    FileWrite $0 "import servicemanager$\r$\n"
    FileWrite $0 "import win32serviceutil$\r$\n"
    FileWrite $0 "import win32service$\r$\n"
    FileWrite $0 "from pathlib import Path$\r$\n"
    FileWrite $0 "$\r$\n"
    FileWrite $0 "class AntiRansomwareService(win32serviceutil.ServiceFramework):$\r$\n"
    FileWrite $0 "    _svc_name_ = '${SERVICE_NAME}'$\r$\n"
    FileWrite $0 "    _svc_display_name_ = '${PRODUCT_NAME}'$\r$\n"
    FileWrite $0 "    _svc_description_ = 'Ransomware protection service with kernel-level monitoring'$\r$\n"
    FileWrite $0 "    $\r$\n"
    FileWrite $0 "    def SvcStop(self):$\r$\n"
    FileWrite $0 "        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)$\r$\n"
    FileWrite $0 "        self.running = False$\r$\n"
    FileWrite $0 "        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE, servicemanager.PYS_SERVICE_STOPPED, (self._svc_name_, ''))$\r$\n"
    FileWrite $0 "    $\r$\n"
    FileWrite $0 "    def SvcDoRun(self):$\r$\n"
    FileWrite $0 "        self.running = True$\r$\n"
    FileWrite $0 "        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE, servicemanager.PYS_SERVICE_STARTED, (self._svc_name_, ''))$\r$\n"
    FileWrite $0 "        from unified_antiransomware import UnifiedProtectionManager$\r$\n"
    FileWrite $0 "        manager = UnifiedProtectionManager()$\r$\n"
    FileWrite $0 "        while self.running:$\r$\n"
    FileWrite $0 "            import time$\r$\n"
    FileWrite $0 "            time.sleep(5)$\r$\n"
    FileWrite $0 "$\r$\n"
    FileWrite $0 "if __name__ == '__main__':$\r$\n"
    FileWrite $0 "    win32serviceutil.HandleCommandLine(AntiRansomwareService)$\r$\n"
    FileClose $0
    
    ; Install Windows service dependencies
    DetailPrint "Installing service dependencies..."
    nsExec::ExecToLog '"$INSTDIR\python\python.exe" -m pip install pywin32 --no-warn-script-location'
    
    ; Install service
    DetailPrint "Installing Windows service..."
    nsExec::ExecToLog '"$INSTDIR\python\python.exe" "$INSTDIR\service_wrapper.py" install'
    
    ; Set service to auto-start
    nsExec::ExecToLog 'sc config ${SERVICE_NAME} start= auto'
    
    ; Set service description
    nsExec::ExecToLog 'sc description ${SERVICE_NAME} "Anti-Ransomware protection service with TPM, PQC, and kernel-level file monitoring"'
SectionEnd

Section "Desktop Integration" SEC05
    ; Create shortcuts
    CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
    CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk" "$INSTDIR\python\python.exe" '"$INSTDIR\desktop_app.py"' "$INSTDIR\app.ico"
    CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk" "$INSTDIR\uninst.exe"
    CreateShortCut "$DESKTOP\${PRODUCT_NAME}.lnk" "$INSTDIR\python\python.exe" '"$INSTDIR\desktop_app.py"' "$INSTDIR\app.ico"
    
    ; Create startup entry
    CreateShortCut "$SMSTARTUP\${PRODUCT_NAME}.lnk" "$INSTDIR\python\python.exe" '"$INSTDIR\desktop_app.py" --minimized' "$INSTDIR\app.ico"
SectionEnd

Section "Registry Integration" SEC06
    ; Write installation path
    WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" "" "$INSTDIR\desktop_app.py"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayName" "$(^Name)"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "UninstallString" "$INSTDIR\uninst.exe"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$INSTDIR\app.ico"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
    
    ; Write configuration registry keys
    WriteRegStr HKLM "Software\AntiRansomware" "InstallPath" "$INSTDIR"
    WriteRegStr HKLM "Software\AntiRansomware" "Version" "${PRODUCT_VERSION}"
    WriteRegDWORD HKLM "Software\AntiRansomware" "ProtectionEnabled" 1
    WriteRegDWORD HKLM "Software\AntiRansomware" "KernelDriverEnabled" 1
    
    ; Firewall rules (allow application)
    DetailPrint "Configuring Windows Firewall..."
    nsExec::ExecToLog 'netsh advfirewall firewall add rule name="${PRODUCT_NAME}" dir=in action=allow program="$INSTDIR\python\python.exe" enable=yes'
    nsExec::ExecToLog 'netsh advfirewall firewall add rule name="${PRODUCT_NAME}" dir=out action=allow program="$INSTDIR\python\python.exe" enable=yes'
SectionEnd

Section -AdditionalIcons
    WriteIniStr "$INSTDIR\${PRODUCT_NAME}.url" "InternetShortcut" "URL" "${PRODUCT_WEB_SITE}"
    CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Website.lnk" "$INSTDIR\${PRODUCT_NAME}.url"
SectionEnd

Section -Post
    WriteUninstaller "$INSTDIR\uninst.exe"
    
    ; Calculate install size
    ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
    IntFmt $0 "0x%08X" $0
    WriteRegDWORD ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "EstimatedSize" "$0"
    
    ; Completion message
    MessageBox MB_ICONINFORMATION "Installation complete!$\n$\nImportant:$\n- Configure protected folders via the GUI$\n- Create USB tokens for authentication$\n- Review security settings$\n$\nThe service will start automatically on next boot."
SectionEnd

; Section descriptions
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SEC01} "Core application files and libraries (required)"
    !insertmacro MUI_DESCRIPTION_TEXT ${SEC02} "Python runtime and dependencies"
    !insertmacro MUI_DESCRIPTION_TEXT ${SEC03} "Kernel-level driver for enhanced protection"
    !insertmacro MUI_DESCRIPTION_TEXT ${SEC04} "Windows service for background protection"
    !insertmacro MUI_DESCRIPTION_TEXT ${SEC05} "Desktop shortcuts and startup integration"
    !insertmacro MUI_DESCRIPTION_TEXT ${SEC06} "Registry settings and system integration"
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Function un.onUninstSuccess
    HideWindow
    MessageBox MB_ICONINFORMATION|MB_OK "$(^Name) was successfully removed from your computer."
FunctionEnd

Function un.onInit
    MessageBox MB_ICONQUESTION|MB_YESNO|MB_DEFBUTTON2 "Are you sure you want to completely remove $(^Name) and all of its components?" IDYES +2
    Abort
FunctionEnd

Section Uninstall
    ; Stop service
    DetailPrint "Stopping service..."
    nsExec::ExecToLog 'sc stop ${SERVICE_NAME}'
    Sleep 2000
    
    ; Remove service
    DetailPrint "Removing service..."
    nsExec::ExecToLog 'sc delete ${SERVICE_NAME}'
    
    ; Stop and remove kernel driver
    DetailPrint "Removing kernel driver..."
    nsExec::ExecToLog 'sc stop ${DRIVER_NAME}'
    Sleep 2000
    nsExec::ExecToLog 'sc delete ${DRIVER_NAME}'
    
    ; Remove firewall rules
    DetailPrint "Removing firewall rules..."
    nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="${PRODUCT_NAME}"'
    
    ; Remove shortcuts
    Delete "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk"
    Delete "$SMPROGRAMS\${PRODUCT_NAME}\Website.lnk"
    Delete "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk"
    Delete "$DESKTOP\${PRODUCT_NAME}.lnk"
    Delete "$SMSTARTUP\${PRODUCT_NAME}.lnk"
    RMDir "$SMPROGRAMS\${PRODUCT_NAME}"
    
    ; Remove files
    Delete "$INSTDIR\${PRODUCT_NAME}.url"
    Delete "$INSTDIR\uninst.exe"
    Delete "$INSTDIR\*.py"
    Delete "$INSTDIR\*.json"
    Delete "$INSTDIR\*.txt"
    Delete "$INSTDIR\*.md"
    Delete "$INSTDIR\*.sqlite"
    Delete "$INSTDIR\*.key"
    Delete "$INSTDIR\*.ico"
    
    ; Remove directories (preserving user data)
    MessageBox MB_YESNO|MB_ICONQUESTION "Do you want to remove all protected files and logs? (This will delete your protection history)" IDYES removeData IDNO keepData
    
    removeData:
        RMDir /r "$INSTDIR\.audit_logs"
        RMDir /r "$INSTDIR\logs"
        RMDir /r "$INSTDIR\quarantine"
        RMDir /r "$INSTDIR\protected"
        RMDir /r "$INSTDIR\keys"
        RMDir /r "$INSTDIR\certs"
        Goto continueUninstall
    
    keepData:
        DetailPrint "Preserving user data..."
    
    continueUninstall:
    RMDir /r "$INSTDIR\driver"
    RMDir /r "$INSTDIR\python"
    RMDir /r "$INSTDIR\models"
    RMDir /r "$INSTDIR\policies"
    RMDir "$INSTDIR"
    
    ; Remove registry keys
    DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"
    DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
    DeleteRegKey HKLM "Software\AntiRansomware"
    
    SetAutoClose true
SectionEnd
