#
# Build script for Real Anti-Ransomware Kernel Driver
# Compiles using Windows Driver Kit (WDK)
#

# Check for required environment
!IF !EXIST("$(BASEDIR)")
!ERROR Windows Driver Kit (WDK) environment not found. Please run from WDK Build Environment.
!ENDIF

# Build configuration
BUILD_ALT_DIR = obj$(BUILD_ALT_DIR)
MAJORCOMP = security
MINORCOMP = antiransomware

# Target configuration  
TARGETNAME = RealAntiRansomwareDriver
TARGETPATH = $(BUILD_ALT_DIR)
TARGETTYPE = DRIVER

# Include WDK build definitions
!INCLUDE $(NTMAKEENV)\makefile.def

# Build rules
all: $(TARGETPATH)\$(TARGETNAME).sys

$(TARGETPATH)\$(TARGETNAME).sys: $(SOURCES)
    @echo Building Real Anti-Ransomware Kernel Driver...
    @echo Target: $(TARGETPATH)\$(TARGETNAME).sys
    @echo Sources: $(SOURCES)

clean:
    @echo Cleaning build artifacts...
    @if exist $(BUILD_ALT_DIR) rmdir /s /q $(BUILD_ALT_DIR)
    @if exist $(TARGETNAME).pdb del $(TARGETNAME).pdb

# Install target (requires administrator privileges)
install: $(TARGETPATH)\$(TARGETNAME).sys
    @echo Installing kernel driver...
    @copy "$(TARGETPATH)\$(TARGETNAME).sys" "$(SYSTEMROOT)\System32\drivers\"
    @pnputil /add-driver RealAntiRansomwareDriver.inf /install

# Uninstall target
uninstall:
    @echo Uninstalling kernel driver...
    @sc stop RealAntiRansomwareFilter 2>nul || echo Service not running
    @sc delete RealAntiRansomwareFilter 2>nul || echo Service not found
    @del "$(SYSTEMROOT)\System32\drivers\$(TARGETNAME).sys" 2>nul || echo Driver file not found

# Sign driver (production)
sign: $(TARGETPATH)\$(TARGETNAME).sys
    @echo Signing driver for production deployment...
    @signtool sign /v /ac "Microsoft Code Verification Root" /a /t http://timestamp.digicert.com $(TARGETPATH)\$(TARGETNAME).sys

.PHONY: all clean install uninstall sign
