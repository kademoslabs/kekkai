"""PowerShell installer script generation for Windows package managers."""


def generate_installer_script(
    whl_url: str,
    python_version: str = "3.12",
) -> str:
    """
    Generate PowerShell installer script for Kekkai.

    Uses minimal logic to reduce attack surface:
    - Validates Python version
    - Uses pip to install wheel
    - No remote code execution patterns (no Invoke-Expression)
    - HTTPS-only URLs

    Args:
        whl_url: URL to wheel file (must be HTTPS)
        python_version: Minimum Python version required

    Returns:
        PowerShell script as string

    Raises:
        ValueError: If URL is not HTTPS
    """
    if not whl_url.startswith("https://"):
        raise ValueError(f"URL must use HTTPS: {whl_url}")

    # Use heredoc-style string with explicit escaping
    script = f"""# Kekkai Installation Script
# Generated for Windows package managers (Scoop/Chocolatey)

# Validate Python availability
try {{
    $pythonCmd = Get-Command python -ErrorAction Stop
    Write-Host "Found Python: $($pythonCmd.Source)"
}} catch {{
    Write-Error "Python not found in PATH. Please install Python {python_version}+ first."
    exit 1
}}

# Validate Python version
try {{
    $pythonVersionOutput = python --version 2>&1 | Out-String
    if ($pythonVersionOutput -match "Python (\\d+\\.\\d+)") {{
        $installedVersion = [version]$matches[1]
        $requiredVersion = [version]"{python_version}"

        if ($installedVersion -lt $requiredVersion) {{
            Write-Error "Python {python_version}+ required, found $installedVersion"
            exit 1
        }}

        Write-Host "Python version check passed: $installedVersion"
    }} else {{
        Write-Error "Could not parse Python version from: $pythonVersionOutput"
        exit 1
    }}
}} catch {{
    Write-Error "Failed to check Python version: $_"
    exit 1
}}

# Validate pip availability
try {{
    python -m pip --version | Out-Null
    if ($LASTEXITCODE -ne 0) {{
        throw "pip check failed"
    }}
    Write-Host "pip is available"
}} catch {{
    Write-Error "pip is not available. Please ensure pip is installed."
    exit 1
}}

# Install Kekkai wheel with force-reinstall and no-deps
Write-Host "Installing Kekkai from: {whl_url}"
try {{
    python -m pip install --force-reinstall --no-deps "{whl_url}"

    if ($LASTEXITCODE -ne 0) {{
        throw "pip install failed with exit code $LASTEXITCODE"
    }}

    Write-Host "✅ Kekkai installed successfully!"
    Write-Host ""
    Write-Host "Run 'kekkai --help' to get started."
}} catch {{
    Write-Error "Installation failed: $_"
    exit 1
}}
"""

    return script


def generate_uninstaller_script() -> str:
    """
    Generate PowerShell uninstaller script for Kekkai.

    Returns:
        PowerShell uninstall script as string
    """
    script = """# Kekkai Uninstallation Script
# Generated for Windows package managers (Scoop/Chocolatey)

try {
    Write-Host "Uninstalling Kekkai..."

    # Check if pip is available
    python -m pip --version | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "pip is not available, skipping uninstall"
        exit 0
    }

    # Uninstall Kekkai
    python -m pip uninstall -y kekkai

    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Kekkai uninstalled successfully"
    } else {
        Write-Warning "Kekkai may not have been installed or was already removed"
    }
} catch {
    Write-Warning "Uninstall encountered an issue: $_"
    # Don't fail on uninstall errors
    exit 0
}
"""

    return script


def generate_chocolatey_install_script(
    version: str,
    sha256: str,
    python_version: str = "3.12",
) -> str:
    """
    Generate chocolateyinstall.ps1 script for Chocolatey package.

    Args:
        version: Package version
        sha256: Expected SHA256 checksum
        python_version: Minimum Python version required

    Returns:
        Chocolatey install script as string
    """
    whl_url = f"https://github.com/kademoslabs/kekkai/releases/download/v{version}/kekkai-{version}-py3-none-any.whl"

    if not whl_url.startswith("https://"):
        raise ValueError(f"URL must use HTTPS: {whl_url}")

    script = f"""# Kekkai Chocolatey Installation Script
$ErrorActionPreference = 'Stop'

$packageName = 'kekkai'
$version = '{version}'
$url = '{whl_url}'
$checksum = '{sha256}'
$checksumType = 'sha256'

Write-Host "Installing $packageName version $version..."

# Validate Python availability
try {{
    $pythonCmd = Get-Command python -ErrorAction Stop
    Write-Host "Found Python: $($pythonCmd.Source)"
}} catch {{
    throw "Python not found in PATH. Please install Python {python_version}+ first."
}}

# Validate Python version
$pythonVersionOutput = python --version 2>&1 | Out-String
if ($pythonVersionOutput -match "Python (\\d+\\.\\d+)") {{
    $installedVersion = [version]$matches[1]
    $requiredVersion = [version]"{python_version}"

    if ($installedVersion -lt $requiredVersion) {{
        throw "Python {python_version}+ required, found $installedVersion"
    }}

    Write-Host "Python version check passed: $installedVersion"
}} else {{
    throw "Could not parse Python version"
}}

# Download wheel file to temp location
$tempDir = Join-Path $env:TEMP "kekkai-$version"
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
$whlFile = Join-Path $tempDir "kekkai-$version-py3-none-any.whl"

Write-Host "Downloading wheel from: $url"
try {{
    Invoke-WebRequest -Uri $url -OutFile $whlFile -UseBasicParsing
}} catch {{
    throw "Failed to download wheel: $_"
}}

# Verify checksum
Write-Host "Verifying checksum..."
$actualChecksum = (Get-FileHash -Path $whlFile -Algorithm SHA256).Hash
if ($actualChecksum -ne $checksum) {{
    throw "Checksum mismatch! Expected: $checksum, Got: $actualChecksum"
}}
Write-Host "Checksum verified: $actualChecksum"

# Install via pip
Write-Host "Installing via pip..."
python -m pip install --force-reinstall --no-deps $whlFile

if ($LASTEXITCODE -ne 0) {{
    throw "pip install failed"
}}

# Cleanup
Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue

Write-Host "✅ $packageName installed successfully!"
Write-Host "Run 'kekkai --help' to get started."
"""

    return script


def generate_chocolatey_uninstall_script() -> str:
    """
    Generate chocolateyuninstall.ps1 script for Chocolatey package.

    Returns:
        Chocolatey uninstall script as string
    """
    script = """# Kekkai Chocolatey Uninstallation Script
$ErrorActionPreference = 'Continue'

$packageName = 'kekkai'

Write-Host "Uninstalling $packageName..."

try {
    python -m pip uninstall -y kekkai

    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ $packageName uninstalled successfully"
    } else {
        Write-Warning "$packageName may not have been installed or was already removed"
    }
} catch {
    Write-Warning "Uninstall encountered an issue: $_"
}
"""

    return script
