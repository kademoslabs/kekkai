# Installing Kekkai on Windows

Complete guide for installing and using Kekkai on Windows systems via Scoop, Chocolatey, pipx, or pip.

---

## Prerequisites

### Required
- **Windows 10/11** (64-bit)
- **Python 3.12+** installed and in PATH
- **Internet connection** for downloading packages

### Optional
- **Docker Desktop for Windows** (for Dojo features)
- **PowerShell 5.1+** or **PowerShell Core 7+**

---

## Installation Methods

### Option 1: Scoop (Recommended for Developers)

**Scoop** is a command-line installer for Windows that doesn't require admin privileges.

#### Install Scoop (if not already installed)

```powershell
# In PowerShell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
irm get.scoop.sh | iex
```

#### Add Kekkai Bucket and Install

```powershell
# Add Kademos Labs bucket
scoop bucket add kademoslabs https://github.com/kademoslabs/scoop-bucket

# Install Kekkai
scoop install kekkai

# Verify installation
kekkai --version
```

#### Update Kekkai

```powershell
# Update Scoop and Kekkai
scoop update
scoop update kekkai
```

#### Uninstall

```powershell
scoop uninstall kekkai
```

---

### Option 2: Chocolatey (Enterprise/System-wide)

**Chocolatey** is ideal for enterprise deployments and system-wide installations (requires admin privileges).

#### Install Chocolatey (if not already installed)

```powershell
# In PowerShell (Administrator)
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
```

#### Install Kekkai

```powershell
# In PowerShell (Administrator)
choco install kekkai -y

# Verify installation
kekkai --version
```

#### Update Kekkai

```powershell
choco upgrade kekkai -y
```

#### Uninstall

```powershell
choco uninstall kekkai -y
```

---

### Option 3: pipx (Isolated Environment)

**pipx** installs Python CLI tools in isolated environments without polluting your global Python installation.

#### Install pipx (if not already installed)

```powershell
python -m pip install --user pipx
python -m pipx ensurepath
```

Restart your terminal after installing pipx.

#### Install Kekkai

```powershell
pipx install kekkai

# Verify installation
kekkai --version
```

#### Update Kekkai

```powershell
pipx upgrade kekkai
```

#### Uninstall

```powershell
pipx uninstall kekkai
```

---

### Option 4: pip (Traditional)

**pip** installs Kekkai globally or in your active virtual environment.

```powershell
# Install globally (may require admin)
python -m pip install kekkai

# Or in a virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install kekkai

# Verify installation
kekkai --version
```

---

## Verification

After installation, verify Kekkai is working:

```powershell
# Check version
kekkai --version

# View help
kekkai --help

# Test scan (in a git repository)
cd C:\path\to\your\project
kekkai scan
```

---

## Troubleshooting

### Python Not Found

**Error:**
```
'python' is not recognized as an internal or external command
```

**Solution:**
1. Install Python 3.12+ from [python.org](https://www.python.org/downloads/)
2. During installation, check "Add Python to PATH"
3. Or install via Scoop: `scoop install python`
4. Or install via Chocolatey: `choco install python`

**Verify:**
```powershell
python --version
```

---

### pip Not Available

**Error:**
```
No module named pip
```

**Solution:**
```powershell
# Ensure pip is installed
python -m ensurepip --default-pip

# Upgrade pip
python -m pip install --upgrade pip
```

---

### Permission Denied (Scoop)

**Error:**
```
Access denied
```

**Solution:**
- Scoop doesn't require admin privileges
- Install in your user directory (default behavior)
- Check Windows Defender isn't blocking installation

---

### Permission Denied (Chocolatey)

**Error:**
```
Access to the path is denied
```

**Solution:**
- Run PowerShell as Administrator
- Disable antivirus temporarily during installation
- Check folder permissions for `C:\ProgramData\chocolatey`

---

### PATH Not Updated

**Error:**
```
'kekkai' is not recognized
```

**Solution:**

**For Scoop:**
```powershell
# Scoop should auto-update PATH
# Restart terminal and try again
```

**For Chocolatey:**
```powershell
# Restart terminal or refresh environment
refreshenv
```

**For pipx:**
```powershell
# Ensure pipx path is in PATH
python -m pipx ensurepath
# Restart terminal
```

**For pip:**
```powershell
# Python Scripts folder should be in PATH
# Add manually if needed:
# C:\Users\<YourUsername>\AppData\Local\Programs\Python\Python312\Scripts
```

---

### SHA256 Checksum Mismatch

**Error (Scoop/Chocolatey):**
```
Checksum verification failed
```

**Solution:**
1. Wait a few minutes and retry (CDN propagation)
2. Clear package cache:
   ```powershell
   # Scoop
   scoop cache rm kekkai

   # Chocolatey
   choco cache remove
   ```
3. If issue persists, report on [GitHub Issues](https://github.com/kademoslabs/kekkai/issues)

---

### Docker Desktop Not Found

**Error:**
```
Docker daemon is not running
```

**Solution:**
1. Install [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop/)
2. Start Docker Desktop
3. Enable WSL 2 backend (recommended)
4. Verify: `docker --version`

**For Dojo features:**
```powershell
# Start DefectDojo
kekkai dojo up --wait

# Check status
docker ps
```

---

### PowerShell Execution Policy

**Error:**
```
... cannot be loaded because running scripts is disabled on this system
```

**Solution:**
```powershell
# For current user only (no admin required)
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

# Or for current process only
Set-ExecutionPolicy Bypass -Scope Process
```

---

## Comparison of Installation Methods

| Feature | Scoop | Chocolatey | pipx | pip |
|---------|-------|------------|------|-----|
| **Admin Required** | ❌ No | ✅ Yes | ❌ No | Maybe |
| **Auto-update** | ✅ Yes | ✅ Yes | ✅ Yes | ❌ No |
| **Isolated Environment** | ✅ Yes | ✅ Yes | ✅ Yes | ❌ No |
| **Rollback Support** | ✅ Yes | ✅ Yes | ❌ No | ❌ No |
| **Enterprise Ready** | ⚠️ Partial | ✅ Yes | ❌ No | ⚠️ Partial |
| **Best For** | Developers | IT/Ops | Python users | Development |

---

## Docker Desktop Integration

Kekkai's Dojo features require Docker Desktop on Windows.

### Install Docker Desktop

1. Download from [docker.com](https://www.docker.com/products/docker-desktop/)
2. Install with WSL 2 backend (recommended)
3. Start Docker Desktop
4. Verify installation:
   ```powershell
   docker --version
   docker ps
   ```

### Configure Docker for Kekkai

```powershell
# No special configuration needed
# Kekkai will automatically detect Docker

# Test with Dojo
kekkai dojo up --wait --open
```

---

## Next Steps

### Run Your First Scan

```powershell
# Navigate to your project
cd C:\path\to\your\project

# Run security scan
kekkai scan

# View results
Get-Content kekkai-report.json
```

### Launch DefectDojo

```powershell
# Start DefectDojo locally
kekkai dojo up --wait --open

# Access UI
# http://localhost:8080
# Username: admin
# Password: admin (change immediately)
```

### Generate Threat Model

```powershell
# Generate threat model (requires local LLM)
kekkai threatflow --repo . --model-mode local
```

---

## Environment Variables

Kekkai respects the following Windows environment variables:

- `KEKKAI_CONFIG` - Path to custom config file
- `DOCKER_HOST` - Docker daemon connection string
- `HTTP_PROXY`, `HTTPS_PROXY` - Proxy configuration

**Set environment variables:**

```powershell
# Temporary (current session)
$env:KEKKAI_CONFIG = "C:\path\to\config.yaml"

# Permanent (user level)
[System.Environment]::SetEnvironmentVariable('KEKKAI_CONFIG', 'C:\path\to\config.yaml', 'User')

# Permanent (system level, requires admin)
[System.Environment]::SetEnvironmentVariable('KEKKAI_CONFIG', 'C:\path\to\config.yaml', 'Machine')
```

---

## PowerShell vs CMD

Kekkai works in both PowerShell and Command Prompt (CMD).

### PowerShell (Recommended)

```powershell
kekkai --version
kekkai scan
```

### Command Prompt (CMD)

```cmd
kekkai --version
kekkai scan
```

**Note:** Installation scripts use PowerShell, but the `kekkai` command works in both.

---

## Corporate/Restricted Environments

### Proxy Configuration

```powershell
# Configure pip to use proxy
$env:HTTP_PROXY = "http://proxy.company.com:8080"
$env:HTTPS_PROXY = "http://proxy.company.com:8080"

# Install via pip
python -m pip install --proxy http://proxy.company.com:8080 kekkai
```

### Offline Installation

1. Download wheel file from [GitHub Releases](https://github.com/kademoslabs/kekkai/releases)
2. Copy to target machine
3. Install:
   ```powershell
   python -m pip install C:\path\to\kekkai-0.0.1-py3-none-any.whl
   ```

### Certificate Verification

```powershell
# If corporate SSL inspection causes issues
python -m pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org kekkai
```

---

## Updating

### Scoop

```powershell
scoop update kekkai
```

### Chocolatey

```powershell
choco upgrade kekkai -y
```

### pipx

```powershell
pipx upgrade kekkai
```

### pip

```powershell
python -m pip install --upgrade kekkai
```

---

## Uninstalling

### Scoop

```powershell
scoop uninstall kekkai
```

### Chocolatey

```powershell
choco uninstall kekkai -y
```

### pipx

```powershell
pipx uninstall kekkai
```

### pip

```powershell
python -m pip uninstall kekkai
```

---

## Support

- **Documentation**: [https://github.com/kademoslabs/kekkai](https://github.com/kademoslabs/kekkai)
- **Issues**: [GitHub Issues](https://github.com/kademoslabs/kekkai/issues)
- **Security**: security@kademos.org

---

## Related Documentation

- [Automated Distribution Updates](../ci/automated-distributions.md)
- [Scoop Integration](../ci/scoop-integration.md)
- [DefectDojo Quickstart](../dojo/dojo-quickstart.md)
- [CI/CD Integration](../ci/automated-distributions.md)
