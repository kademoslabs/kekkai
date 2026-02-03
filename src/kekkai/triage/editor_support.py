"""Editor-specific line jump syntax support.

Provides detection and command building for popular editors with
security validation per ASVS V5.1.3.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "EditorConfig",
    "detect_editor_config",
    "validate_editor_name",
    "EDITOR_REGISTRY",
]

# ASVS V5.1.3: Only allow safe characters in editor names
EDITOR_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9/_.-]+$")


@dataclass
class EditorConfig:
    """Editor-specific command line configuration.

    Attributes:
        name: Canonical editor name (e.g., "vim", "code", "subl").
        syntax_type: Command syntax category for building commands.
    """

    name: str
    syntax_type: str  # "vim", "vscode", "sublime", "notepadpp", "jetbrains"


# Editor registry mapping base names to configurations
EDITOR_REGISTRY: dict[str, EditorConfig] = {
    # Vim family (syntax: editor +LINE file)
    "vim": EditorConfig("vim", "vim"),
    "nvim": EditorConfig("nvim", "vim"),
    "neovim": EditorConfig("neovim", "vim"),
    "vi": EditorConfig("vi", "vim"),
    # Emacs family (syntax: editor +LINE file)
    "emacs": EditorConfig("emacs", "vim"),
    "nano": EditorConfig("nano", "vim"),
    # VS Code (syntax: code -g file:line)
    "code": EditorConfig("code", "vscode"),
    "code-insiders": EditorConfig("code-insiders", "vscode"),
    "codium": EditorConfig("codium", "vscode"),  # VSCodium (FOSS fork)
    # Sublime Text (syntax: subl file:line)
    "subl": EditorConfig("subl", "sublime"),
    "sublime": EditorConfig("sublime", "sublime"),
    "sublime_text": EditorConfig("sublime_text", "sublime"),
    # Atom (syntax: atom file:line) - legacy but still used
    "atom": EditorConfig("atom", "sublime"),
    # Notepad++ (syntax: notepad++ -nLINE file)
    "notepad++": EditorConfig("notepad++", "notepadpp"),
    "notepad++.exe": EditorConfig("notepad++.exe", "notepadpp"),
    # JetBrains IDEs (syntax: editor --line LINE file)
    "idea": EditorConfig("idea", "jetbrains"),
    "pycharm": EditorConfig("pycharm", "jetbrains"),
    "webstorm": EditorConfig("webstorm", "jetbrains"),
    "phpstorm": EditorConfig("phpstorm", "jetbrains"),
    "goland": EditorConfig("goland", "jetbrains"),
    "rider": EditorConfig("rider", "jetbrains"),
    "clion": EditorConfig("clion", "jetbrains"),
    "rubymine": EditorConfig("rubymine", "jetbrains"),
}


def detect_editor_config(editor_name: str) -> EditorConfig:
    """Detect editor configuration from name.

    Args:
        editor_name: Editor executable name (e.g., "vim", "/usr/bin/code").

    Returns:
        EditorConfig for the detected editor, or vim-style default if unknown.

    Examples:
        >>> detect_editor_config("vim").syntax_type
        'vim'
        >>> detect_editor_config("/usr/local/bin/code").syntax_type
        'vscode'
        >>> detect_editor_config("unknown-editor").syntax_type
        'vim'
    """
    # Extract base name from path
    base_name = Path(editor_name).stem.lower()

    # Handle .exe extension on Windows
    if base_name.endswith(".exe"):
        base_name = base_name[:-4]

    # Lookup in registry
    config = EDITOR_REGISTRY.get(base_name)
    if config:
        return config

    # Default to vim-style syntax for unknown editors
    return EditorConfig("unknown", "vim")


def validate_editor_name(editor: str) -> bool:
    """Validate that editor name is safe to use.

    Security: ASVS V5.1.3 - Validate data at trust boundaries.
    Rejects editor names containing shell metacharacters to prevent
    command injection attacks.

    Args:
        editor: Editor name from environment variable.

    Returns:
        True if editor name is safe, False if it contains unsafe characters.

    Examples:
        >>> validate_editor_name("vim")
        True
        >>> validate_editor_name("/usr/bin/code")
        True
        >>> validate_editor_name("vim; curl evil.com")
        False
        >>> validate_editor_name("vim && rm -rf /")
        False
    """
    if not editor:
        return False

    # Check against safe pattern (alphanumeric + /.-_ only)
    return bool(EDITOR_NAME_PATTERN.match(editor))


def build_editor_command(
    editor_path: str, file_path: Path, line: int, editor_config: EditorConfig
) -> list[str]:
    """Build editor command arguments based on editor type.

    Args:
        editor_path: Full path to editor executable.
        file_path: Path to file to open.
        line: Line number to jump to.
        editor_config: Editor configuration with syntax type.

    Returns:
        List of command arguments for subprocess.run().

    Security:
        ASVS V14.2.1 - Uses list args (not shell string) to prevent injection.
    """
    if editor_config.syntax_type == "vscode":
        # VS Code: code -g file:line
        return [editor_path, "-g", f"{file_path}:{line}"]
    elif editor_config.syntax_type == "sublime":
        # Sublime Text / Atom: editor file:line
        return [editor_path, f"{file_path}:{line}"]
    elif editor_config.syntax_type == "notepadpp":
        # Notepad++: notepad++ -nLINE file
        return [editor_path, f"-n{line}", str(file_path)]
    elif editor_config.syntax_type == "jetbrains":
        # JetBrains IDEs: editor --line LINE file
        return [editor_path, "--line", str(line), str(file_path)]
    else:
        # Default (Vim/Emacs/Nano): editor +LINE file
        return [editor_path, f"+{line}", str(file_path)]
