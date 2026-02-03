"""Unit tests for editor support module."""

from __future__ import annotations

from pathlib import Path

from kekkai.triage.editor_support import (
    EditorConfig,
    build_editor_command,
    detect_editor_config,
    validate_editor_name,
)


class TestEditorDetection:
    """Tests for editor detection and configuration."""

    def test_detect_vim_family(self) -> None:
        """Test detection of Vim family editors."""
        for editor in ["vim", "nvim", "neovim", "vi"]:
            config = detect_editor_config(editor)
            assert config.syntax_type == "vim"
            assert config.name in ["vim", "nvim", "neovim", "vi"]

    def test_detect_emacs_family(self) -> None:
        """Test detection of Emacs family editors."""
        for editor in ["emacs", "nano"]:
            config = detect_editor_config(editor)
            assert config.syntax_type == "vim"  # Use vim-style syntax

    def test_detect_vscode(self) -> None:
        """Test detection of VS Code variants."""
        for editor in ["code", "code-insiders", "codium"]:
            config = detect_editor_config(editor)
            assert config.syntax_type == "vscode"

    def test_detect_vscode_with_path(self) -> None:
        """Test detection works with full paths."""
        config = detect_editor_config("/usr/local/bin/code")
        assert config.syntax_type == "vscode"
        assert config.name == "code"

    def test_detect_sublime(self) -> None:
        """Test detection of Sublime Text variants."""
        for editor in ["subl", "sublime", "sublime_text"]:
            config = detect_editor_config(editor)
            assert config.syntax_type == "sublime"

    def test_detect_atom(self) -> None:
        """Test detection of Atom editor."""
        config = detect_editor_config("atom")
        assert config.syntax_type == "sublime"  # Uses same syntax as Sublime

    def test_detect_notepadpp(self) -> None:
        """Test detection of Notepad++."""
        for editor in ["notepad++", "notepad++.exe"]:
            config = detect_editor_config(editor)
            assert config.syntax_type == "notepadpp"

    def test_detect_jetbrains(self) -> None:
        """Test detection of JetBrains IDEs."""
        for editor in ["idea", "pycharm", "webstorm", "phpstorm", "goland", "rider"]:
            config = detect_editor_config(editor)
            assert config.syntax_type == "jetbrains"

    def test_unknown_editor_fallback(self) -> None:
        """Test that unknown editors fall back to vim syntax."""
        config = detect_editor_config("unknown-editor")
        assert config.syntax_type == "vim"
        assert config.name == "unknown"

    def test_case_insensitive_detection(self) -> None:
        """Test that editor detection is case-insensitive."""
        config = detect_editor_config("CODE")
        assert config.syntax_type == "vscode"

        config = detect_editor_config("VIM")
        assert config.syntax_type == "vim"


class TestEditorValidation:
    """Tests for editor name validation (ASVS V5.1.3)."""

    def test_validate_safe_names(self) -> None:
        """Test that safe editor names are accepted."""
        safe_names = [
            "vim",
            "code",
            "nvim",
            "/usr/bin/vim",
            "/usr/local/bin/code",
            "editor-name",
            "editor.name",
            "editor_name",
        ]
        for name in safe_names:
            assert validate_editor_name(name), f"Should accept: {name}"

    def test_validate_reject_shell_metacharacters(self) -> None:
        """Test that editor names with shell metacharacters are rejected."""
        unsafe_names = [
            "vim; curl evil.com",
            "vim && rm -rf /",
            "vim | cat /etc/passwd",
            "vim $(whoami)",
            "vim `whoami`",
            "vim & curl",
            "vim > /tmp/evil",
            "vim < /etc/passwd",
        ]
        for name in unsafe_names:
            assert not validate_editor_name(name), f"Should reject: {name}"

    def test_validate_reject_empty(self) -> None:
        """Test that empty editor name is rejected."""
        assert not validate_editor_name("")


class TestCommandBuilding:
    """Tests for editor command building."""

    def test_build_vim_command(self) -> None:
        """Test building command for Vim-style editors."""
        config = EditorConfig("vim", "vim")
        cmd = build_editor_command("/usr/bin/vim", Path("/repo/file.py"), 42, config)

        assert cmd == ["/usr/bin/vim", "+42", "/repo/file.py"]

    def test_build_vscode_command(self) -> None:
        """Test building command for VS Code."""
        config = EditorConfig("code", "vscode")
        cmd = build_editor_command("/usr/bin/code", Path("/repo/file.py"), 42, config)

        assert cmd == ["/usr/bin/code", "-g", "/repo/file.py:42"]

    def test_build_sublime_command(self) -> None:
        """Test building command for Sublime Text."""
        config = EditorConfig("subl", "sublime")
        cmd = build_editor_command("/usr/bin/subl", Path("/repo/file.py"), 42, config)

        assert cmd == ["/usr/bin/subl", "/repo/file.py:42"]

    def test_build_notepadpp_command(self) -> None:
        """Test building command for Notepad++."""
        config = EditorConfig("notepad++", "notepadpp")
        cmd = build_editor_command(
            "C:\\Program Files\\Notepad++\\notepad++.exe", Path("C:\\repo\\file.py"), 42, config
        )

        assert cmd == ["C:\\Program Files\\Notepad++\\notepad++.exe", "-n42", "C:\\repo\\file.py"]

    def test_build_jetbrains_command(self) -> None:
        """Test building command for JetBrains IDEs."""
        config = EditorConfig("pycharm", "jetbrains")
        cmd = build_editor_command("/usr/bin/pycharm", Path("/repo/file.py"), 42, config)

        assert cmd == ["/usr/bin/pycharm", "--line", "42", "/repo/file.py"]

    def test_command_uses_list_args(self) -> None:
        """Test that all commands use list args (not shell strings) per ASVS V14.2.1."""
        editors = [
            EditorConfig("vim", "vim"),
            EditorConfig("code", "vscode"),
            EditorConfig("subl", "sublime"),
            EditorConfig("notepad++", "notepadpp"),
            EditorConfig("idea", "jetbrains"),
        ]

        for editor in editors:
            cmd = build_editor_command("/usr/bin/editor", Path("/file.py"), 10, editor)
            assert isinstance(cmd, list), f"Command should be list for {editor.name}"
            assert all(isinstance(arg, str) for arg in cmd), "All args should be strings"
