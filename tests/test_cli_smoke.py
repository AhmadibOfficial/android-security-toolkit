from typer.testing import CliRunner
from ahmad_sec.cli import app


def test_top_level_help_is_available():
    result = CliRunner().invoke(app, ['--help'])
    assert result.exit_code == 0, result.output
    assert 'apk' in result.output
