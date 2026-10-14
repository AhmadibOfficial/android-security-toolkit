from typer.testing import CliRunner
from ahmad_sec.cli import app


def test_registered_commands_available():
    runner = CliRunner()
    for args in (['--help'], ['apk', '--help'], ['version'], ['info']):
        result = runner.invoke(app, args)
        assert result.exit_code == 0, (args, result.output, result.exception)
