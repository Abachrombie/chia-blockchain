param(
    [Parameter(Mandatory, HelpMessage="Python version")]
    [string]
    $pythonVersion
)

$ErrorActionPreference = "Stop"

py -$pythonVersion -m venv .penv
.penv/Scripts/python -m pip install --upgrade pip setuptools wheel
# TODO: maybe make our own zipapp/shiv/pex of poetry and download that?
.penv/Scripts/python -m pip install poetry
.penv/Scripts/poetry self add poetry-dynamic-versioning-plugin@latest

# New-Item -ItemType SymbolicLink -Path "poetry.exe" -Target ".penv/Scripts/poetry.exe"
