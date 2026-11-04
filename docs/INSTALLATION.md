# Installation

RIG Sentinel v0.1.0 is installed from source. It has **no runtime dependencies**;
`pytest` is only needed for development.

## Requirements

| Requirement | Notes |
|---|---|
| Python | 3.11 or newer (declared in `pyproject.toml`). CI and maintainer testing use **3.13**. |
| pip | Recent pip with PEP 517 support (`python -m pip install --upgrade pip`). |
| Git | To clone the repository. |
| Network | Only during installation, to fetch the `setuptools` build backend from PyPI. Scanning is fully offline. |

## Windows (PowerShell)

```powershell
git clone https://github.com/Igualguana/RIG-Sentinel.git
cd RIG-Sentinel
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install .
rig-sentinel --help
```

If script execution is blocked, run PowerShell with an execution policy that allows
local scripts for the current process, or use `.\.venv\Scripts\activate.bat` from
`cmd.exe`.

## Linux / macOS

```bash
git clone https://github.com/Igualguana/RIG-Sentinel.git
cd RIG-Sentinel
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
rig-sentinel --help
```

## Development install

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

The `dev` extra installs `pytest>=8.0,<10.0`.

## Install directly from GitHub

```bash
python -m pip install "git+https://github.com/Igualguana/RIG-Sentinel.git@main"
```

Replace `@main` with `@v0.1.0` once that tag has been published. This requires the
repository to be publicly accessible (or Git credentials for a private repository).

## Running without the console script

The CLI module can also be invoked directly:

```bash
python -m rig_sentinel.cli scan .
```

## Verify the installation

```bash
rig-sentinel --help
rig-sentinel scan . --json > rig-sentinel.json
rig-sentinel scan . --html rig-sentinel.html
rig-sentinel scan . --sarif rig-sentinel.sarif
python -c "import json; d=json.load(open('rig-sentinel.sarif', encoding='utf-8')); assert d['version'] == '2.1.0'; print('SARIF OK')"
```

## Uninstall

```bash
python -m pip uninstall rig-sentinel
```

## Platform status

See the [platform table in the README](../README.md#platform-status).
