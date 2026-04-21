# Environment Setup

Use a local virtual environment before running collection/training scripts.

## Create and install

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Verify key packages

```bash
pip show mitreattack-python stix2
```

## Run atomic collection from ATT&CK STIX

```bash
bash scripts/pipeline/run_atomic_collection.sh enterprise-attack
```
