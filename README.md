# AutoReportNWU
AutoReportNWU offers NWUer an automatic reporter.

## Requirements
```bash
pip install -r requirements.txt
```

## Usage

### Local Mode

#### Initialization
```bash
python autoReport.py local --username 1234 --password abc123
```
#### Run
```bash
python autoReport.py local
```

### Online Mode
```bash
python autoReport.py online --username *** --password ***
```

## Description
The local mode will create a `cookies.json` to store your cookies.

If you want to change your report data, please modify `reportdata.json`.
