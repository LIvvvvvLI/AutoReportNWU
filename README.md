# AutoReportNWU
AutoReportNWU offers NWUer an automatic reporter.

**Tips：only for learning**

## Requirements
```cmd
pip install -r requirements.txt
```

## Usage

### Local Mode

#### Initialization
```cmd
python autoReport.py local --username $YourUsername$ --password $YourPassword$
```
#### Run
```cmd
python autoReport.py local
```

### Online Mode
```cmd
python autoReport.py online --username $YourUsername$ --password $YourPassword$
```

## Description
The local mode will create a `cookies.json` to store your cookies.

If you want to change your report data, please modify `reportdata.json`.
