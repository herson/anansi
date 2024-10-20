# Reporter Module

The **Reporter** module generates structured output for the scanning, enumeration, and exploitation results.

## Key Functions

- **generate_report(scan_result: dict, services: dict) -> None**: Generates a text-based report summarizing the findings.

### Example Usage

```python
from modules.reporter import generate_report

generate_report(scan_result, services)
```

## Output Format

- Open ports and services identified.
- Exploitation results (if any).