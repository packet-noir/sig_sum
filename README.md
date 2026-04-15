# sig-sum

Accepts a path to a directory containing sigma rules and summarizes them.

## Dependencies

- Python >=3.10
- 'requests' third-party module
- 'pyyaml' third-party module

## Usage

```
python3 sig-sum.py /absolute/path/to/directory
```

## Sample Output

```
title: File And SubFolder Enumeration Via Dir Command
severity: low
source: process_creation from windows
Mitre Tags: ['discovery', 't1217'] Mitre Technique Name(s): ['Browser Information Discovery']
Detection: {'selection_cmd': [{'Image|endswith': '\\cmd.exe'}, {'OriginalFileName': 'Cmd.Exe'}], 'selection_cli': {'CommandLine|contains|windash': 'dir*-s'}, 'condition': 'all of selection_*'}

title: Potential Product Reconnaissance Via Wmic.EXE
severity: medium
source: process_creation from windows
Mitre Tags: ['execution', 't1047'] Mitre Technique Name(s): ['Windows Management Instrumentation']
Detection: {'selection_img': [{'Image|endswith': '\\wmic.exe'}, {'OriginalFileName': 'wmic.exe'}], 'selection_cli': {'CommandLine|contains': 'Product'}, 'filter_main_call_operations': {'CommandLine|contains': [' uninstall', ' install']}, 'condition': 'all of selection_* and not 1 of filter_main_*'}

title: PUA - NirCmd Execution As LOCAL SYSTEM
severity: high
source: process_creation from windows
Mitre Tags: ['execution', 't1569.002', 's0029'] Mitre Technique Name(s): ['Service Execution']
Detection: {'selection': {'CommandLine|contains': ' runassystem '}, 'condition': 'selection'}
``` 

