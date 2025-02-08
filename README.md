# ECSplorer for Ark

Adapted from [ECSplorer](https://github.com/tumi8/ECSplorer)

Initial development at the GMI-AIMS-5 Hackaton

Contributors:
- [Patrick Sattler](https://github.com/sattler)
- [Mattijs Jonker](https://github.com/mattijsjonker)

## Manual

```
usage: ark-ecs-scanner.py [-h] --config CONFIG --domains_list DOMAINS_LIST [--prefixes_list PREFIXES_LIST] --output_basedir OUTPUT_BASEDIR --mux MUX [--ignore-response-scope]

Response Aware EDNS Client Subnet Scanner.

options:
  -h, --help            show this help message and exit
  --config CONFIG       Path to the YAML config file.
  --domains_list DOMAINS_LIST
                        File that contains list of input domain names.
  --prefixes_list PREFIXES_LIST
                        File that contains list of prefixes. If set the config file entries are ignored.
  --output_basedir OUTPUT_BASEDIR
                        Base directory for output data
  --mux MUX             The multiplexing socket for Scamper Control.
  --ignore-response-scope
                        if set code will ignore the scope prefix lengt when scheduling measurements
```