# Packet sniffing

This repo contains a few scripts for analysis.

The currently supported and up-to-date script is "readpcap.py" which will take a pcap file and create a report of the unique destinations accessed.
The other scripts are WIP.
# Installation

We recommend using poetry to manage the python environment, although it is possible to just use pip or conda.
If you want to use these alternatives, create the respective requirements/environment file with the same package versions in the `pyproject.toml` file.

Install python v3.8.17 or install and use `pyenv` to manage the python environment.

Install poetry, set the python version with `poetry env use 3.8.17` and then run `poetry install` in this folder.
You can then either run for example:

`poetry run python readpcap.py <pcap file location> <desired output csv name>`

or

```shell
poetry shell
python run python readpcap.py <pcap file location> <desired output csv name>
```

# Usage

## readpcap.py

This script will take in an existing pcap as the first argument and the desired csv file name as the second (no need to create the csv beforehand).
Note that the report csv will be named the same as the desired csv with a prepended `report_` to the filename.
There will be an intermediary csv file with the exact name you specified, this will contain a row for each packet.
The script will access a location service lookup based on the ip address, this database may not have the location for all IPs.
The script will also try to make a hostname lookup for the ip address, this may also not be successful and will leave the name empty.

Note on large pcap files (thousands of packets) can take a few minutes to run.
