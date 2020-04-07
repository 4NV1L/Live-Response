# Live-Response
> Linux Incident Response Bash script for live-response purposes.

[![NPM Version][bash-image]][npm-url]
[![NPM Version][Forensics-image]][npm-url]

## Description

Through most intrusion events, or incidents you will want to initiate a live-response investigation. The goal of the script is mainly data collection and doing so while keeping the integrity of the evidence you collect. Live data collections should be conducted with minimal changes on the system, or if there are changes, they need to be logged. The level of changes to the target system will vary dependent on the organization needs.  With this bash script you will find evidence collecting commands and an audit trail for each command run on the system. You will have created folders in /tmp where you can access this data or compress it, to ship it off to a different machine. 

This is a continuous project, being tested, and changed as I have time. Please feel free to make recommendations as I will take them seriously. 

### Tested Operating systems

```sh
Ubuntu - Tested
Centos - Pending 
RedHat - Pending 
MacOSX - Pending 
Debian - Pending 
```
### Usage 

This does not currently require installing additional packages, commands will be executed, if one does not exist it is skipped and logged in the audit file "log".

This does require root priviledges, and to be run within the /tmp directory. Make sure the script is there, or simple move the script to /tmp. Line 53, is the default path configuration, you can change this to a different path if needed, but I highly recommend running within /tmp for consistency in investigations.

```sh
chmod +x ./LinResponse.sh
./LinResponse.sh
```


### References 

* https://tools.ietf.org/html/rfc3227 Guidelines for Evidence Collection and Archiving
<!-- Markdown link & img dfn's -->
[bash-image]: https://img.shields.io/badge/Code-BASH-brightgreen&?style=for-the-badge&logo=appveyor
[Forensics-image]: https://img.shields.io/badge/Type-Forensics-brightgreen&?style=for-the-badge&logo=appveyor
[npm-url]: https://img.shields.io/badge/Type-Forensics-brightgreen&?style=for-the-badge&logo=appveyor
