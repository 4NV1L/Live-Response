# Live-Response
> Throughout my experience in Incident Response, Live Response forensics always is the proper first step in confirming a compromise.

[![NPM Version][bash-image]][npm-url]
[![NPM Version][Forensics-image]][npm-url]

Live Response shell script will sift through various log sources and commands to determine what is happening on the box. Currently it checks various network connections, processes, open files, system information, user accounts, history files and other interesting indicators on system. Below you will find the exhaustive list of commands that the shell script runs. There is also a logging function that ensures each command that is run, is properly logged within a logging file that populates on each command run, and time stamped. 


<!-- Markdown link & img dfn's -->
[bash-image]: https://img.shields.io/badge/Code-BASH-brightgreen&?style=for-the-badge&logo=appveyor
[Forensics-image]: https://img.shields.io/badge/Type-Forensics-brightgreen&?style=for-the-badge&logo=appveyor
[npm-url]: https://img.shields.io/badge/Type-Forensics-brightgreen&?style=for-the-badge&logo=appveyor
