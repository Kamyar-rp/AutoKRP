# Third-party notices

AutoKRP itself is licensed under the [MIT License](LICENSE). It bundles or depends on the following third-party components. The licenses below are listed for convenience; the authoritative text is in each project.

## Bundled in this repository
| Component | Location | License |
|---|---|---|
| Vazirmatn font | `ui/fonts/` | SIL Open Font License 1.1 (`ui/fonts/OFL.txt`) |
| xterm.js and addon-fit | `ui/vendor/` | MIT (`ui/vendor/xterm-LICENSE.txt`) |
| IANA port registry data via npm `port-numbers` | `ui/ports_iana.js` | BSD-2-Clause (notice kept in the file) |
| IEEE MAC vendor registry (MA-L and IAB), from the `netaddr` package data | `autokrp/oui.dat` | Public IEEE Registration Authority data; netaddr is BSD-3-Clause |
| MIB files | `assets/mibs/src/` | Copyright of their respective vendors/authors; redistributed for SNMP interoperability |

## Python dependencies (installed by pip and packed into the exe)
| Package | License |
|---|---|
| pywebview | BSD-3-Clause |
| requests, urllib3 | Apache-2.0 / MIT |
| cryptography | Apache-2.0 or BSD-3-Clause |
| netmiko | MIT |
| paramiko | LGPL-2.1 |
| dnspython | ISC |
| PyMySQL | MIT |
| pysnmp, pysmi | BSD-2-Clause |
| ldap3 | LGPL-3.0 |
| sqlcipher3 (SQLCipher) | zlib / BSD-style |
| truststore | MIT |
| pyserial | BSD-3-Clause |
| pystray | LGPL-3.0 |
| Pillow | MIT-CMU (HPND) |
| Jinja2, lark | BSD-3-Clause / MIT |
| PyInstaller (build only) | GPL-2.0 with bootloader exception — does not affect the license of the built exe |

The LGPL-licensed packages are used unmodified. Their source code is available from PyPI, and you can replace them by running AutoKRP from source with your own versions.
