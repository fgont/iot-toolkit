*******************************************************************************
*                   SI6 Networks IoT Toolkit v1.0 (       )                   *
*******************************************************************************

Description of each of the files and directories:
-------------------------------------------------

 data:        Contains the configuration files and miscellaneous databases.
 manuals:     Contains the manual pages for the security assessment tools.
 tools:       Contains the source code for the security assessment tools.
 CHANGES.TXT: Contains the changelog of the toolkit
 CREDITS.TXT: Contains the credits of this project.
 LICENSE.TXT: Contains the license for this software (GPLv3)
 README.TXT:  This file.


Building the tools
------------------

You can build the tools by running the following command:
 
   make all

You can install the tools, configuration file, database, and existing manual
pages by running the following command:

   make install

Note: The libpcap and the libssl libraries must be previously installed on 
the system. The corresponding packages are typically named "libpcap-dev" and
libssl-dev, respctively.

All the tools have been tested to build (both with gcc and clang) and run on 
Debian GNU/Linux 7.0 and FreeBSD 9.0.


Bug reports
-----------

Please send any bug reports to Fernando Gont <fgont@si6networks.com>

