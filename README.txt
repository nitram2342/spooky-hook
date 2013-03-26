SpookyHook
-------------

Spooky-hook.py is an API call hooking tool based on WinAppDbg for the Windows
platform. It is derived from a script written by Michael Ligh published in the
Malware Analyst's Cookbook [1]


[1] https://code.google.com/p/malwarecookbook/source/browse/trunk/11/12/pymon.py

Catching data
-------------

I had some trouble to get the data from an API call and it required several
tries to get it working. Thus, the script is a mess. However, the hooked
send() API call serves as an example, but please note that this still requires
a cleanup.

Status
-------------

The script is not finished, yet, but might serve as a template for API hooking tests.

License
-------------

Since the original script is published aunder the GNU General Publi
License >= Version 3, this script is it, too.

