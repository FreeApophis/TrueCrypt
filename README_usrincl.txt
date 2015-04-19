These files belong in /usr/include... They have been changed to be where truecrypt expects them vs where Ubuntu puts them.

Quick and dirty solution,... it aint pretty but it workz.

You probably want to do tar -cvrf ~/usr_include_orig.tar /usr/include/* to save your files...


Then untar the archive included here over top of /usr/include so you have the correctly hacked Qt4 and Wx include files that match the hacks I did to the TrueCrypt include files in the TC code.

So again, usr_include_.tgz goes to overwrite partz of /usr/include after you back it up.

-Alex@bitshark.net
