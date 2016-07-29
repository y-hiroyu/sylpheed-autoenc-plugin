Automatic Attachment Encryption Plug-in for Sylpheed
====================================================

This is a Sylpheed plug-in to encrypt attached files automatically
when sending mails.

Requirement
-----------

This plug-in requires Sylpheed 3.5.1 or later.
It also requires 7-Zip.

- http://sylpheed.sraoss.jp/
- http://www.7-zip.org/

Install
-------

    ./configure
    make
    make install


(MinGW)

    ./makewin32.sh

Usage
-----

1. Compose new message.
2. Attach any files.
3. Push "Send with encryption" button.
4. A password notify mail is newly created. Send it if it's okay.

License
-------

Sylpheed-autoenc-plugin is distributed under LGPLv2.1+ license.
Please see COPYING for details.
