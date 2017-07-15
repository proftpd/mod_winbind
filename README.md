mod_winbind v1.0
================

mod_winbind is a ProFTPD module that uses Samba's winbind daemon to
authenticate Windows domain users.


Orphaned
========

I'm no longer actively maintaining `mod_winbind`; it is **orphaned**. If you
have some programming experience and would like to take over maintainership,
I'd be happy to answer questions and provide initial guidance.


Setup
=====

* Make sure `mod_winbind` is compiled into ProFTPD on your system,
  or that `mod_winbind.so` is available as a DSO.

   * If not, [read the general instructions on compiling ProFTPD](http://www.proftpd.org/docs/howto/Compiling.html) or
     [building ProFTPD modules as DSOs](http://proftpd.org/docs/howto/DSO.html).

     Copying `mod_winbind.c` into `proftpd-`_version_`/contrib/` and building
     ProFTPD with:
```
$ ./configure --with-modules=mod_winbind
```
     is a good start.  You'll need Samba's Winbind client library,
     `libwbclient`, *and* its development header, `wbclient.h`, to compile
     `mod_winbind`.

* Enable `mod_winbind` in your `proftpd.conf`:

        <IfModule mod_winbind.c>
          WinbindEngine on
        </IfModule>

* To automatically create home directories for your users, also add:

        CreateHome on

* By default, `mod_winbind` is *not* authoritative. When a user does not exist
  in the Windows domain, other ProFTPD authentication modules are given
  the chance to authenticate the user, so local Unix users and groups
  can be used. If you want ProFTPD to use *only* the Windows domain, add:

        AuthOrder mod_winbind.c*


Configuring the Winbind Daemon
==============================

Install Samba(http://www.samba.org/) and configure Winbind in `smb.conf`.
For example:

    [global]
    realm = dns-domain-of-your-windows-domain
    workgroup = windows-domain-name
    password server = domain-controller-hostname
    security = ads
    idmap uid = 10000-20000
    idmap gid = 10000-20000
    template shell = /bin/bash
    template homedir = /home/%U
    winbind use default domain = yes

Users will be assigned UIDs and GIDs between 10000 and 20000, and their home
directories will be placed in `/home`.

Then, join the Windows domain:

    net rpc join -S domain-controller.example.com -U Administrator
