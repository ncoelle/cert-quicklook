Plug-in for QuickLook to allow easily generate preview of various unprotected certificate tokens.

Currently includes support for X509 certificates, DER or PEM (ASCII-armored).

Future plans includes extending for other types of data: keys, revocation lists, signing requests, e.t.c.

Tested with MacOS 10.5.8/10.6.6/10.7.1

## Do i need it? ##
If you work with certificate files and you are on OSX, you probably can be interested in installing the plugin. It allows you to view content of your certificates directly from Finder via QuickLook technology.

## How does it look? ##
Here is a screenshot:

![http://cert-quicklook.googlecode.com/svn/trunk/wiki/scr01.png](http://cert-quicklook.googlecode.com/svn/trunk/wiki/scr01.png)

## But Lion(10.7) has built-in QuickLook support for PEM files? ##
It is. But it doesn't work with .cer, .der, .crt, e.t.c. files. And if you are on 10.6 (Snow Leo) or 10.5 (Leo) - you have no QuickLook support for certificates.

## How can i install it? ##
  1. Download latest version zip arhive.
  1. Unzip
  1. Copy **CertQuickLook.qlgenerator** to **~/Library/QuickLook/** (or **/Library/QuickLook/** )
  1. Wait for awhile until QuickLook will find new plugin (or run in terminal: **qlmanage -r**, if you impatient to try it ;)
  1. Browse your cert files (.crt, .cer, .der, .pem are supported for now)

## Can i browse protected files: .p12? ##
  1. stay tuned, there are some ideas how to do this in next versions

## What if preview is not working for my files? ##
  1. well, there can be defects as in any other software. If you files are NOT top-secret you can send them to me or raise an issue for the project. We'll try to troubleshoot.