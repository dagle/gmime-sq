Sequoia support for gmime
=========================

Currently a WIP. 

For examples how to use this lib with gmime. Checkout the test.c
If you don't know how to use gmime, read the gmime documentation first.

For password protected secrets to work, you need to set a password function. Because
compared to gpg, sequoia doesn't come with a default one.

The library uses gmime-rs and subclasses the cryptocontext. It then creates
library called galore with the galore namespace (placeholder, this will change
in the future). Using the header file, a gir and a typelib file is generated,
which then can be used like any gobject.

Currently it's not possible to use this sequoia code directly with introspection (if you 
want to write your code in python, lua or something else). You will need to write a small
C wrapper to wrap the functions that are not introspectable. 
