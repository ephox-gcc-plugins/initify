initify plugin
=============

This plugin has two passes. The first one tries to find all functions that
can be become __init/__exit. The second one moves string constants
(local variables and function string arguments marked by
the nocapture attribute) only referenced in __init/__exit functions
to __initconst/__exitconst sections.
Based on an idea from Mathias Krause <minipli@ld-linux.so>.

The kernel patches required by the plugin are maintained in PaX (http://www.grsecurity.net/~paxguy1/) and grsecurity (http://grsecurity.net/).

Compiling & Usage
-----------------

##### gcc 4.5 - 6:

```shell
$ make clean; make
```

##### Usage

```shell
$ make run
```
