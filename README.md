initify plugin
=============

Move string constants (__func__ and function string arguments marked by the nocapture attribute)
only referenced in __init/__exit functions to __initconst/__exitconst sections.

The kernel patches required by the plugin are maintained in PaX (http://www.grsecurity.net/~paxguy1/) and grsecurity (http://grsecurity.net/).

Compiling & Usage
-----------------

##### gcc 4.5 - 5.0:

```shell
$ make clean; make
```

##### Usage

```shell
$ make run
```
