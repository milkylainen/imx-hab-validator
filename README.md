# imx-hab-validator
i.MX8 HABv4 userspace CSF validator  
Should be a pretty straight forward build.  
Relies on OpenSSL and list.h. list.h being either the Linux or the BSD fork one.

```
$ autoreconf -i
$ ./configure
$ make
```
Usage is a payload with IVT+CSF.  
This is validated as to it's own integrity and terminated in the user provided  
super root key hash, which should be calculated to the same as for the keys  
in the super root key table.  
Caveats apply. This is built as per my understanding and not peer reviewed  
by HAB experts. No guarantees of anything of any sort. Expressed or implied.
