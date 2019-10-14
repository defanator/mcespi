MIPS IPsec library

Forked from https://sourceforge.net/projects/mcespi/files/

# MIPS tuning

> Those of you that are on MIPS *big endian* machines can replace the default `aes_generic.ko`, `sha_generic.ko`, `cbc.ko` and `md5.ko` modules with a single assembler optimized `mcespi.ko`. The module is quite some years old and a first experience with crypto modules. Nevertheless it will work quite fine but needs manual compiling. The easyiest way to install it includes a few steps.
>
> - create a buildroot environment
> - compile an image for your router once
> - put the `mcespi.c` into the the folder `build_dir/target-<arch>/linux-<cpu-model>/linux-X.Y.Z/crypto`
> - Include the line `obj-$(CONFIG_CRYPTO_MD5) += mcespi.o` into `build_dir/target-<arch>/linux-<cpu-model>/linux-X.Y.Z/crypto/Makefile`
> - compile the image once again.
> - Afterwards you will find `build_dir/target-<arch>/linux-<cpu-model>/linux-X.Y.Z/crypto/mcespi.ko`
> - Put `mcespi.ko` to your router into `/lib/modules/<X.Y.Z>`
> - Load the module with `insmod`
> - For automatic loading create a new `/etc/modules.d/09-crypto-mcespi` with corresponding content.

(documentation taken from [https://openwrt.org/docs/guide-user/services/vpn/ipsec/strongswan/performance#mips_tuning](https://openwrt.org/docs/guide-user/services/vpn/ipsec/strongswan/performance#mips_tuning))
