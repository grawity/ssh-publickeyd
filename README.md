# ssh-publickeyd, a RFC 4819 server

This is a server implementation of VanDyke's [RFC 4819][] public key management protocol for SSHv2, which lets clients upload authorized SSH keys without needing to know implementation details. In the future it might also support [RFC 7076][].

## Configuring OpenSSH server

Add the following to your `/etc/ssh/sshd_config`:

    Subsystem  publickey              /usr/local/bin/ssh-publickeyd
    Subsystem  publickey@vandyke.com  /usr/local/bin/ssh-publickeyd

You'll also need [nullroute.authorized\_keys](https://github.com/grawity/code/blob/master/lib/python/nullroute/authorized_keys.py) somewhere Python can find it. Apologies for not making it a proper pip module yet.

## Writing a client

publickeyd is meant to be invoked as a SSH _subsystem_, for example, using `ssh -s foo.example.com publickey` or libssh2\_channel\_subsystem() ([example](http://www.libssh2.org/examples/subsystem_netconf.html)).

However, the only difference between normal commands (`ssh foo whoami`) and subsystems is that the latter have a well-known name. Otherwise they work like regular commands and speak over stdin/stdout.

After connecting, speak the [RFC 4819][] protocol. Its structure follows the main SSH protocol (binary length+data packets); see [RFC 4251 §5][] for a short reference.

## Known clients

 - VanDyke SecureCRT (did most of the testing on this)
 - Bitvise Tunnelier ([apparently](https://www.bitvise.com/wug-publickey), but untested)
 - Multinet SSH (untested)
 - there is a [wishlist](http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/subsystem-publickey.html) entry for PuTTY
 - no OpenSSH yet

## Known servers

 - VanDyke VShell
 - Bitvise WinSSHd
 - Multinet SSH
 - ssh-publickeyd!

[RFC 4819]: https://tools.ietf.org/html/rfc4819
[RFC 7076]: https://tools.ietf.org/html/rfc7076
[RFC 4251]: https://tools.ietf.org/html/rfc4251
[RFC 4251 §5]: https://tools.ietf.org/html/rfc4251#section-5
