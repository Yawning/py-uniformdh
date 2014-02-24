## py-uniformdh - OpenSSL based UniformDH
#### Yawning Angel (yawning at schwanenlied dot me)

### What?

This is a OpenSSL based UniformDH implementation for obfs3/ScrambleSuit.
It is a drop-in replacement for obfsproxy/transports/obfs3_dh.py

### Usage

    import uniformdh

    my_keypair = uniformdh.UniformDH()
    my_public = my_keypair.get_public()

    # Get the other public key

    shared_secret = my_keypair.get_secret(their_public)

### Implementation notes

 * This uses OpenSSL.
 * This uses C.
 * It matches the gmpy based implementation in performance.
 * Because it uses OpenSSL's DH code, the mod exp operation is blinded.
 * It properly removes the private keys from the heap.  Though that's sort of
   fighting for a lost cause since the shared secret is passed back to Python.
 * Because no official test vectors for UniformDH exist, I made some.

