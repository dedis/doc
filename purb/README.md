# Leakage-Hardened Encryption via Padded Uniform Random Blobs (PURBs)

(abstract)

Encrypted data formats typically leak two forms of side-channel information that
can be useful to attackers: (1) unencrypted headers and other internal metadata,
and (2) the (approximate) length of the encrypted plaintext.  This document
proposes an application-independent discipline for eliminating the first form of
leakage and minimizing the second in new or upgraded formats for encrypted data,
by encrypting *all* content including metadata and padding it to one of a
standard set of sizes.  The resulting Padded Uniform Random Blobs or PURBs,
properly formed, are cryptographically indistignuishable from each other within
a given "size bucket" even across different applications that might generate
PURBs, and hence reveal no metadata to potential attackers even about the
encryption scheme used, who or how many recipients can decrypt it, or what
application or software version created it.  Even a PURB's length provably leaks
at most O(log log L) bits of information about a plaintext of length L -
asymptotically the best possible for any practical scheme allowing
variable-length plaintexts - while incurring at most 12% padding overhead on any
ciphertext and at most 6% overhead on ciphertexts 256 bytes or greater.

## Building

In order to compile the purb.md file into an html or txt file, you first need to
install:
+ xml2rfc: http://xml2rfc.ietf.org/
+ mmark: https://github.com/miekg/mmark

After that, a simple `make` will produce an HTML version of the draft.

## Contributions

All contributions are welcome. You may first open an issue to talk about
specific points of the draft or directly open a pull request explaining your
proposed changes. 
