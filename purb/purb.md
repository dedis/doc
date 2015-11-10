% Title = "Leakage-Hardened Encryption via Padded Uniform Random Blobs (PURBs)"
% abbrev = "Padded Uniform Random Blobs"
% category = "std"
% docName = "draft-ford-cfrg-purb-00"
% area = "Application"
% workgroup = "CFRG"
% keyword = [""]
%
% [[author]]
% initials="B."
% surname="Ford"
% fullname="Bryan Ford"
% organization = "EPFL"
%   [author.address]
%   email = "bryan.ford@epfl.ch"
%   phone = "+41 21 693 28 73"
%   [author.address.postal]
%   street = "BC 210, Station 14"
%   city = "Lausanne"
%   code = "CH-1015"
%   country = "Switzerland"

.# Abstract

Encrypted data formats typically leak two forms of
side-channel information that can be useful to attackers:
(1) unencrypted headers and other internal metadata, and
(2) the (approximate) length of the encrypted plaintext.
This document proposes an application-independent discipline
for eliminating the first form of leakage and minimizing the second
in new or upgraded formats for encrypted data,
by encrypting *all* content including metadata
and padding it to one of a standard set of sizes.
The resulting Padded Uniform Random Blobs or PURBs, properly formed,
are cryptographically indistignuishable from each other
within a given "size bucket"
even across different applications that might generate PURBs,
and hence reveal no metadata to potential attackers
even about the encryption scheme used,
who or how many recipients can decrypt it,
or what application or software version created it.
Even a PURB's length provably leaks
at most O(log log L) bits of information about a plaintext of length L -
asymptotically the best possible
for any practical scheme allowing variable-length plaintexts -
while incurring at most 12% padding overhead on any ciphertext
and at most 6% overhead on ciphertexts 256 bytes or greater.

{mainmatter}

# Introduction

Traditional encrypted data formats -
whether designed for "at-rest" data (e.g., OpenPGP-encrypted files [@!RFC4880])
or "in-transit" data (e.g., TLS blocks [@!RFC5246]) -
usually attempt to encrypt only "content" or "payload" data
while leaving a variety of "surrounding" metadata unencrypted.
Such unencrypted metadata often includes
magic numbers identifying the file type or chunk type,
format version information,
encryption and integrity protection algorithms used,
the number and possibly the identities
of potential receipients who can decrypt the file, etc.
The traditional justification for this approach is that
it makes decryption simple and efficient for legitimate receivers
without leaking "obviously useful" information
to attackers not holding the relevant decryption keys.
Unfortunately, experience has shown that realistic attackers
can leverage this metadata - including its length -
in surprising and subtle ways.

This document therefore proposes an alternative paradigm
for designing encrypted data formats
for either "at-rest" or "in-transit" data.
A compliant data producer or sender encrypts
not just application payload but *all* metadata,
while padding the ciphertext to one of a standard set of allowable lengths,
producing what we refer to as a Padded Uniform Random Blob or PURB.
Provided that PURBs are properly formed using strong encryption schemes,
an attacker not holding the relevant keys cannot distinguish -
or hence learn anything about - PURBs within a given size category,
including even which application created it.
Of course the context in which a PURB appears -
such as the filename assigned to a file containing a PURB -
might still leak information about its content,
but we treat such contextual leakage as out of scope for present purposes.

## Motivation for Metadata Protection

XXX fill out 
Motivations: anonymize, protect metadata, hide identities.
- hide what application it's for, which may be sensitive.
	(Is it a PGP-encrypted document or just an encrypted swap file
	some application left behind?)
- hide what version of an application created it:
		knowing the version can give attacker clues
		as to whether it has a known crypto weakness worth the cost
		of attempting to exploit.
- hide the internal structure of the file:
	e.g., how long records are, which can leak important information
	about the contents - such as the length of individual files
	within an encrypted archive,
	which might be recognizable or fingerprintable.
- hide the identity or identities of whomever may be able to read it.
	Revealing who it's for enables rubber-hose decryption attacks.
- hide the NUMBER of potential readers or receipients.
	Is this encrypted message for one person or a group?
	Does this encrypted partition contain only one volume,
	a "hidden volumes" as in TrueCrypt,
	or even multiple hidden volumes?
- enhance plausible deniability: 
	if any of several applications could have created an encrypted blob
	for any of a variety of different purposes,
	it's much easier to deny that it contains something sensitive,
	or even something the user is able to identify or decrypt.
etc.

## Example Metadata-related Attack Vulnerabilities

While this unencrypted metadata was not thought to be privacy-sensitive
when the OpenPGP format was first designed,
the evolution of today's threats have called this assumption into question.
For example, the very existence on a hard drive
of a file that is readily identifiable as OpenPGP-encrypted
can arouse suspicion and has been known to lead
airport, border-control, and other authorities of some countries
to demand passwords or decryption keys under threat of incarceration
even if it is not clear that the holder of the device
is in possession of the necessary decryption keys.
Furthermore, as the state-of-the-art in cryptanalysis and brute-force attacks
gradually overtakes the security of older cryptographic schemes,
the existence of a cryptographic scheme identifier in cleartext
effectively acts as a "crack me!" flag,
making it unnecessarily easy for an attacker to invest computational resources
selectively into cracking ciphertexts known to use weak cryptographic schemes,
while avoiding wasting compute resources attempting to crack ciphertexts
encrypted under stronger schemes.
The number of distinct public keys that can decrypt a file
can serve to identify the group of people for which the file was encrypted.
Finally, even the file's length can represent sensitive,
possibly incriminating information especially in known-plaintext situations,
e.g., when an attacker suspects but cannot otherwise prove that
an OpenPGP file on a suspected whistleblower's or dissident's hard disk
is an encryption of a particular document.

XXX fill out with some more specific, real-world examples of relevant attacks.
e.g., CRIME attack?
e.g., weak ciphers like RC4,
whose ciphertexts are more readily and cheaply identifiable
when they come labeled "RC4!!"


# Padded Uniform Random Blobs (PURBs)

This section defines a raw binary format for PURBs,
an ASCII-encoded format,
and a set of lengths that PURBs are allowed to have.
The content of this section represents the entire and *only*
"normative" specification intended to be universally applicable
to all creators of PURBs.
Later sections provide information about practices
for designing specific applications producing PURBs,
but these practices purely informational
and need not be agreed upon between different applications
that might produce and consume PURBs.

A specific PURB-producing application must of course
provide a (separate) specification of the mechanisms
and internal data formats for that application.
Only a compatible PURB consumer application holding appropriate keys
will be able to decrypt - or even identify -
PURBs in that format that were properly formed using strong encryption.
But as an essential side-effect of the "application-indistinguishability"
properity that the PURB concept provides,
all data format details other than the minimal normative specification
in this session may be left to separate, application-specific specifications.

## Binary-encoded PURB format

A binary PURB is just a sequence of octets of some length L,
which MUST be constrained to
a certain set of allowed values as described below.
The PURB's content MUST be encoded in such a way that every one
of the 8L bits comprising the PURB
appear cryptographically indistinguishable from 8L
independently and uniformly random coin-flips,
as perceived by to anyone who knows none of the particular secrets (i.e., keys)
that were used in creating the PURB.

An "ideal" but practically useless way to create a PURB of length L is simply
to flip a fair coin 8L times.
More practically useful ways to create URBs employ cryptographic techniques
of the type informationally discussed in later sections,
but this specification makes no requirement whatsoever about
precisely how the URB's content is encoded:
only that every bit must "appear" independently and uniformly random.

## ASCII-encoded PURB format

XXX base64 (which?) or radix-64 from pgp, or PEM?
specify # chars per line, etc.

possibly delimited by:

	BEGIN BINARY DATA

	END BINARY DATA

or BEGIN/END ENCRYPTED DATA?

### Justification for ASCII encoding (Informative):

In any context that "normally" contains human-readable text,
a binary blob encoded in any space-efficient way is almost certain
to stand and and look "obviously" like encrypted data of some kind.
So we're not giving away much by indicating that it's a binary blob.
We just don't want to leak anything about what's in it
or how it was created.

## Allowed PURB ciphertext lengths

The following algorithm defines the set of possible lengths L
that PURBs are allowed to have:

1. For a given candidate length L greater than zero,
let B = ceil(log2(L)).
B represents the number of bits comprising
the shortest two's-complement binary representation of L.

2. Let S = ceil(log2(B))+1.
S determines the number of "significant figures"
L's binary representation may have, as explained below.

3. The given length L is an allowed PURB length
if and only if the least-significant (B-S) bits
of L's binary representation are all zero.

Note that this specification does not impose any upper bound on L,
so the set of allowed PURB lengths is infinite.
Particular PURB-generating applications or formats
may define a maximum length of PURBs generated by that application,
but any such restrictions are application-specific
and outside the scope of this specification.


### Table of example PURB lengths (Informational)

The following table schematically illustrates the binary representations
of allowed PURB lengths between 1 and 2^32,
where '?' characters represent significant figures,
 or "don't-care" bits that may be have values of either 0 or 1:

	Binary representation of length L	Parameters
	---------------------------------	----------
	00000000000000000000000000000001	B=1, S=1
	0000000000000000000000000000001?	B=2, S=2
	000000000000000000000000000001??	B=3, S=3
	00000000000000000000000000001??0	B=4, S=3
	0000000000000000000000000001???0	B=5, S=4
	000000000000000000000000001???00	B=6, S=4
	00000000000000000000000001???000	B=7, S=4
	0000000000000000000000001???0000	B=8, S=4
	000000000000000000000001????0000	B=9, S=5
	00000000000000000000001????00000	B=10, S=5
	0000000000000000000001????000000	B=11, S=5
	000000000000000000001????0000000	B=12, S=5
	00000000000000000001????00000000	B=13, S=5
	0000000000000000001????000000000	B=14, S=5
	000000000000000001????0000000000	B=15, S=5
	00000000000000001????00000000000	B=16, S=5
	0000000000000001?????00000000000	B=17, S=6
	000000000000001?????000000000000	B=18, S=6
	00000000000001?????0000000000000	B=19, S=6
	0000000000001?????00000000000000	B=20, S=6
	000000000001?????000000000000000	B=21, S=6
	00000000001?????0000000000000000	B=22, S=6
	0000000001?????00000000000000000	B=23, S=6
	000000001?????000000000000000000	B=24, S=6
	00000001?????0000000000000000000	B=25, S=6
	0000001?????00000000000000000000	B=26, S=6
	000001?????000000000000000000000	B=27, S=6
	00001?????0000000000000000000000	B=28, S=6
	0001?????00000000000000000000000	B=29, S=6
	001?????000000000000000000000000	B=30, S=6
	01?????0000000000000000000000000	B=31, S=6
	1?????00000000000000000000000000	B=32, S=6

Because the number of significant figures S
gradually increases with PURB size,
large PURBs entail less padding overhead or "waste"
when considered as a fraction of total PURB size.
For example, for PURBs of length at least 256 bytes but less than 64KB
(the region where S=5), 
mandatory padding imposes at most 6.25% waste,
while PURBs at least 64KB and less than 4GB (S=6)
incur at most 3.12% waste through padding, 
and large PURBs at least 4GB and less than 2^64 bytes (S=7)
incur at most 1.56% waste.

Despite this low (and decreasing with size) waste,
PURBs leak at most O(log log L) bits of information via their length.
This leakage is asympotically optimal for any "reasonable"
variable-length encrypted data format, as explained in more detail below.


### Motivation and theory of PURB lengths (Informational)

If the cryptographic methods used to encode an PURB are sound,
then the PURB's 8L bits of content should leak no information
to an observer with no access to relevant secrets about the PURB.
However, the PURB's length L can still leak information about its content.
Unintended side-channel information leaks via the length of encrypted blobs
can and have led to real security problems:
for example: (TLS record-length attacks with compression, etc.)

We could simply mandate that all PURBs have a single fixed length,
but this is unrealistic since many applications can create and consume
files or network transmissions whose lengths often differ
by many orders of magnitude.
Requiring all URBs to be padded to a large fixed length
would be extremely wasteful when ...  (XXX finish)

XXX intermediate strawman: just round to next power of 2,
but that incurs up to 50% waste.

XXX explain: in any "reasonable", "practical" encoding
that needs to allow an arbitrary range of lengths,
where we are willing to tolerate some (constant) maximum fraction of waste,
we have to allow powers-of-something.
Regardless of what power we use, this yields O(log log N) information leakage.
This is thus the best we can do for this broad class of encrypted encodings.

Given that encryption itself without padding reduces leakage
from O(L) bits (the plaintext content itself)
to O(log L) bits (the un-padded length of the content),
a further reduction from O(log L) to O(log log L) leakage
is clearly significant from an asymptotice perspective.

But ... explain how with the above PURB allowed purb length algorithm
we still guarantee at most O(log log L) leakage, the optimal,
while keeping the actual (constant-factor) waste much smaller in practice,
and decreasing for larger PURBs (for which we probably care more about waste).


# Practices for At-Rest PURB Data Formats (Informational)

XXX summarize the objectives and challenges.

## Multi-entrypoint PURB encryption

The sections below outline a scheme for encoding PURBs
that allows for multiple heterogeneous "entrypoints" for
different legitimate receivers who might need to decrypt the PURB
in different ways.

The main desirable properties the scheme has are (a) it produces uniform random
blobs with no unencrypted metadata; (b) it supports multiple encryption
schemes, both passphrase and/or public-key - though “too many” schemes would
get costly; (c) it supports multiple passphrase and/or recipient public keys
with each scheme; (d) for a given scheme and a given passphrase or private key
held by a recipient, the recipient needs to perform at most one public-key
crypto operation and O(log N) symmetric-key crypto operations - and to read a
similarly small part of the input - in order to determine if the file is
encrypted for this recipient passphrase/keypair and unlock it if so.


We work from a simple case to progressively more “interesting” and general cases:

1. Encryption using a single scheme (e.g., a single well-known “ciphersuite”) via a single passphrase.

2. Single symmetric-key scheme, but multiple alternative passphrases using that scheme.

3. Single public-key encryption scheme, with message encrypted for one or multiple public keys compatible with that scheme.

4. Multiple symmetric and/or public-key schemes, allowing multiple different passphrases and recipient public-keys each, respectively.

(Warning: all the text in the subsections below needs to be
cleaned up and clarified.)

### Encryption using a single scheme via a single passphrase

Suppose simplistically we only want single-passphrase encryption using a single
well-known encryption scheme.  More-or-less as usual for PGP, we (a) choose a
random session key, (b) use a password-hashing scheme such as Argon2 to produce
a symmetric encryption key that is used to AEAD-encrypt the file’s session key,
and (c) use the session key to AEAD-encrypt the file’s content.  Assume for now
that we encrypt the file in one big chunk, though chunking (with metadata
encryption) can be added as well using existing techniques (e.g., those
mentioned earlier analyzed in the context of SSH).

So we basically have three important blobs of data to place in the file: (a)
the salt for the password-hashing scheme, (b) the AEAD-encrypted session key
encrypted using the password-hasher’s output, and (c) the AEAD-encrypted file
content encrypted using the session key.  Item (a) needs to be encoded in the
file in “cleartext” since it needs to be available to the decryptor before it
can decrypt anything, but fortunately the salt can just be a uniformly random
blob anyway (of a length fixed by this well-known scheme).  So for the moment
let’s just put it at the very beginning of the encoded file.  Then place the
AEAD-encrypted session key blob (b) immediately afterwards, whose size can also
easily be fixed for this scheme.  This fixed-length session-key blob may
contain encrypted metadata in addition to the session key, such as the file
offset of the AEAD-encrypted file content, the (possibly padded) total size of
the AEAD-encrypted blob, and perhaps the size of the “useful payload” within
that blob after removing any padding.  This metadata will of course appear as
uniform random bits to a non-recipient as long as the AEAD encryption scheme is
doing its job.  Finally, place the AEAD-encrypted file content (c), including
any padding, after the encrypted session-key blob as the rest of the file.

### Single passphrase-encryption scheme, multiple passphrases

Now assume we want to encrypt with multiple passphrases.  Perhaps not a highly
compelling case, but it’s conceptually simpler to start with than multiple
recipient public-keys but addresses the same technical issues.  The approach
Neal suggested of using Bloom filters is not far off, but we at least wouldn’t
want to use *unencrypted* Bloom filters that might look distinguishable from
random bits.

As a straw-man design suppose we just pick an upper-bound on the number, say N,
of different passphrases with which we expect anyone might ever want to encrypt
a file.  Then we lay out the encrypted file as follows: (a) a single, uniformly
random password-salt value of fixed length comes first in the file, followed by
(b) a hash table with room for not just one but N consecutive AEAD-encrypted
session-key blobs of the same kind as for the single-password scheme above, and
finally (c) the AEAD-encrypted file content.  Both the encryptor and decryptor
use the salt to hash the user’s password, then hash the output of that to form
both the AEAD-encryption key for the session-key blob and an index into the
N-entry hash table.  The decryptor then simply attempts to AEAD-decrypt and
check that particular hash-table entry - or to allow for rare hash collisions,
attempts to decrypt (say) three consecutive hash-table entries starting at that
position and wrapping around mod N.  If any of those AEAD-decryptions works,
the decryptor wins; if not, the decryptor gives up and decides the passphrase
doesn’t work.

Since each passphrase will produce a different (pseudo-random) hash-index, the
session-key blobs for different passphrases will typically occupy different
positions in the hash-table, thereby allowing decryption using any of the
corresponding passphrases.  Hash collisions may occur, but if the number of
actual passphrases is not too close to N (i.e., the hash table not too full),
the encryptor should be able to squeeze in session-key blobs for all of them
using the “slop” allowed by the 3-tries (or k-tries) search rule above, and/or
by simply retrying everything from scratch with a fresh salt if that doesn’t
work.  Once the hash table is laid out and filled with all useful session-key
blobs, all remaining unused entries are just filled with uniform random bits,
so anyone not holding one of the passphrases can’t distinguish “full” from
“empty” hash-table entries.

Now the next step we’d like is to avoid having to pick a particular value of N:
too large and we’re wasting a lot of space at the beginning of every file on a
hash table that often will probably have only 1 entry populated; too small and
we don’t allow for multiple session key blobs.  So instead of including just
one hash table in the file, we include a variable-length sequence of hash
tables whose sizes increase by powers of two.  Thus, immediately after the
password-hashing salt, we encode a 1-entry hash table, followed by a 2-entry
hash table, followed by a 4-entry hash table, etc., stopping wherever the
encoder feels like stopping.  The encoder takes the passphrases it’s supposed
to encrypt the file with, and successively creates an encrypted session-key
blob for each passphrase, storing it at the appropriate hashed position (for
that passphrase) - or within a 3-tries distance - in the lowest-numbered hash
table that has room for it.  Then the encoder writes out to the encrypted file:
(a) the common password-encryption salt, (b) all the *non-empty* hash tables
starting from the size-1 table, with any empty entries filled with uniform
random bits, and (c) the AEAD-encrypted file content, as usual.  Note that the
encryptor can “lay out” the header and figure out how many hash tables are
actually needed before it does the AEAD-encryption of the session key blobs,
which means those session key blobs can still contain the file offset and
length metadata pointing to the encrypted file content.

On the decryptor side, given the salt at the beginning of the file and the
user’s passphrase, the decryptor now needs to generate a hash-index for each
possible hash table and try decrypting a few consecutive entries per hash
table.  Neither the decryptor, nor anyone else, initially knows the number of
hash tables in the file.  But note that the decryptor only needs to do a single
expensive password-hashing operation (with that one salt and the entered
password).  Also, since the total number of hash tables is log2(N) where N is
an upper-bound on the number of recipients, the total number of symmetric-key
trial-decryptions the recipient needs to perform to see if the passphrase
“works" is O(log N), regardless of the number of passphrases the file was
actually encrypted for.  We might want to set some kind of upper bound on the
maximum size that the header portion might be, of course, but that can probably
be fairly large (e.g., 1MB) since it’s just an upper bound.  In the common case
when a file is encrypted with only one passphrase, only the first, size-1 hash
table is non-empty, and the encrypted file is just as compact as it would be in
the “naive” base-case design above that only supports a single passphrase.

### Single public-key encryption scheme, multiple recipient public keys

We now assume that we wish to encrypt a file so as to be decryptable by
multiple receivers, the encoder has public keys for all those receivers, and
(most importantly) all those receivers’ public keys are in the same group:
e.g., they are all Ed25519 keys or all Ed448 keys.  This assumption is not very
realistic for “legacy” DSA keys and not realistic at all for RSA keys, but
let’s assume we’re willing to live with that restriction at least for “new”
files encrypted this way.

Structurally, the public-key multiple-receivers scheme works exactly the same
as above for passphrase encryption, but the encryptor (a) replaces the
password-hashing salt at the beginning of the file with an Elligator-encoded
ephemeral Diffie-Hellman public key, whose corresponding private key was
freshly picked by the encryptor; (b) computes a shared Diffie-Hellman master
secret using this ephemeral private key and each receiver’s public key (which
as stated above we assume all to be in a common group); and (c) AEAD-encrypts
all the session-key blobs in the hash tables using these Diffie-Hellman master
secrets instead of password-based secrets.  Everything else about hash table
layout and such works exactly the same way as discussed above for multiple
passphrases.

For those not familiar with Elligator and its follow-on work (e.g., Elligator
2, Elligator Squared, Binary Elligator Squared), all are ways to encode an
elliptic curve point usable for Diffie-Hellman key exchange, such that the
encoding appears indistinguishable from uniform random bits.  Different schemes
apply to different subsets of elliptic curves and impose different tradeoffs:
e.g., the original scheme works only for certain curves (including Ed25519) and
is very compact but may require the encoder to retry the generation of the
ephemeral DH point several times (no big deal in practice); other later schemes
are a bit less compact (e.g., require 2x the space for the representation) but
less constrained and can encode any point on the curve rather than only about
half the points, etc.  The details aren’t important for present purposes; only
the fact that they exist and they work. :)

So because Elligator encodes the initial DH key in uniform representation, and
everything else in the file is either an AEAD-encoded blob or just random bits,
the whole file looks like uniform random bits to anyone not holding one of the
recipients’ private keys.  A non-recipient can’t even tell whether the file is
encrypted to just one recipient (the Elligator-encoded point followed by the
size-1 hash table followed by the encrypted file content) or to many (the
Elligator point followed by several hash tables).  The decryptor doesn’t know
this either without trying, but the decryptor only needs to do the one
public-key DH agreement calculation to compute its ephemeral secret shared with
the encryptor, and then perform at most O(log N) AEAD trial decryptions to see
if its key works near the appropriate indexes of any of the O(log N) hash
tables.

### Multiple symmetric-key and/or public-key schemes

This is where things start to get still a bit more hairy, although the
underlying principles remain pretty similar.  The problem now is that we may
now have multiple, different and incompatible encryption schemes: e.g., we
might want to encrypt a file both with a passphrase *and* for several
public-key recipients, some of whom have (say) Ed25519 keypairs while others
have Ed448 keypairs while others have NIST P-* keypairs.  We’ll assume (a) that
all public-key schemes are in DH-compatible, Elligator-encodable groups of some
kind, and (b) we will administratively avoid needing to support a huge number
of different schemes all at once.  (It feels like this assumption is compatible
with where the CFRG and OpenPGP WGs are headed anyway.)

So as should be clear from the above by now, the “cornerstone” of each scheme
is a salt value in the case of a passphrase scheme, and an Elligator-encoded
point in the case of a public-key scheme.  Passphrase salts can just be
unstructured random bits, so in that case one might imagine just starting the
file with a single “common salt” large enough to seed all the passphrase-based
schemes we might want to support (if we even want to support more than one in a
given file, which might be unlikely).  But an Elligator-encoded point must be
created rather carefully such that the encryptor knows the corresponding
private key for DH agreement, so it’s not feasible to dump some random bits at
the beginning of the file and expect it to be usable as multiple different
Elligator points for multiple different curves: we really need to encode
multiple distinct Elligator points for distinct curves so that they’re all
independently decodable.  

Further compounding the challenge, we don’t want the decryptor to have to
perform multiple expensive public-key operations (or multiple expensive
password-hashing operations) per scheme.  We can’t avoid the decryptor having
to do *one* expensive public-key or password-hashing operation per scheme that
the user might hold a key for: e.g., if the user’s keychain holds both an
Ed25519 private key and an Ed448 private key, we’ll have to do two Elligator
point decodes and two DH key agreements, but we want to avoid having to do more
than two.  (And for the common-case of users holding only one private key, we
want the user to have to do only one DH key agreement.)

So to solve this, we’ll use a multiple-hash-table approach similar to the above
to allow a file to contain multiple “cornerstone” values (password salts and/or
Elligator points) at the beginning, but slightly modified to avoid the need for
multiple trial decryptions.  For each scheme, we take that scheme’s cornerstone
value (e.g., Elligator point), and first round its size up to the next power of
two.  Next, for each scheme, we pick (via standardization) an upper bound on
the total number of other *schemes* we want this scheme to be compatible with
now and in the near future (i.e., number of other distinct cornerstone values
we need to encode at the beginning of the file).  For each scheme, we then
standardize a small number of possible positions for that scheme’s cornerstone
value, perhaps chosen more-or-less randomly (but statically), one position per
hash table within a small number of hash tables laid out in increasing
power-of-two sizes exactly as earlier for session-key blobs.  We ensure, again
via standardization, that among the set of schemes we want to be compatible
with each other, each scheme has at least one possible position (perhaps the
largest) for which its cornerstone can be encoded so as to be disjoint and
non-overlapping with at least one possible position of every other scheme.

For example, suppose we want to support Ed25519, Ed448, and P-384, and may want
to support other schemes later on whose recipient keys can be intermixed with
keys from these schemes.  Let’s say that we can Elligator-encode an Ed25519
point in 32 bytes (true), we can Elligator-encode an Ed448 point in 64 bytes
(not sure about this, but either that or a 128-bit encoding should be
feasible).  We might pick 3 possible cornerstone-value positions for each of
these schemes as follows:

* Ed25519: offset 0, offset (32 or 64), and offset (96, 128, 160, or 192).
* Ed448: offset 0, offset (64 or 128), and offset (192, 256, 320, or 384).

For each of the parenthesized alternatives, give the OpenPGP WG chairs a coin
during some meeting and have them flip it to pick one of the two or four
alternatives for the second and third possible position for each scheme. :)

Future schemes we might add will come with their own list of possible
cornerstone-value positions, which can be of varying lengths, and similarly can
overlap (though all of them should have 0 as the base-case offset) provided we
maintain the invariant that each scheme we still care about has some unique
position that doesn’t overlap with any other scheme we still care about.  We
can also optimize the possible positions more carefully if we choose; the above
example is just to keep things conceptually simple.

Now, when the encryptor is encrypting an OpenPGP file, it creates a cornerstone
value suitable for each scheme, and picks a position for each scheme’s
cornerstone value from the fixed list of available positions for that scheme,
such that the actually-picked cornerstone value positions are as low as
feasible but don’t overlap.  For example, if a file is encrypted with both
Ed25519 and Ed448 receiver keys, the “best” set of positions from those above
might be position 0 for the Ed448 key and position 64 for the Ed25519 (other
choices would also work but be a bit less space-efficient).  But now the
encryptor needs to encode these cornerstone values so that the decryptor can
get exactly the cornerstone value it needs, on the “first try”, without
actually knowing at which possible position for a given scheme it was encoded.

So here’s the trick: we use a variant of DC-nets or PIR-type encoding
techniques to “anonymize” the true position at which a given cornerstone value
is encoded.  In particular, the encoder arranges the file such that for each
scheme, the decoder reads *all* of the possible cornerstone value positions for
that scheme, and XORs them together, to reconstruct the “actual” cornerstone
value for that scheme.  That is, to get the Elligator-encoded Ed25519 point,
the decoder will read the 32 bytes starting at each of the three positions
defined for Ed25519, then XOR these 32-byte sequences together, and use that as
the Ed25519 point.  Similarly for the other schemes.

The important point is that as long as the encoder picks some “workable” order
in which to encode all the cornerstone values, it can treat previously-encoded
cornerstone values in one scheme as “noise” to be canceled (via XOR) when
encoding cornerstone values for other schemes.  For example, suppose the
encryptor encodes the Ed448 point first at file offset 0.  The encoder fills
the second and third possible positions for Ed448 with random bits, then XORs
those alternative positions with the actual Ed448 cornerstone value and writes
the result at offset 0.  Now the byte-ranges corresponding to those positions
are fixed and no longer changeable, but can be included as “noise” to be
canceled in writing other cornerstone values.  For example, say now the
encryptor wants to encode the Ed25519 point: it obviously can’t put it at
position 0, but hopefully the second or third alternative position for Ed25519
should be non-overlapping with the already-locked Ed448 point positions.  Say
the second Ed25519 position is still available: the encryptor fills the third
position with random bits (and the first, offset-0 position has already been
filled with random-looking bits), then XORs the contents of the first and third
Ed25519 positions and the true cornerstone value to fill the second Ed25519
position.

OK, so it might look like we’ll always need to reserve a fairly large chunk of
header space for these cornerstone values (e.g., ~448 bytes in the above
example depending on the precise choices of the cornerstone value positions).
But it turns out that’s not true, provided we (a) first reserve space for only
*one* suitably-chosen cornerstone-encoding position per scheme, (b) then lay
out all the hash tables containing symmetric-key blobs for all the schemes, (c)
then lay out and encrypt the file’s contents (or its first substantial-size
chunk of data in the streaming case), (d) encrypt all the session-key blobs of
all schemes into appropriate, already-reserved positions in those schemes’
respective hash tables, (e) fill all remaining unreserved space in this whole
variable-length header region with random bits, and finally (f) encode the
cornerstone values at the very end.  This way, some of the possible positions
for the cornerstone values of each scheme can actually overlap with
symmetric-key blobs generated by the same or other schemes, since all those
random-looking bits will just be treated as pre-existing noise that gets XORed
together with the “true” cornerstone value to be filled into the “last
position” for the corresponding scheme.

Going back to the question of the hash tables for the session-key blobs, note
that although we now have multiple hash tables of different sizes for several
different schemes, all those hash tables can actually overlap, provided the
encoder handles its layout properly.  For example, each scheme’s smallest,
size-1 hash table might always be defined to start immediately after the
offset-0 position for that scheme’s cornerstone value, and successive hash
tables grow from there.  As the encryptor is choosing positions for session-key
blobs in any schemes, it basically just looks for a byte-range in one of that
scheme’s hash tables that hasn’t yet been allocated by that or any other
scheme.

Thus, in the very likely common case of a file being encrypted to only one
recipient under only one scheme (e.g., Ed25519), the file can always be “as
small as possible” and consist of simply (a) the elligator-encoded Ed25519
cornerstone point for DH agreement, (b) the single session-key blob encrypted
using the DH key shared between the encryptor’s cornerstone keypair and the
recipient’s keypair, and (c) the variable-length encrypted file content itself,
all back-to-back in one uniformly-random-looking blob.  If a few but not many
different recipients are to be included in one or a few schemes, the incurred
header overhead grows gracefully with the number of recipients, and no one
without a key can tell how many recipients the file is actually encrypted for.
And the recipient only needs to do at most public-key (or password-hashing)
operation per scheme and O(log N) AEAD trial decryptions per scheme for which
the recipient holds a key.

As a potentially nice little bonus, with this general scheme it’s entirely
possible that an encoder could create a file such that different symmetric-key
pairs actually lead to and enable access to *different* file data chunks,
effectively giving different receivers the ability to “open” different parts -
or different subsets - of encrypted data.  And one receiver will not
necessarily be able to tell either how many other receivers there are or how
much “other” data might be hiding in the file, beyond some upper bound.  Kind
of like Truecrypt partitions, but with any number of hidden partitions
scattered anywhere you like in the volume with different passphrases. :)  This
kind of thing may well reasonably be out-of-scope for what we want OpenPGP to
do, but interesting to think about.

## Deterministic versus randomized padding

The PURB length specification (Section XXX)
prescribes only a set of lengths that PURBs are (and are not) allowed to have,
and not how a particular PURB producer
actually chooses the length of a particular PURB.
In particular, given a cleartext of a given length,
the PURB producer might always produce a PURB of the minimum allowed length,
or might use some random distribution to choose among
many allowed ciphertext lengths large enough to encode the cleartext.

XXX discuss why this may be useful in some contexts,
e.g., to add high-frequency noise to make CRIME-like attacks harder
where an attacker might be able to cause ciphertexts to be generated
so that the "border" between one allowed length and the next
might rapidly leak information 1 bit at a time.

But also discuss the inherent limitations of random padding:
cannot prevent leakage entirely, only slow it down
by effectively imposting a "low-pass filter" on leakage rate.


# Practices for In-Transit PURB Data Formats (Informational)

XXX e.g., discuss techniques for initial negotiation,
and block-by-block or burst-by-burst communication,
in encrypted protocols like [D]TLS etc.

Rate-based streaming applications (e.g., VoIP/video)

PadL: applies to
	- Number of frames per epoch
	- Number of ticks per frame
	- Number of bytes per frame

Thus, max leakage is 6 log2 log2 N per epoch.

UX issues: how often are epochs?
- option 1: let application logic determine dynamically.
	might cause higher leakage unexpectedly to the user
- option 2: just set a minimum epoch length,
	enforcing an upper bound on leakage rate.
- option 3 (paranoia): when application wants to adjust rate,
	show/enable an "Adjust Network Rate?" button,
	which will allow one rate adjustment (new epoch)
	if/when the user presses it.

Bursty interactive applications (e.g., Web browsing)

Whenever new activity is initiated one way or the other, 
a max-rate burst (limited by CC) commences in both directions.
Since CC depends only on network not application secrets,
this should be safe (discuss).
Max-rate activity burst ends in each direction when
application connection is logically idle in both directions
and when the burst length is a PadL.

For application-initiated activity triggers that might depend
on sensitive/vulnerable data (e.g., periodic polls, JavaScript),
idle times are also padded:
e.g., round number of clock ticks of idle time up to the next PadL.
This will delay activity triggers after long idle periods:
e.g., after a 1-minute idle period, up to a second or two delay.

However, for clearly user-initiated activity triggers
whose timing we believe is truly derived from outside the system
and is unlikely to leak sensitive information,
such as when the user clicks a link or presses Enter in a form field,
these might be user-initiated activity triggers
that do not pad the idle time to a PadL.


# Security Considerations

XXX Many.  Examples to be discussed:

- An attacker could use statistical properties of a known weak cipher
(e.g., RC4) to identify that a PURB (or part of one)
was encrypted using that cipher,
even if the attacker cannot outright crack the encryption
(or chooses not to invest the computational power required to do so).
PURB encoding may still make it more difficult and computationally expensive
for an attacker to distinguish files encrypted using a weak cipher, however,
at least as compared to the (trivial) identification of such files
with traditional data formats that provide unencrypted labels
immediately identifying the cipher.

- more...


<reference anchor='GCM' target='http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf'>
 <front>
 <title>Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC</title>
  <author initials='M.' surname='Dworkin' fullname='Morris Dworkin'>
   <organization abbrev='NIST'>National Institute of Standards and Technology</organization>
  </author>
  <date year='2007' month='November'/>
 </front>
 <seriesInfo name='NIST Special Publication' value='800-38D'/>
</reference>

<reference anchor='SHA3' target='http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf'>
 <front>
 <title>SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions</title>
  <author fullname='Information Technology Laboratory'>
   <organization abbrev='NIST'>National Institute of Standards and Technology</organization>
  </author>
  <date year='2015' month='August'/>
 </front>
 <seriesInfo name='FIPS' value='202'/>
</reference>

<reference anchor='MONKEY' target='http://keccak.noekeon.org/KeccakDIAC2012.pdf'>
 <front>
 <title>Permutation-based encryption, authentication and authenticated encryption</title>
  <author initials='G.' surname='Bertoni' fullname='Guido Bertoni'></author>
  <author initials='J.' surname='Daemen' fullname='Joan Daemen'></author>
  <author initials='M.' surname='Peeters' fullname='Micha&euml;l Peeters'></author>
  <author initials='G.' surname='Van Assche' fullname='Gilles Van Assche'></author>
  <date year='2015' month='August'/>
 </front>
 <seriesInfo name='Directions in Authenticated Ciphers' value='2012'/>
</reference>

<reference anchor='METADATA' target='https://drive.google.com/file/d/0BwK1bcoczINteWVwVFN5UWNORW8/view?usp=sharing'>
 <front>
 <title>The information leaked from a gpg encrypted file.</title>
  <author initials='M.' surname='Underwood' fullname='Matthew Underwood'></author>
  <date year='2015' month='October'/>
 </front>
</reference>

{backmatter}
