# Collective Edwards-Curve Digital Signature Algorithm

This folder holds the RFC draft about collective Edwards-curve digital signature
algorithm. For more background information, check out the original paper
["Keeping Authorities "Honest or Bust" with Decentralized Witness
Cosigning"](https://arxiv.org/abs/1503.08768) published at IEEE S&P '16.

To participate in the discussion, please see the following mailing list threads:

- [Crypto Forum Research Group](https://www.ietf.org/mail-archive/web/cfrg/current/msg09205.html) (main thread)
- [curves@moderncrypto](https://moderncrypto.org/mail-archive/curves/2017/000927.html)

## Building

To compile the `cosi.md` file into an html or txt file, you first need to install:

+ xml2rfc: http://xml2rfc.ietf.org/
+ mmark: https://github.com/miekg/mmark

After that, a simple `make` will produce an HTML version of the draft.

## Contributions

All contributions are welcome. However, to keep the discussion bundled on the 
[CFRG mailing list](https://datatracker.ietf.org/group/cfrg/about/),
please propose your changes there and only then send a PR on GitHub.

