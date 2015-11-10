# To format this Internet-Draft you'll need to install:
#
# - xml2rfc: http://xml2rfc.ietf.org/
# - mmark: https://github.com/miekg/mmark

all: purb.txt

%.xml: %.md
	mmark -xml2 -page $*.md >$*.xml

%.txt: %.xml
	xml2rfc --text $*.xml

