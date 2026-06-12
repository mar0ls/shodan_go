SHODAN ?= ./shodan-go
QUERY ?= apache country:PL
DOMAIN ?= example.com
OUT ?= results.json

.PHONY: shodan-count shodan-search shodan-dns shodan-dns-all shodan-myip

shodan-count:
	$(SHODAN) count "$(QUERY)"

shodan-search:
	$(SHODAN) search --all --out "$(OUT)" "$(QUERY)"

shodan-dns:
	$(SHODAN) dns "$(DOMAIN)"

shodan-dns-all:
	$(SHODAN) dns --all-records "$(DOMAIN)"

shodan-myip:
	$(SHODAN) myip
