pkg = dns
source = $(pkg)/DNSRecord.java $(pkg)/DNSCache.java $(pkg)/DNSZone.java $(pkg)/DNSMessage.java $(pkg)/DNSServer.java
jc = javac

classfiles = $(source:.java=.class)

all: $(classfiles)

%.class: %.java
	$(jc) $<

clean:
	rm -f $(pkg)/*.class
