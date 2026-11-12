package ports

import (
	"slices"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
)

// The deep profile ("Approfondi") scans more than the catalog: every
// well-known port (1 to 1024, IANA's system range) and a selection of
// registered ports commonly found exposed. We do not use Nmap's "top 1000"
// list: it comes from Nmap's own scan statistics, whose license (NPSL) has
// not been reviewed for a commercial service (see CLAUDE.md). Port numbers
// and their IANA names are public registry data.

// otherService is the family of an open port outside the catalog: no
// specific advice, but the customer should know it is reachable.
var otherService = family{
	checkID:  "port-other-service-exposed",
	severity: finding.SeverityLow,
	why:      "A network service is reachable from the internet on this port. Every exposed service is something attackers can probe; it should be there on purpose.",
	fix: []string{
		"Check what this service is and whether it must be reachable from the internet.",
		"If not, close the port in the firewall or make the service listen on a private network only.",
		"If it must stay open, keep its software up to date.",
	},
}

// registered are ports above 1024 commonly exposed by mistake, beyond the
// catalog. Names from the IANA registry or the software's documentation.
var registered = map[int]string{
	1194: "OpenVPN", 1352: "Lotus Notes", 1434: "SQL Server browser", 1701: "L2TP VPN",
	1723: "PPTP VPN", 1900: "UPnP (SSDP)", 2000: "Cisco SCCP", 2001: "web application",
	2049: "NFS", 2086: "WHM", 2087: "WHM", 2095: "cPanel webmail", 2096: "cPanel webmail",
	2181: "ZooKeeper", 2380: "etcd peer", 2483: "Oracle database", 2484: "Oracle database",
	3000: "web application or dashboard", 3001: "web application", 3260: "iSCSI",
	3268: "Active Directory global catalog", 3269: "Active Directory global catalog",
	3299: "SAP router", 3690: "Subversion", 4000: "web application", 4369: "Erlang port mapper",
	4443: "alternate HTTPS server", 4505: "SaltStack", 4506: "SaltStack", 4848: "GlassFish admin",
	5000: "web application or development server", 5001: "web application", 5005: "Java debugger",
	5222: "XMPP", 5269: "XMPP", 5353: "mDNS", 5555: "Android debug bridge", 5601: "Kibana",
	5671: "AMQP over TLS", 5800: "VNC over HTTP", 5938: "TeamViewer", 5985: "WinRM", 5986: "WinRM over TLS",
	6000: "X11", 6001: "X11", 6066: "Spark", 6080: "noVNC", 6082: "Varnish admin",
	6666: "IRC", 6667: "IRC", 7000: "Cassandra cluster", 7001: "WebLogic", 7002: "WebLogic",
	7070: "web application", 7071: "Zimbra admin", 7077: "Spark", 7443: "alternate HTTPS server",
	7474: "Neo4j", 7547: "TR-069 router management", 8001: "web application", 8008: "alternate web server",
	8009: "Tomcat AJP", 8010: "web application", 8020: "Hadoop", 8081: "alternate web server",
	8082: "alternate web server", 8083: "alternate web server", 8086: "InfluxDB", 8088: "Hadoop YARN",
	8089: "Splunk", 8090: "web application", 8091: "Couchbase", 8098: "Riak", 8161: "ActiveMQ console",
	8180: "alternate web server", 8181: "alternate web server", 8200: "Vault", 8291: "MikroTik Winbox",
	8300: "Consul", 8384: "Syncthing", 8500: "Consul", 8529: "ArangoDB", 8554: "RTSP",
	8649: "Ganglia", 8686: "JMX", 8761: "Eureka", 8800: "web application", 8834: "Nessus",
	8880: "alternate web server", 8983: "Solr", 9001: "Supervisor", 9002: "web application",
	9043: "WebSphere admin", 9060: "WebSphere admin", 9100: "printer (JetDirect)", 9160: "Cassandra Thrift",
	9300: "Elasticsearch cluster", 9418: "Git", 9443: "alternate HTTPS server", 9999: "web application",
	10001: "web application", 10443: "alternate HTTPS server", 11211: "Memcached", 15672: "RabbitMQ management",
	16010: "HBase", 18080: "Spark history", 20000: "Usermin", 25565: "Minecraft", 27018: "MongoDB",
	28017: "MongoDB web", 32400: "Plex", 50000: "SAP", 50070: "Hadoop NameNode",
}

// wellKnown names a few system ports, for the deep scan's reports when the
// service does not identify itself.
var wellKnown = map[int]string{
	7: "Echo", 13: "Daytime", 19: "Chargen", 25: "SMTP", 37: "Time", 43: "WHOIS", 53: "DNS",
	69: "TFTP", 79: "Finger", 88: "Kerberos", 102: "Siemens S7", 113: "Ident", 119: "NNTP",
	123: "NTP", 161: "SNMP", 179: "BGP", 443: "HTTPS", 465: "SMTP over TLS", 502: "Modbus",
	512: "rexec", 513: "rlogin", 514: "rsh", 515: "printer (LPD)", 548: "AFP file sharing",
	554: "RTSP", 587: "SMTP submission", 631: "printing (IPP)", 636: "LDAP over TLS",
	993: "IMAP over TLS", 995: "POP3 over TLS",
}

// webExpected are ports expected open on a website, never reported.
var webExpected = []int{80, 443}

// deepServices is the catalog plus every port of the deep range not in it.
func deepServices() []service {
	out := slices.Clone(catalog)
	in := make(map[int]bool, len(catalog))
	for _, s := range catalog {
		in[s.port] = true
	}
	add := func(port int, name string) {
		if in[port] || slices.Contains(webExpected, port) {
			return
		}
		in[port] = true
		if name == "" {
			name = "unknown service"
		}
		out = append(out, service{port: port, name: name, family: otherService})
	}
	for p := 1; p <= 1024; p++ {
		add(p, wellKnown[p])
	}
	ports := make([]int, 0, len(registered))
	for p := range registered {
		ports = append(ports, p)
	}
	slices.Sort(ports)
	for _, p := range ports {
		add(p, registered[p])
	}
	return out
}
