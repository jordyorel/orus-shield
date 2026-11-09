package ports

import "github.com/jordyorel/orus-shield/engine/internal/finding"

// family groups services that carry the same risk and the same advice.
type family struct {
	checkID  string
	severity finding.Severity
	// why explains the risk to a non-specialist.
	why string
	fix []string
}

// service is one TCP port we look for.
type service struct {
	port   int
	name   string
	family family
	// severity overrides the family's when set.
	severity finding.Severity
}

func (s service) sev() finding.Severity {
	if s.severity != "" {
		return s.severity
	}
	return s.family.severity
}

var (
	remoteDesktop = family{
		checkID:  "port-remote-desktop-exposed",
		severity: finding.SeverityCritical,
		why:      "Remote desktop services are one of the main entry points of ransomware: attackers try passwords against them automatically, all day long.",
		fix: []string{
			"Close this port to the internet in the firewall or the hosting panel.",
			"Reach the machine through a VPN instead.",
			"Until then, use long unique passwords and lock accounts after failed attempts.",
		},
	}
	windowsSharing = family{
		checkID:  "port-windows-sharing-exposed",
		severity: finding.SeverityCritical,
		why:      "Windows file sharing and RPC were never meant for the internet. Worms such as WannaCry spread through them without any password.",
		fix:      []string{"Block this port in the firewall: these services must stay on the internal network."},
	}
	cleartextAdmin = family{
		checkID:  "port-cleartext-admin-exposed",
		severity: finding.SeverityCritical,
		why:      "This administration protocol sends passwords and commands unencrypted: anyone on the path can read them.",
		fix:      []string{"Disable the service and administer the machine over SSH instead."},
	}
	orchestration = family{
		checkID:  "port-orchestration-api-exposed",
		severity: finding.SeverityCritical,
		why:      "Container and cluster control APIs give full control of the server to whoever can reach them, often without any password.",
		fix: []string{
			"Close this port to the internet; only administrators' networks should reach it.",
			"Require authentication and TLS client certificates on the API.",
		},
	}
	database = family{
		checkID:  "port-database-exposed",
		severity: finding.SeverityHigh,
		why:      "A database should only be reachable by the application that uses it. Several databases (Redis, MongoDB, Elasticsearch, Memcached) accept connections without a password by default: the whole database can then be copied or erased in one connection.",
		fix: []string{
			"Make the database listen on localhost or a private network only.",
			"Block this port in the firewall.",
			"Check that authentication is enabled.",
		},
	}
	fileSharing = family{
		checkID:  "port-file-sharing-exposed",
		severity: finding.SeverityHigh,
		why:      "File transfer and sharing services expose files to the internet, and several of them (FTP, NFS, rsync) send passwords or data unencrypted or trust the network instead of asking for a password.",
		fix: []string{
			"Close this port if the service is not needed from the internet.",
			"Replace FTP with SFTP (file transfer over SSH).",
		},
	}
	directory = family{
		checkID:  "port-directory-exposed",
		severity: finding.SeverityHigh,
		why:      "A directory server (LDAP) holds user accounts and often answers questions about them; exposed, it helps attackers list users and guess passwords.",
		fix:      []string{"Block this port in the firewall; directory services belong on the internal network."},
	}
	broker = family{
		checkID:  "port-message-broker-exposed",
		severity: finding.SeverityHigh,
		why:      "Message brokers connect internal applications. Exposed, they can let outsiders read or inject messages, often with default credentials.",
		fix: []string{
			"Close this port to the internet.",
			"Require authentication and change default credentials.",
		},
	}
	proxy = family{
		checkID:  "port-proxy-exposed",
		severity: finding.SeverityHigh,
		why:      "An open proxy lets anyone relay traffic through your server: attackers use them to hide their origin, and your IP then gets blocklisted.",
		fix:      []string{"Close this port or restrict the proxy to your own users."},
	}
	adminWeb = family{
		checkID:  "port-admin-web-exposed",
		severity: finding.SeverityMedium,
		why:      "Alternate web ports often host admin panels, dashboards or development servers that were never meant to be public.",
		fix: []string{
			"Check what answers on this port.",
			"If it is an admin or development tool, close the port or put it behind a VPN or a login.",
		},
	}
	voip = family{
		checkID:  "port-voip-exposed",
		severity: finding.SeverityMedium,
		why:      "Exposed telephony (SIP) servers are scanned constantly for weak accounts, which attackers use to place expensive calls at your cost.",
		fix:      []string{"Restrict this port to your telephony provider's addresses."},
	}
	cleartextMail = family{
		checkID:  "port-cleartext-mail-exposed",
		severity: finding.SeverityLow,
		why:      "This mail port accepts unencrypted connections, so mailbox passwords can travel in clear text.",
		fix:      []string{"Use the encrypted ports (993 for IMAP, 995 for POP3) and close the unencrypted ones."},
	}
	ssh = family{
		checkID:  "port-ssh-exposed",
		severity: finding.SeverityLow,
		why:      "SSH is the normal way to administer a server, but it is attacked continuously by automated password guessing.",
		fix: []string{
			"Allow key-based login only and disable password login.",
			"If possible, restrict the port to your own addresses or a VPN.",
		},
	}
)

// catalog is the list of ports checked. Web ports 80 and 443 are not here:
// they are expected to be open, and the TLS module covers 443.
var catalog = []service{
	{port: 3389, name: "Remote Desktop (RDP)", family: remoteDesktop},
	{port: 5900, name: "VNC remote desktop", family: remoteDesktop},
	{port: 5901, name: "VNC remote desktop", family: remoteDesktop},

	{port: 135, name: "Windows RPC", family: windowsSharing},
	{port: 139, name: "NetBIOS file sharing", family: windowsSharing},
	{port: 445, name: "Windows file sharing (SMB)", family: windowsSharing},

	{port: 23, name: "Telnet", family: cleartextAdmin},

	{port: 2375, name: "Docker API (unencrypted)", family: orchestration},
	{port: 2376, name: "Docker API", family: orchestration, severity: finding.SeverityHigh},
	{port: 2379, name: "etcd", family: orchestration},
	{port: 6443, name: "Kubernetes API", family: orchestration, severity: finding.SeverityHigh},
	{port: 10250, name: "Kubernetes kubelet", family: orchestration},

	{port: 1433, name: "Microsoft SQL Server", family: database},
	{port: 1521, name: "Oracle database", family: database},
	{port: 3306, name: "MySQL / MariaDB", family: database},
	{port: 5432, name: "PostgreSQL", family: database},
	{port: 5984, name: "CouchDB", family: database},
	{port: 6379, name: "Redis", family: database},
	{port: 9042, name: "Cassandra", family: database},
	{port: 9200, name: "Elasticsearch", family: database},
	{port: 11211, name: "Memcached", family: database},
	{port: 27017, name: "MongoDB", family: database},

	{port: 21, name: "FTP", family: fileSharing},
	{port: 111, name: "RPC portmapper", family: fileSharing, severity: finding.SeverityMedium},
	{port: 873, name: "rsync", family: fileSharing},
	{port: 2049, name: "NFS", family: fileSharing},

	{port: 389, name: "LDAP", family: directory},

	{port: 1883, name: "MQTT", family: broker},
	{port: 5672, name: "RabbitMQ (AMQP)", family: broker},
	{port: 9092, name: "Kafka", family: broker},

	{port: 1080, name: "SOCKS proxy", family: proxy},
	{port: 3128, name: "HTTP proxy (Squid)", family: proxy},

	{port: 2082, name: "cPanel", family: adminWeb},
	{port: 2083, name: "cPanel", family: adminWeb},
	{port: 3000, name: "web application or dashboard", family: adminWeb},
	{port: 5000, name: "web application or development server", family: adminWeb},
	{port: 5601, name: "Kibana", family: adminWeb},
	{port: 8000, name: "web application or development server", family: adminWeb},
	{port: 8080, name: "alternate web server", family: adminWeb},
	{port: 8443, name: "alternate HTTPS server", family: adminWeb, severity: finding.SeverityLow},
	{port: 8888, name: "web application or notebook", family: adminWeb},
	{port: 9000, name: "web application or admin panel", family: adminWeb},
	{port: 9090, name: "web application or monitoring", family: adminWeb},
	{port: 10000, name: "Webmin", family: adminWeb},
	{port: 15672, name: "RabbitMQ management", family: adminWeb},

	{port: 5060, name: "SIP telephony", family: voip},

	{port: 110, name: "POP3 (unencrypted)", family: cleartextMail},
	{port: 143, name: "IMAP (unencrypted)", family: cleartextMail},

	{port: 22, name: "SSH", family: ssh},
	{port: 2222, name: "SSH (alternate port)", family: ssh},
}
