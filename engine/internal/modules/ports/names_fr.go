package ports

// namesFR are the French names of services whose English name is made of
// common words; product and protocol names (Redis, SSH, LDAP) stay as they
// are, and so does any name missing here.
var namesFR = map[string]string{
	"Remote Desktop (RDP)":                  "Bureau à distance (RDP)",
	"VNC remote desktop":                    "Bureau à distance VNC",
	"Windows file sharing (SMB)":            "Partage de fichiers Windows (SMB)",
	"Windows RPC":                           "RPC Windows",
	"NetBIOS file sharing":                  "Partage de fichiers NetBIOS",
	"RPC portmapper":                        "Portmapper RPC",
	"Docker API":                            "API Docker",
	"Docker API (unencrypted)":              "API Docker (non chiffrée)",
	"Kubernetes API":                        "API Kubernetes",
	"Oracle database":                       "Base de données Oracle",
	"HTTP proxy (Squid)":                    "Proxy HTTP (Squid)",
	"SOCKS proxy":                           "Proxy SOCKS",
	"IMAP (unencrypted)":                    "IMAP (non chiffré)",
	"POP3 (unencrypted)":                    "POP3 (non chiffré)",
	"IMAP over TLS":                         "IMAP sur TLS",
	"POP3 over TLS":                         "POP3 sur TLS",
	"SMTP over TLS":                         "SMTP sur TLS",
	"SMTP submission":                       "SMTP (soumission)",
	"LDAP over TLS":                         "LDAP sur TLS",
	"AMQP over TLS":                         "AMQP sur TLS",
	"WinRM over TLS":                        "WinRM sur TLS",
	"VNC over HTTP":                         "VNC sur HTTP",
	"SIP telephony":                         "Téléphonie SIP",
	"SSH (alternate port)":                  "SSH (port secondaire)",
	"alternate HTTPS server":                "serveur HTTPS secondaire",
	"alternate web server":                  "serveur web secondaire",
	"web application":                       "application web",
	"web application or admin panel":        "application web ou panneau d’administration",
	"web application or dashboard":          "application web ou tableau de bord",
	"web application or development server": "application web ou serveur de développement",
	"web application or monitoring":         "application web ou supervision",
	"web application or notebook":           "application web ou notebook",
	"RabbitMQ management":                   "console d’administration RabbitMQ",
	"ActiveMQ console":                      "console ActiveMQ",
	"GlassFish admin":                       "administration GlassFish",
	"WebSphere admin":                       "administration WebSphere",
	"Zimbra admin":                          "administration Zimbra",
	"Varnish admin":                         "administration Varnish",
	"Java debugger":                         "débogueur Java",
	"Android debug bridge":                  "pont de débogage Android (ADB)",
	"Active Directory global catalog":       "catalogue global Active Directory",
	"SQL Server browser":                    "SQL Server Browser",
	"L2TP VPN":                              "VPN L2TP",
	"PPTP VPN":                              "VPN PPTP",
	"etcd peer":                             "etcd (communication entre nœuds)",
	"Cassandra cluster":                     "cluster Cassandra",
	"Elasticsearch cluster":                 "cluster Elasticsearch",
	"AFP file sharing":                      "partage de fichiers AFP",
	"printer (JetDirect)":                   "imprimante (JetDirect)",
	"printer (LPD)":                         "imprimante (LPD)",
	"printing (IPP)":                        "impression (IPP)",
	"TR-069 router management":              "gestion de routeur TR-069",
	"MongoDB web":                           "interface web MongoDB",
	"Spark history":                         "historique Spark",
	"Erlang port mapper":                    "Erlang Port Mapper",
	"cPanel webmail":                        "webmail cPanel",
	"SAP router":                            "routeur SAP",
}

// nameFR is a service's French name.
func nameFR(name string) string {
	if fr, ok := namesFR[name]; ok {
		return fr
	}
	return name
}
