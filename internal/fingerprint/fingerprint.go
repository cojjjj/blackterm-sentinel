package fingerprint

import "fmt"

var known = map[uint16]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
	80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS",
	143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
	465: "SMTPS", 587: "SMTP", 636: "LDAPS", 993: "IMAPS",
	995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS",
	2375: "Docker", 3000: "HTTP", 3306: "MySQL", 3389: "RDP",
	5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8000: "HTTP",
	8080: "HTTP", 8443: "HTTPS", 8888: "HTTP", 9200: "Elasticsearch",
	27017: "MongoDB",
}

func ServiceName(port uint16) string {
	if name, ok := known[port]; ok {
		return name
	}
	return fmt.Sprintf("tcp/%d", port)
}
