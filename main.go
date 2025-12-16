package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
	"github.com/miekg/dns"
)

type LocationInfo struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	City     string `json:"city,omitempty"`
	Region   string `json:"region,omitempty"`
	Country  string `json:"country,omitempty"`
	Loc      string `json:"loc,omitempty"` // Latitude,Longitude
	Org      string `json:"org,omitempty"`
	Postal   string `json:"postal,omitempty"`
	Timezone string `json:"timezone,omitempty"`
	Anycast  bool   `json:"anycast,omitempty"`
}

type SubdomainResult struct {
	Subdomain   string                  `json:"subdomain"`
	IPAddresses []string                `json:"ip_addresses"`
	IPLocations map[string]LocationInfo `json:"ip_locations,omitempty"` // IP -> LocationInfo
	StatusCode  int                     `json:"status_code"`
	IsAlive     bool                    `json:"is_alive"`
	Environment string                  `json:"environment"` // prod, staging, dev, etc.
}

type Discovery struct {
	domain     string
	wordlist   []string
	results    []SubdomainResult
	mu         sync.Mutex
	workers    int
	timeout    time.Duration
	resolver   *net.Resolver
	seen       map[string]bool
	expandSize int
}

func NewDiscovery(domain string, workers int, timeout time.Duration, expandSize int) *Discovery {
	return &Discovery{
		domain:     domain,
		workers:    workers,
		timeout:    timeout,
		results:    make([]SubdomainResult, 0),
		resolver:   &net.Resolver{},
		seen:       make(map[string]bool),
		expandSize: expandSize,
	}
}

// DNS-based subdomain enumeration
func (d *Discovery) dnsEnumeration(ctx context.Context) {
	jobs := make(chan string, len(d.wordlist))
	var wg sync.WaitGroup

	// Worker pool
	for i := 0; i < d.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for subdomain := range jobs {
				d.checkSubdomain(ctx, subdomain)
			}
		}()
	}

	// Send jobs
	for _, word := range d.wordlist {
		subdomain := fmt.Sprintf("%s.%s", word, d.domain)
		jobs <- subdomain
	}
	close(jobs)
	wg.Wait()
}

func (d *Discovery) checkSubdomain(ctx context.Context, subdomain string) {
	// Normalize and dedupe
	subdomain = strings.TrimSpace(subdomain)
	subdomain = strings.TrimPrefix(subdomain, "*.")
	if !strings.HasSuffix(subdomain, d.domain) {
		return
	}
	d.mu.Lock()
	if d.seen[subdomain] {
		d.mu.Unlock()
		return
	}
	d.seen[subdomain] = true
	d.mu.Unlock()
	// DNS resolution with timeout
	resolveCtx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	ips, err := d.resolver.LookupHost(resolveCtx, subdomain)
	if err != nil {
		return // Subdomain doesn't resolve
	}

	result := SubdomainResult{
		Subdomain:   subdomain,
		IPAddresses: ips,
		IPLocations: make(map[string]LocationInfo),
		IsAlive:     false,
		Environment: d.detectEnvironment(subdomain),
	}

	// Fetch location information for each IP
	for _, ip := range ips {
		if locInfo := d.fetchIPLocation(ctx, ip); locInfo != nil {
			result.IPLocations[ip] = *locInfo
		}
	}

	// HTTP probe to check if alive
	if d.probeHTTP(subdomain, &result) {
		result.IsAlive = true
	}

	d.mu.Lock()
	d.results = append(d.results, result)
	d.mu.Unlock()

	fmt.Printf("[+] Found: %s -> %v (HTTP: %d) [%s]\n",
		subdomain, ips, result.StatusCode, result.Environment)
}

func (d *Discovery) probeHTTP(subdomain string, result *SubdomainResult) bool {
	client := &http.Client{
		Timeout: d.timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	// Try HTTPS first
	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s", scheme, subdomain)
		resp, err := client.Get(url)
		if err == nil {
			result.StatusCode = resp.StatusCode
			resp.Body.Close()
			return true
		}
	}
	return false
}

func (d *Discovery) fetchIPLocation(ctx context.Context, ip string) *LocationInfo {
	// Use ipinfo.io free API (no auth required for basic usage)
	url := fmt.Sprintf("https://ipinfo.io/%s/json", ip)

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil // Silently fail if location lookup fails
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var locInfo LocationInfo
	if err := json.NewDecoder(resp.Body).Decode(&locInfo); err != nil {
		return nil
	}

	// Ensure IP is set (some APIs don't return it)
	if locInfo.IP == "" {
		locInfo.IP = ip
	}

	return &locInfo
}

func (d *Discovery) detectEnvironment(subdomain string) string {
	lower := strings.ToLower(subdomain)

	envKeywords := map[string][]string{
		"production":  {"prod", "www", "api", "app"},
		"staging":     {"staging", "stage", "stg", "uat"},
		"development": {"dev", "develop", "test"},
		"internal":    {"internal", "corp", "vpn"},
		"legacy":      {"old", "legacy", "deprecated", "archive"},
	}

	for env, keywords := range envKeywords {
		for _, keyword := range keywords {
			if strings.Contains(lower, keyword) {
				return env
			}
		}
	}
	return "unknown"
}

// Certificate Transparency logs enumeration
func (d *Discovery) ctLogsEnumeration(ctx context.Context) error {
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", d.domain)

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to query crt.sh: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	var entries []map[string]interface{}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&entries); err != nil {
		return fmt.Errorf("failed to decode JSON response: %w", err)
	}

	if len(entries) == 0 {
		return nil // No entries found, but not an error
	}

	foundCount := 0
	for _, e := range entries {
		if nv, ok := e["name_value"].(string); ok {
			// name_value can contain multiple names separated by newlines
			for _, sd := range strings.Split(nv, "\n") {
				sd = strings.TrimSpace(sd)
				if sd == "" {
					continue
				}
				// Handle wildcard certificates
				sd = strings.TrimPrefix(sd, "*.")
				// Remove trailing dot if present
				sd = strings.TrimSuffix(sd, ".")
				if sd == "" {
					continue
				}
				// Only process subdomains of our target domain
				if strings.HasSuffix(sd, d.domain) || sd == d.domain {
					d.checkSubdomain(ctx, sd)
					foundCount++
				}
			}
		}
	}

	if foundCount > 0 {
		fmt.Printf("[+] CT logs: Found %d unique subdomains\n", foundCount)
	}
	return nil
}

// Zone transfer attempt (usually fails but worth trying)
func (d *Discovery) attemptZoneTransfer() {
	nameservers, err := net.LookupNS(d.domain)
	if err != nil {
		return // No nameservers found, silently skip
	}

	var successCount int

	for _, ns := range nameservers {
		nsHost := strings.TrimSuffix(ns.Host, ".")
		ips, err := net.LookupIP(nsHost)
		if err != nil || len(ips) == 0 {
			continue
		}
		// Try each IP for AXFR
		for _, ip := range ips {
			addr := net.JoinHostPort(ip.String(), "53")
			m := new(dns.Msg)
			m.SetAxfr(d.domain + ".")
			t := new(dns.Transfer)
			ch, err := t.In(m, addr)
			if err != nil {
				// No AXFR or refused - silently continue
				continue
			}

			// Only print success message if we actually got a response
			hasRecords := false
			recordsProcessed := 0
			for en := range ch {
				if en.Error != nil {
					// If we get an error during transfer, it wasn't successful
					break
				}
				for _, rr := range en.RR {
					hasRecords = true
					// We can extract hostnames and add as discovered subdomains
					if rr.Header().Rrtype == dns.TypeA || rr.Header().Rrtype == dns.TypeCNAME || rr.Header().Rrtype == dns.TypeNS || rr.Header().Rrtype == dns.TypeMX {
						name := strings.TrimSuffix(rr.Header().Name, ".")
						if strings.HasSuffix(name, d.domain) || name == d.domain {
							d.checkSubdomain(context.Background(), name)
							recordsProcessed++
						}
					}
				}
			}

			if hasRecords && recordsProcessed > 0 {
				successCount++
				fmt.Printf("[!] Zone transfer succeeded from %s (%s) - processed %d records\n", nsHost, ip.String(), recordsProcessed)
			}
		}
	}

	if successCount == 0 {
		// Only print if we actually tried and failed, not if we couldn't find nameservers
		// This avoids misleading output when AXFR simply isn't available (which is normal)
	}
}

func (d *Discovery) loadWordlist(filename string) error {
	if filename == "" {
		defaultList := getDefaultWordlist()
		if d.expandSize > 0 {
			d.wordlist = expandWordlist(defaultList, d.expandSize)
		} else {
			d.wordlist = defaultList
		}
		return nil
	}
	file, err := os.Open(filename)
	if err != nil {
		// Use default wordlist if file not found
		d.wordlist = getDefaultWordlist()
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			d.wordlist = append(d.wordlist, word)
		}
	}
	return scanner.Err()
}

// expandWordlist expands a base list with numeric suffixes to reach a specified size
func expandWordlist(base []string, size int) []string {
	if size <= len(base) {
		return base
	}
	out := make([]string, 0, size)
	out = append(out, base...)
	i := 1
	for len(out) < size {
		for _, b := range base {
			if len(out) >= size {
				break
			}
			out = append(out, fmt.Sprintf("%s%d", b, i))
		}
		i++
	}
	return out
}

func getDefaultWordlist() []string {
	return []string{
		// Common infrastructure
		"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
		"ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
		"ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
		"mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
		"docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
		"web", "media", "email", "images", "img", "www1", "intranet", "portal", "video",
		"sip", "dns2", "api", "cdn", "stats", "dns1", "ns4", "www3", "dns", "search",
		"staging", "stage", "stg", "prod", "production", "uat", "sandbox", "internal",
		"app", "apps", "gateway", "gw", "monitor", "monitoring", "dashboard",

		// Cloud & hosting
		"cloud", "aws", "azure", "gcp", "s3", "storage", "bucket", "cdn1", "cdn2",
		"origin", "origin-www", "edge", "edge-www", "cache", "assets", "static-assets",
		"hosting", "server", "server1", "server2", "web1", "web2", "web3", "db", "db1",

		// Cloud VMs & Instances
		"vm", "vm1", "vm2", "vm3", "instance", "instance1", "instance2", "compute",
		"compute1", "compute2", "ec2", "ec2-", "gce", "gce-", "azure-vm", "vm-",
		"node", "node1", "node2", "node3", "worker", "worker1", "worker2",
		"master-node", "worker-node", "compute-node", "app-instance", "web-instance",
		"db-instance", "bastion-host", "jump-host", "jumpbox", "bastion1", "bastion2",
		"nat-instance", "nat1", "nat2", "appvm", "appvm1", "appvm2", "webvm", "webvm1",

		// Load Balancers
		"alb", "alb1", "alb2", "elb", "elb1", "elb2", "nlb", "nlb1", "nlb2",
		"glb", "glb1", "glb2", "clb", "clb1", "clb2", "lb1", "lb2", "lb3",
		"loadbalancer1", "loadbalancer2", "load-balancer1", "load-balancer2",
		"internal-lb", "external-lb", "public-lb", "private-lb", "internet-lb",
		"application-lb", "network-lb", "classic-lb", "azure-lb", "azure-lb1",
		"gcp-lb", "gcp-lb1", "traefik", "haproxy", "haproxy1", "haproxy2",

		// Cloud Storage Buckets
		"s3-bucket", "s3-", "bucket1", "bucket2", "bucket3", "storage-bucket",
		"gcs-bucket", "gcs-", "azure-blob", "azure-blob-", "blob", "blob1", "blob2",
		"blob-storage", "object-storage", "cold-storage", "archive-storage",
		"backup-bucket", "backup-s3", "logs-bucket", "logs-s3", "assets-bucket",
		"media-bucket", "static-bucket", "public-bucket", "private-bucket",
		"internal-bucket", "external-bucket", "data-bucket", "temp-bucket",
		"s3-prod", "s3-staging", "s3-dev", "bucket-prod", "bucket-staging",
		"wasabi", "wasabi-", "backblaze", "backblaze-", "digitalocean-spaces",

		// Cloud Gateways
		"gateway1", "gateway2", "gateway3", "api-gateway", "api-gateway1",
		"apigw", "apigw1", "apigw2", "nat-gateway", "nat-gw", "nat-gw1", "nat-gw2",
		"transit-gateway", "tgw", "tgw1", "internet-gateway", "igw", "igw1",
		"vpn-gateway", "vpn-gw", "vpn-gw1", "vpn-gw2", "aws-api-gateway",
		"azure-api-gateway", "gcp-api-gateway", "azure-application-gateway",
		"app-gateway", "app-gateway1", "app-gateway2", "service-gateway",
		"private-gateway", "public-gateway", "cloud-gateway", "mesh-gateway",
		"istio-gateway", "kong-gateway", "kong", "tyk-gateway", "tyk",

		// Services & APIs
		"api1", "api2", "api3", "rest", "graphql", "v1", "v2", "v3", "version", "versions",
		"service", "services", "microservice", "backend", "frontend", "client", "clients",
		"proxy", "lb", "loadbalancer", "load-balancer", "nginx", "apache", "tomcat",

		// Development & testing
		"test1", "test2", "testing", "qa", "quality", "preprod", "pre-prod", "preproduction",
		"rc", "release", "release-candidate", "hotfix", "patch", "build", "builder",
		"ci", "cd", "jenkins", "git", "gitlab", "github", "bitbucket", "svn",

		// Business & regions
		"us", "uk", "eu", "eu-west", "eu-east", "us-east", "us-west", "ap", "asia",
		"apac", "emea", "na", "sa", "africa", "oceania", "japan", "china", "india",
		"emea-west", "emea-east", "global", "local", "regional",

		// Applications
		"account", "accounts", "auth", "authentication", "login", "signin", "signup",
		"register", "registration", "profile", "profiles", "user", "users", "member",
		"members", "customer", "customers", "client-portal", "admin-portal",

		// Content & media
		"cdn-", "cdn1-", "cdn2-", "cdn3-", "assets1", "assets2", "files", "file",
		"download", "downloads", "upload", "uploads", "content", "cdn-content",
		"stream", "streaming", "player", "live", "live1", "vod", "media1", "media2",

		// Communication
		"chat", "messaging", "message", "im", "xmpp", "irc", "slack", "teams",
		"conference", "meeting", "webinar", "voice", "telephony", "pbx",

		// Infrastructure services
		"ldap", "ad", "active-directory", "directory", "radius", "kerberos",
		"ntp", "time", "syslog", "log", "logs", "logging", "log1", "log2",
		"backup", "backups", "backup1", "backup2", "archive", "archives",

		// Database & data
		"db2", "db3", "database", "mongo", "mongodb", "redis", "cache1", "cache2",
		"elasticsearch", "es", "kibana", "logstash", "influxdb", "postgres", "mysql1",
		"mssql", "oracle", "cassandra", "rabbitmq", "kafka", "zookeeper",

		// Monitoring & ops
		"monitoring1", "monitoring2", "prometheus", "grafana", "zabbix", "nagios",
		"datadog", "newrelic", "splunk", "elk", "graylog", "loki", "alertmanager",
		"health", "healthcheck", "ping", "status", "metrics", "telemetry",

		// Security
		"security", "secure1", "secure2", "ssl", "tls", "cert", "certificate",
		"vpn1", "vpn2", "vpn3", "proxy1", "proxy2", "firewall", "fw", "ids", "ips",
		"waf", "ddos", "shield", "guard", "shield1",

		// E-commerce
		"shop1", "shop2", "store", "stores", "cart", "checkout", "payment", "payments",
		"pay", "billing", "invoice", "invoices", "order", "orders", "commerce",

		// Documentation & help
		"docs1", "documentation", "help", "helpdesk", "support1", "ticket", "tickets",
		"faq", "knowledge", "kb", "wiki1", "wiki2", "guide", "guides",

		// Collaboration
		"collab", "collaboration", "share", "sharepoint", "onedrive", "drive",
		"file-share", "fileshare", "sync", "syncing", "dropbox", "box",

		// Marketing
		"marketing", "campaign", "campaigns", "promo", "promotion", "ads", "advertising",
		"ad", "adserver", "tracking", "analytics", "ga", "gtm", "pixel", "pixels",

		// Mobile & apps
		"mobile1", "mobile2", "m1", "m2", "ios", "android", "app1", "app2", "app3",
		"ios-app", "android-app", "native", "hybrid", "pwa",

		// Legacy & old
		"old1", "old2", "legacy1", "legacy2", "archive1", "archive2", "deprecated",
		"retired", "sunset", "v1-legacy", "v2-legacy", "classic", "new-", "new1",

		// Generic numbers
		"01", "02", "03", "04", "05", "1", "2", "3", "4", "5", "10", "11", "12",
		"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "alpha", "beta", "gamma",

		// Common prefixes
		"pub", "public", "private", "priv", "internal1", "internal2", "external",
		"ext", "public-api", "private-api", "internal-api", "external-api",

		// Mail & messaging infrastructure
		"mail1", "mail3", "mail4", "mailserver", "exchange", "owa", "outlook",
		"imap1", "imap2", "pop1", "pop2", "smtp1", "smtp2", "smtp3", "mx1", "mx2",
		"mx3", "mailgateway", "mailrelay", "antispam", "antivirus",

		// DNS & networking
		"ns5", "ns6", "ns7", "ns8", "dns3", "dns4", "dns5", "dns6",
		"router", "switch", "firewall1", "firewall2", "gateway1", "gateway2",

		// Container & orchestration
		"k8s", "kubernetes", "kube", "docker", "registry", "registry1", "registry2",
		"swarm", "nomad", "consul", "etcd", "vault", "terraform",

		// Storage & backup
		"storage1", "storage2", "s3-", "s3-", "bucket1", "bucket2", "backup3",
		"backup4", "snapshot", "snapshots", "mirror", "mirror1", "replica",

		// Search & indexing
		"search1", "search2", "search3", "solr", "lucene", "sphinx", "algolia",

		// CMS & platforms
		"wordpress", "wp", "wp-admin", "wp-content", "wp-includes", "drupal",
		"joomla", "magento", "prestashop", "opencart", "ghost", "jekyll",

		// Version control & CI/CD
		"git1", "git2", "gitlab1", "github1", "bitbucket1", "svn1", "jenkins1",
		"jenkins2", "teamcity", "bamboo", "circleci", "travis", "codeship",

		// Collaboration tools
		"confluence", "jira", "jira1", "redmine", "trello", "asana", "basecamp",
		"mattermost", "rocketchat", "discord", "mumble", "ventrilo",

		// Business applications
		"crm", "crm1", "salesforce", "hubspot", "zendesk", "zendesk1", "freshdesk",
		"servicenow", "servicenow1", "sap", "sap1", "oracle1", "oracle2",

		// Communication platforms
		"jabber", "jitsi", "bigbluebutton", "zoom", "gotomeeting", "webex",

		// Content delivery
		"origin-", "edge-", "cache1", "cache2", "cache3", "cdn-origin",
		"cdn-edge", "fastly", "cloudflare", "akamai", "maxcdn",

		// Development environments
		"dev1", "dev2", "dev3", "develop1", "develop2", "development1", "development2",
		"devel", "devel1", "devel2", "tst", "tst1", "tst2", "test3", "test4",

		// Production environments
		"prod1", "prod2", "prod3", "production1", "production2", "prd", "prd1",
		"live1", "live2", "live3", "www-prod", "www-live",

		// Staging environments
		"stg1", "stg2", "stg3", "staging1", "staging2", "stage1", "stage2",
		"pre", "pre1", "pre2", "preview", "preview1", "preview2",

		// Geographic
		"ny", "nyc", "la", "sf", "chi", "dc", "tx", "fl", "ca", "uk1", "uk2",
		"london", "paris", "frankfurt", "tokyo", "singapore", "sydney",
		"dublin", "amsterdam", "mumbai", "seoul", "hongkong",

		// Protocols & services
		"tftp", "snmp", "dhcp", "tftp", "rsync", "ssh", "ssh1", "ssh2",
		"rdp", "rdp1", "vnc", "rdp-gateway", "ssh-gateway",

		// More common services
		"paste", "pastebin", "paste1", "gist", "snippet", "snippets",
		"shortener", "short", "url", "urls", "redirect", "redirects",

		// Additional infrastructure
		"router1", "switch1", "fw1", "fw2", "ids1", "ips1", "waf1",
		"bastion", "bastion1", "jump", "jumpbox", "jump1",

		// More API variations
		"api-dev", "api-staging", "api-prod", "api-internal", "api-external",
		"api-v1", "api-v2", "api-v3", "api-rest", "api-graphql",
		"api1-dev", "api2-dev", "api1-prod", "api2-prod",

		// Additional apps
		"apps1", "apps2", "apps3", "application", "applications",
		"app-dev", "app-staging", "app-prod", "app-test",

		// More mail variations
		"email1", "email2", "emails", "mailbox", "mailboxes", "postfix",
		"sendmail", "qmail", "zimbra", "zimbra1",

		// More monitoring
		"nagios1", "zabbix1", "icinga", "icinga1", "munin", "munin1",
		"cacti", "cacti1", "observium", "observium1",

		// More databases
		"postgresql", "postgres1", "postgres2", "pg", "pg1", "pg2",
		"mariadb", "mariadb1", "percona", "percona1",

		// Additional common terms
		"home", "home1", "main", "primary", "secondary", "tertiary",
		"master", "slave", "primary1", "secondary1", "replica1", "replica2",

		// Time-based
		"hourly", "daily", "weekly", "monthly", "yearly",
		"backup-hourly", "backup-daily", "backup-weekly",

		// More variations
		"v1-", "v2-", "v3-", "v4-", "v5-", "version1", "version2",
		"release1", "release2", "release3",

		// Common misconfigurations
		"adm", "administrator", "root", "sysadmin", "ops", "operations",
		"noc", "network", "net", "it", "info", "info1",
	}
}

func (d *Discovery) printResults() {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Printf("Discovery Results for: %s\n", d.domain)
	fmt.Println(strings.Repeat("=", 80))

	envGroups := make(map[string][]SubdomainResult)
	for _, r := range d.results {
		envGroups[r.Environment] = append(envGroups[r.Environment], r)
	}

	for env, results := range envGroups {
		fmt.Printf("\n[%s] (%d found)\n", strings.ToUpper(env), len(results))
		fmt.Println(strings.Repeat("-", 80))
		for _, r := range results {
			status := "DOWN"
			if r.IsAlive {
				status = fmt.Sprintf("UP (%d)", r.StatusCode)
			}
			fmt.Printf("  %-40s %-15s %s\n", r.Subdomain, status, strings.Join(r.IPAddresses, ", "))

			// Show location info if available
			if len(r.IPLocations) > 0 {
				for ip, loc := range r.IPLocations {
					locationStr := ""
					if loc.City != "" && loc.Region != "" {
						locationStr = fmt.Sprintf("%s, %s", loc.City, loc.Region)
					} else if loc.City != "" {
						locationStr = loc.City
					} else if loc.Region != "" {
						locationStr = loc.Region
					}
					if loc.Country != "" {
						if locationStr != "" {
							locationStr += ", " + loc.Country
						} else {
							locationStr = loc.Country
						}
					}
					if loc.Org != "" {
						if locationStr != "" {
							locationStr += " (" + loc.Org + ")"
						} else {
							locationStr = loc.Org
						}
					}
					if locationStr != "" {
						fmt.Printf("    └─ %s: %s\n", ip, locationStr)
					}
				}
			}
		}
	}

	fmt.Printf("\nTotal subdomains found: %d\n", len(d.results))
}

// API-related structures and handlers
type ScanStatus struct {
	Domain      string            `json:"domain"`
	Status      string            `json:"status"` // "running", "completed", "error"
	StartedAt   time.Time         `json:"started_at"`
	CompletedAt *time.Time        `json:"completed_at,omitempty"`
	Results     []SubdomainResult `json:"results,omitempty"`
	Error       string            `json:"error,omitempty"`
}

var db *sql.DB
var dbMu sync.Mutex

// Project represents a logical grouping of scopes (domains, IPs, etc.)
type Project struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	Scopes      []Scope   `json:"scopes,omitempty"`
}

// Scope represents a single asset scope (domain or IP) that can be scanned
type Scope struct {
	ID        int64     `json:"id"`
	ProjectID int64     `json:"project_id"`
	Type      string    `json:"type"`  // "domain" or "ip"
	Value     string    `json:"value"` // domain name or IP address
	CreatedAt time.Time `json:"created_at"`
}

func initDB(connString string) error {
	var err error
	db, err = sql.Open("postgres", connString)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	// Create tables
	createScansTable := `
	CREATE TABLE IF NOT EXISTS scans (
		domain TEXT PRIMARY KEY,
		status TEXT NOT NULL,
		started_at TIMESTAMP NOT NULL,
		completed_at TIMESTAMP,
		error TEXT
	);`

	createResultsTable := `
	CREATE TABLE IF NOT EXISTS scan_results (
		id SERIAL PRIMARY KEY,
		domain TEXT NOT NULL,
		subdomain TEXT NOT NULL,
		ip_addresses TEXT NOT NULL,
		ip_locations TEXT,
		status_code INTEGER NOT NULL,
		is_alive INTEGER NOT NULL,
		environment TEXT NOT NULL,
		FOREIGN KEY (domain) REFERENCES scans(domain) ON DELETE CASCADE
	);`

	createProjectsTable := `
	CREATE TABLE IF NOT EXISTS projects (
		id SERIAL PRIMARY KEY,
		name TEXT NOT NULL,
		description TEXT,
		created_at TIMESTAMP NOT NULL
	);`

	createScopesTable := `
	CREATE TABLE IF NOT EXISTS scopes (
		id SERIAL PRIMARY KEY,
		project_id INTEGER NOT NULL,
		type TEXT NOT NULL,
		value TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL,
		UNIQUE(type, value),
		FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
	);`

	// Add ip_locations column if it doesn't exist (for existing databases)
	addLocationColumn := `
	DO $$ 
	BEGIN
		IF NOT EXISTS (
			SELECT 1 FROM information_schema.columns 
			WHERE table_name = 'scan_results' AND column_name = 'ip_locations'
		) THEN
			ALTER TABLE scan_results ADD COLUMN ip_locations TEXT;
		END IF;
	END $$;`

	createIndex := `
	CREATE INDEX IF NOT EXISTS idx_scan_results_domain ON scan_results(domain);`

	createScopesIndex := `
	CREATE INDEX IF NOT EXISTS idx_scopes_project_id ON scopes(project_id);`

	if _, err := db.Exec(createScansTable); err != nil {
		return fmt.Errorf("failed to create scans table: %w", err)
	}

	if _, err := db.Exec(createResultsTable); err != nil {
		return fmt.Errorf("failed to create scan_results table: %w", err)
	}

	if _, err := db.Exec(createProjectsTable); err != nil {
		return fmt.Errorf("failed to create projects table: %w", err)
	}

	if _, err := db.Exec(createScopesTable); err != nil {
		return fmt.Errorf("failed to create scopes table: %w", err)
	}

	// Try to add ip_locations column (will fail silently if it already exists)
	_, _ = db.Exec(addLocationColumn)

	if _, err := db.Exec(createIndex); err != nil {
		return fmt.Errorf("failed to create index: %w", err)
	}

	if _, err := db.Exec(createScopesIndex); err != nil {
		return fmt.Errorf("failed to create scopes index: %w", err)
	}

	return nil
}

func startScan(domain string) (bool, error) {
	dbMu.Lock()
	defer dbMu.Unlock()

	// Check if scan already exists and is running
	var status string
	err := db.QueryRow("SELECT status FROM scans WHERE domain = $1", domain).Scan(&status)
	if err == nil {
		if status == "running" {
			return false, nil // Already running
		}
		// If exists but not running, delete old scan and results
		_, _ = db.Exec("DELETE FROM scan_results WHERE domain = $1", domain)
		_, _ = db.Exec("DELETE FROM scans WHERE domain = $1", domain)
	} else if err != sql.ErrNoRows {
		return false, fmt.Errorf("database error: %w", err)
	}

	// Insert new scan
	_, err = db.Exec(
		"INSERT INTO scans (domain, status, started_at) VALUES ($1, $2, $3)",
		domain, "running", time.Now(),
	)
	if err != nil {
		return false, fmt.Errorf("failed to insert scan: %w", err)
	}

	return true, nil
}

func updateScan(domain string, results []SubdomainResult, scanErr error) error {
	dbMu.Lock()
	defer dbMu.Unlock()

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Update scan status
	status := "completed"
	errorMsg := ""
	var completedAt *time.Time

	if scanErr != nil {
		status = "error"
		errorMsg = scanErr.Error()
		completedAt = nil
	} else {
		now := time.Now()
		completedAt = &now
	}

	if scanErr != nil {
		_, err = tx.Exec(
			"UPDATE scans SET status = $1, completed_at = NULL, error = $2 WHERE domain = $3",
			status, errorMsg, domain,
		)
	} else {
		_, err = tx.Exec(
			"UPDATE scans SET status = $1, completed_at = $2, error = $3 WHERE domain = $4",
			status, completedAt, errorMsg, domain,
		)
	}
	if err != nil {
		return fmt.Errorf("failed to update scan: %w", err)
	}

	// Delete old results
	_, err = tx.Exec("DELETE FROM scan_results WHERE domain = $1", domain)
	if err != nil {
		return fmt.Errorf("failed to delete old results: %w", err)
	}

	// Insert new results
	stmt, err := tx.Prepare(
		"INSERT INTO scan_results (domain, subdomain, ip_addresses, ip_locations, status_code, is_alive, environment) VALUES ($1, $2, $3, $4, $5, $6, $7)",
	)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, result := range results {
		ipAddressesJSON, _ := json.Marshal(result.IPAddresses)
		ipLocationsJSON, _ := json.Marshal(result.IPLocations)
		isAlive := 0
		if result.IsAlive {
			isAlive = 1
		}

		_, err = stmt.Exec(
			domain,
			result.Subdomain,
			string(ipAddressesJSON),
			string(ipLocationsJSON),
			result.StatusCode,
			isAlive,
			result.Environment,
		)
		if err != nil {
			return fmt.Errorf("failed to insert result: %w", err)
		}
	}

	return tx.Commit()
}

func getScan(domain string) (*ScanStatus, bool, error) {
	dbMu.Lock()
	defer dbMu.Unlock()

	var status string
	var startedAt time.Time
	var completedAt sql.NullTime
	var errorMsg sql.NullString
	err := db.QueryRow(
		"SELECT status, started_at, completed_at, error FROM scans WHERE domain = $1",
		domain,
	).Scan(&status, &startedAt, &completedAt, &errorMsg)

	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("database error: %w", err)
	}

	scan := &ScanStatus{
		Domain:    domain,
		Status:    status,
		StartedAt: startedAt,
		Error:     errorMsg.String,
	}

	if completedAt.Valid {
		scan.CompletedAt = &completedAt.Time
	}

	// Load results
	rows, err := db.Query(
		"SELECT subdomain, ip_addresses, ip_locations, status_code, is_alive, environment FROM scan_results WHERE domain = $1",
		domain,
	)
	if err != nil {
		return nil, false, fmt.Errorf("failed to query results: %w", err)
	}
	defer rows.Close()

	results := make([]SubdomainResult, 0)
	for rows.Next() {
		var result SubdomainResult
		var ipAddressesJSON string
		var ipLocationsJSON sql.NullString
		var isAlive int

		err := rows.Scan(
			&result.Subdomain,
			&ipAddressesJSON,
			&ipLocationsJSON,
			&result.StatusCode,
			&isAlive,
			&result.Environment,
		)
		if err != nil {
			continue
		}

		result.IsAlive = isAlive == 1
		json.Unmarshal([]byte(ipAddressesJSON), &result.IPAddresses)

		// Initialize IPLocations map
		result.IPLocations = make(map[string]LocationInfo)

		// Parse location data if available
		if ipLocationsJSON.Valid && ipLocationsJSON.String != "" {
			json.Unmarshal([]byte(ipLocationsJSON.String), &result.IPLocations)
		}

		results = append(results, result)
	}

	scan.Results = results
	return scan, true, nil
}

type DiscoverRequest struct {
	Domain     string `json:"domain"`
	Wordlist   string `json:"wordlist,omitempty"`
	Workers    int    `json:"workers,omitempty"`
	Timeout    string `json:"timeout,omitempty"`
	UseCT      *bool  `json:"use_ct,omitempty"`
	UseAXFR    *bool  `json:"use_axfr,omitempty"`
	ExpandSize int    `json:"expand_size,omitempty"`
}

type DiscoverResponse struct {
	Message string `json:"message"`
	Domain  string `json:"domain"`
	Status  string `json:"status"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func handleDiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req DiscoverRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, ErrorResponse{Error: "Invalid JSON: " + err.Error()})
		return
	}

	if req.Domain == "" {
		respondJSON(w, http.StatusBadRequest, ErrorResponse{Error: "domain is required"})
		return
	}

	// Check if scan already running
	started, err := startScan(req.Domain)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Database error: " + err.Error()})
		return
	}
	if !started {
		respondJSON(w, http.StatusConflict, ErrorResponse{Error: "Scan already running for this domain"})
		return
	}

	// Set defaults
	if req.Workers == 0 {
		req.Workers = 50
	}
	timeoutDuration := 3 * time.Second
	if req.Timeout != "" {
		if parsed, err := time.ParseDuration(req.Timeout); err == nil {
			timeoutDuration = parsed
		}
	}
	// UseCT and UseAXFR default to true (matching CLI behavior)
	useCT := true
	if req.UseCT != nil {
		useCT = *req.UseCT
	}
	useAXFR := true
	if req.UseAXFR != nil {
		useAXFR = *req.UseAXFR
	}

	// Start scan in background
	startDiscoveryBackground(req.Domain, req.Wordlist, req.Workers, timeoutDuration, useCT, useAXFR, req.ExpandSize)

	respondJSON(w, http.StatusAccepted, DiscoverResponse{
		Message: "Discovery started",
		Domain:  req.Domain,
		Status:  "running",
	})
}

func handleGetResults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		respondJSON(w, http.StatusBadRequest, ErrorResponse{Error: "domain parameter is required"})
		return
	}

	scan, exists, err := getScan(domain)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Database error: " + err.Error()})
		return
	}
	if !exists {
		respondJSON(w, http.StatusNotFound, ErrorResponse{Error: "No scan found for this domain"})
		return
	}

	respondJSON(w, http.StatusOK, scan)
}

func handleGetStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		respondJSON(w, http.StatusBadRequest, ErrorResponse{Error: "domain parameter is required"})
		return
	}

	scan, exists, err := getScan(domain)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Database error: " + err.Error()})
		return
	}
	if !exists {
		respondJSON(w, http.StatusNotFound, ErrorResponse{Error: "No scan found for this domain"})
		return
	}

	// Return status without full results
	statusOnly := ScanStatus{
		Domain:      scan.Domain,
		Status:      scan.Status,
		StartedAt:   scan.StartedAt,
		CompletedAt: scan.CompletedAt,
		Error:       scan.Error,
	}
	if scan.Status == "completed" {
		statusOnly.Results = scan.Results // Include results when completed
	}

	respondJSON(w, http.StatusOK, statusOnly)
}

// --- Projects & Scopes ---

type createProjectRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type createScopeRequest struct {
	ProjectID int64  `json:"project_id"`
	Type      string `json:"type"`  // "domain" or "ip"
	Value     string `json:"value"` // domain or IP
}

func handleProjects(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		getProjects(w, r)
	case http.MethodPost:
		createProject(w, r)
	case http.MethodDelete:
		deleteProject(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func getProjects(w http.ResponseWriter, _ *http.Request) {
	dbMu.Lock()
	defer dbMu.Unlock()

	rows, err := db.Query("SELECT id, name, description, created_at FROM projects ORDER BY created_at DESC")
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Database error: " + err.Error()})
		return
	}
	defer rows.Close()

	var projects []Project
	for rows.Next() {
		var (
			id          int64
			name        string
			description sql.NullString
			createdAt   time.Time
		)
		if err := rows.Scan(&id, &name, &description, &createdAt); err != nil {
			continue
		}

		p := Project{
			ID:          id,
			Name:        name,
			Description: description.String,
			CreatedAt:   createdAt,
		}

		// Load scopes for this project
		scopeRows, err := db.Query("SELECT id, project_id, type, value, created_at FROM scopes WHERE project_id = $1 ORDER BY created_at ASC", id)
		if err == nil {
			defer scopeRows.Close()
			for scopeRows.Next() {
				var s Scope
				var createdAtTime time.Time
				if err := scopeRows.Scan(&s.ID, &s.ProjectID, &s.Type, &s.Value, &createdAtTime); err != nil {
					continue
				}
				s.CreatedAt = createdAtTime
				p.Scopes = append(p.Scopes, s)
			}
		}

		projects = append(projects, p)
	}

	respondJSON(w, http.StatusOK, projects)
}

func createProject(w http.ResponseWriter, r *http.Request) {
	var req createProjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, ErrorResponse{Error: "Invalid JSON: " + err.Error()})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		respondJSON(w, http.StatusBadRequest, ErrorResponse{Error: "name is required"})
		return
	}

	now := time.Now()

	dbMu.Lock()
	res, err := db.Exec("INSERT INTO projects (name, description, created_at) VALUES ($1, $2, $3)", req.Name, req.Description, now)
	dbMu.Unlock()
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Database error: " + err.Error()})
		return
	}

	id, _ := res.LastInsertId()
	project := Project{
		ID:          id,
		Name:        req.Name,
		Description: req.Description,
		CreatedAt:   now,
	}

	respondJSON(w, http.StatusCreated, project)
}

func deleteProject(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		respondJSON(w, http.StatusBadRequest, ErrorResponse{Error: "id parameter is required"})
		return
	}
	projectID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid id parameter"})
		return
	}

	dbMu.Lock()
	defer dbMu.Unlock()

	// Delete scans associated with all scopes of this project
	scopeRows, err := db.Query("SELECT value FROM scopes WHERE project_id = $1", projectID)
	if err == nil {
		defer scopeRows.Close()
		for scopeRows.Next() {
			var value string
			if err := scopeRows.Scan(&value); err != nil {
				continue
			}
			_, _ = db.Exec("DELETE FROM scans WHERE domain = $1", value)
		}
	}

	// Delete project (scopes will be removed via FK cascade)
	if _, err := db.Exec("DELETE FROM projects WHERE id = $1", projectID); err != nil {
		respondJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Database error: " + err.Error()})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func handleScopes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		createScope(w, r)
	case http.MethodDelete:
		deleteScope(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func createScope(w http.ResponseWriter, r *http.Request) {
	var req createScopeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, ErrorResponse{Error: "Invalid JSON: " + err.Error()})
		return
	}

	if req.ProjectID == 0 {
		respondJSON(w, http.StatusBadRequest, ErrorResponse{Error: "project_id is required"})
		return
	}
	req.Type = strings.ToLower(strings.TrimSpace(req.Type))
	req.Value = strings.TrimSpace(req.Value)
	if req.Type != "domain" && req.Type != "ip" {
		respondJSON(w, http.StatusBadRequest, ErrorResponse{Error: "type must be 'domain' or 'ip'"})
		return
	}
	if req.Value == "" {
		respondJSON(w, http.StatusBadRequest, ErrorResponse{Error: "value is required"})
		return
	}

	now := time.Now()

	dbMu.Lock()
	res, err := db.Exec(
		"INSERT INTO scopes (project_id, type, value, created_at) VALUES ($1, $2, $3, $4)",
		req.ProjectID, req.Type, req.Value, now,
	)
	dbMu.Unlock()
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Database error: " + err.Error()})
		return
	}

	scopeID, _ := res.LastInsertId()
	scope := Scope{
		ID:        scopeID,
		ProjectID: req.ProjectID,
		Type:      req.Type,
		Value:     req.Value,
		CreatedAt: now,
	}

	// Start a scan for this scope
	started, err := startScan(req.Value)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Database error: " + err.Error()})
		return
	}
	if !started {
		respondJSON(w, http.StatusConflict, ErrorResponse{Error: "Scan already running for this scope"})
		return
	}

	// Background scan depending on scope type
	if req.Type == "domain" {
		startDiscoveryBackground(req.Value, "", 50, 3*time.Second, true, true, 0)
	} else if req.Type == "ip" {
		startIPScanBackground(req.Value, 3*time.Second)
	}

	respondJSON(w, http.StatusCreated, scope)
}

func deleteScope(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		respondJSON(w, http.StatusBadRequest, ErrorResponse{Error: "id parameter is required"})
		return
	}
	scopeID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid id parameter"})
		return
	}

	dbMu.Lock()
	defer dbMu.Unlock()

	// Find scope value so we can delete its assets
	var value string
	err = db.QueryRow("SELECT value FROM scopes WHERE id = $1", scopeID).Scan(&value)
	if err == sql.ErrNoRows {
		respondJSON(w, http.StatusNotFound, ErrorResponse{Error: "scope not found"})
		return
	} else if err != nil {
		respondJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Database error: " + err.Error()})
		return
	}

	// Delete scans (assets) for this scope; scan_results will cascade
	_, _ = db.Exec("DELETE FROM scans WHERE domain = $1", value)

	// Delete scope itself
	if _, err := db.Exec("DELETE FROM scopes WHERE id = $1", scopeID); err != nil {
		respondJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "Database error: " + err.Error()})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// startDiscoveryBackground starts a domain discovery scan in the background.
func startDiscoveryBackground(domain, wordlist string, workers int, timeout time.Duration, useCT, useAXFR bool, expandSize int) {
	go func() {
		discovery := NewDiscovery(domain, workers, timeout, expandSize)

		if err := discovery.loadWordlist(wordlist); err != nil {
			if updateErr := updateScan(domain, nil, err); updateErr != nil {
				log.Printf("Failed to update scan error in database: %v", updateErr)
			}
			return
		}

		ctx := context.Background()

		// Method 1: DNS bruteforce
		discovery.dnsEnumeration(ctx)

		// Method 2: Certificate Transparency logs
		if useCT {
			if err := discovery.ctLogsEnumeration(ctx); err != nil {
				// Log error but continue
				log.Printf("CT logs error for %s: %v", domain, err)
			}
		}

		// Method 3: Zone transfer attempt
		if useAXFR {
			discovery.attemptZoneTransfer()
		}

		// Update scan with results
		if err := updateScan(domain, discovery.results, nil); err != nil {
			log.Printf("Failed to update scan in database: %v", err)
		}
	}()
}

// startIPScanBackground starts a simple IP scan (HTTP probe + geolocation) in the background.
func startIPScanBackground(ip string, timeout time.Duration) {
	go func() {
		discovery := NewDiscovery(ip, 1, timeout, 0)
		ctx := context.Background()

		result := SubdomainResult{
			Subdomain:   ip,
			IPAddresses: []string{ip},
			IPLocations: make(map[string]LocationInfo),
			IsAlive:     false,
			Environment: "unknown",
		}

		if loc := discovery.fetchIPLocation(ctx, ip); loc != nil {
			result.IPLocations[ip] = *loc
		}

		if discovery.probeHTTP(ip, &result) {
			result.IsAlive = true
		}

		if err := updateScan(ip, []SubdomainResult{result}, nil); err != nil {
			log.Printf("Failed to update IP scan in database: %v", err)
		}
	}()
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "3600")

		// Handle preflight requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Call the next handler
		next(w, r)
	}
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func startServer(port string, connString string) {
	// Initialize database
	if err := initDB(connString); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	http.HandleFunc("/api/discover", corsMiddleware(handleDiscover))
	http.HandleFunc("/api/results", corsMiddleware(handleGetResults))
	http.HandleFunc("/api/status", corsMiddleware(handleGetStatus))
	http.HandleFunc("/api/projects", corsMiddleware(handleProjects))
	http.HandleFunc("/api/scopes", corsMiddleware(handleScopes))
	http.HandleFunc("/health", corsMiddleware(handleHealth))

	addr := ":" + port
	fmt.Printf("[*] Starting REST API server on http://localhost%s\n", addr)
	fmt.Printf("[*] Database: PostgreSQL\n")
	fmt.Printf("[*] Endpoints:\n")
	fmt.Printf("    POST   /api/discover - Start a discovery scan\n")
	fmt.Printf("    GET    /api/results?domain=example.com - Get full results\n")
	fmt.Printf("    GET    /api/status?domain=example.com - Get scan status\n")
	fmt.Printf("    GET    /health - Health check\n")

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

func main() {
	domain := flag.String("d", "", "Target domain (required for CLI mode)")
	wordlist := flag.String("w", "", "Wordlist file (optional)")
	workers := flag.Int("t", 50, "Number of concurrent workers")
	timeout := flag.Duration("timeout", 3*time.Second, "Timeout for DNS/HTTP requests")
	useCT := flag.Bool("ct", true, "Use Certificate Transparency logs")
	axfr := flag.Bool("axfr", true, "Attempt AXFR zone transfer")
	expandSize := flag.Int("n", 0, "Expand default wordlist to N entries (numeric suffixes)")
	server := flag.Bool("server", false, "Start REST API server instead of CLI mode")
	port := flag.String("port", "8080", "Port for REST API server (default: 8080)")

	flag.Parse()

	// If server mode, start the API server
	if *server {
		connString := os.Getenv("DATABASE_URL")
		if connString == "" {
			log.Fatal("DATABASE_URL environment variable is required when running in server mode")
		}
		startServer(*port, connString)
		return
	}

	// CLI mode - require domain
	if *domain == "" {
		fmt.Println("Usage:")
		fmt.Println("  CLI Mode:  go run main.go -d example.com [-w wordlist.txt] [-t 50]")
		fmt.Println("  Server Mode: go run main.go -server [-port 8080]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	discovery := NewDiscovery(*domain, *workers, *timeout, *expandSize)

	fmt.Printf("[*] Starting subdomain discovery for: %s\n", *domain)
	fmt.Printf("[*] Workers: %d, Timeout: %s\n", *workers, *timeout)

	// Load wordlist
	if err := discovery.loadWordlist(*wordlist); err != nil {
		fmt.Printf("[!] Error loading wordlist: %v\n", err)
	}
	fmt.Printf("[*] Loaded %d words for enumeration\n", len(discovery.wordlist))

	ctx := context.Background()

	// Method 1: DNS bruteforce
	fmt.Println("\n[*] Starting DNS enumeration...")
	discovery.dnsEnumeration(ctx)

	// Method 2: Certificate Transparency logs
	if *useCT {
		fmt.Println("\n[*] Querying Certificate Transparency logs...")
		if err := discovery.ctLogsEnumeration(ctx); err != nil {
			fmt.Printf("[!] CT logs error: %v\n", err)
		}
	}

	// Method 3: Zone transfer attempt
	if *axfr {
		discovery.attemptZoneTransfer()
	}

	// Display results
	discovery.printResults()
}
