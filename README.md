# Penetration Testing Report: Footprinting & Network Scanning

**Reconnaissance of networkwalks.com and host discovery with Zenmap**

**Prepared by: JATOTH ABHUDAY CHANDRANATH**

## 1. Liability Disclaimer

These activities were performed only on systems and devices where I had permission, or that I own. All material here is for education and research only. Do not use anything from this repository to break the law. The author and Networkwalks are not responsible for how this knowledge is used. Every action you take is your own responsibility, and unauthorised access is a crime in most countries even when nothing is damaged.

## 2. Introduction

This report covers footprinting the **networkwalks.com** domain with several Kali Linux tools and scanning a private lab network with Zenmap. The first part shows how an attacker gathers public information about a target. The second shows how live hosts on a network are discovered and mapped. Together they cover the first two phases of a penetration test.

Each step lists the command used, the result observed, a screenshot as evidence, and a short note on why the finding matters.

## 3. Tools Used

| Tool | Purpose |
|---|---|
| Kali Linux | Operating system used for web and DNS reconnaissance |
| whois | Find domain registration details (registrar, dates, name servers) |
| nslookup | Resolve the domain name to its IP address using DNS |
| curl -I | Read the HTTP response headers of the website |
| whatweb | Fingerprint web technologies (server, CMS, plugins, IP) |
| wafw00f v2.4.2 | Detect whether a Web Application Firewall protects the site |
| dnsrecon | Enumerate DNS records (SOA, NS, MX, A, TXT, SRV) and check DNSSEC |
| Zenmap (Nmap 7.993) | Ping scan of the lab subnet to find live hosts and view the topology |

## 4. Activities Performed

### 4.1 Footprinting & Reconnaissance (networkwalks.com)

#### Step 1: Domain registration with WHOIS

```bash
whois networkwalks.com
```

[Write 2-3 lines from your whois output: registrar, creation and expiry dates, name servers, and whether registrant details are hidden by privacy protection.]

*WHOIS screenshot: not included in the supplied report images.*

#### Step 2: DNS resolution with nslookup

```bash
nslookup networkwalks.com
```

The domain resolves to **192.232.216.135** (non-authoritative answer from 8.8.8.8). This IP is the main target for later port and service scanning.


#### Step 3: HTTP headers with curl

```bash
curl -I https://networkwalks.com
```

The server returned `HTTP/1.1 200 OK` with `Server: Apache`. The headers also showed the WordPress REST API endpoint (`/wp-json/`), an nginx cache header (`X-nginx-cache: WordPress`), a `Referrer-Policy: no-referrer-when-downgrade` header and a session cookie marked `secure; HttpOnly`. No `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options` or `X-Content-Type-Options` header was seen in this HEAD response.


Additional capture from the repeated header request:


#### Step 4: Technology fingerprinting with WhatWeb

```bash
whatweb networkwalks.com
```

| Attribute | Detected value |
|---|---|
| Redirect | HTTP returns 301 to HTTPS |
| Web server | Apache |
| CMS | WordPress 7.1.4 |
| Plugin | WordPress Download Manager 3.3.76 |
| JavaScript | jQuery 3.7.1, Google Tag Manager |
| Contact e-mail | info@networkwalks.com |
| IP / Country | 192.232.216.135 / United States |

WhatWeb also listed a Bootstrap version equal to the WordPress version. This looks like a fingerprinting false positive and should be checked by hand.


#### Step 5: WAF detection with wafw00f

```bash
wafw00f networkwalks.com
```

The site is behind **ModSecurity (SpiderLabs)**, found in 2 requests. A WAF is a positive control, but it also means later active testing must be slow and carefully scoped.



#### Step 6: DNS enumeration with dnsrecon

```bash
dnsrecon -d networkwalks.com
```

| Type | Record | Note |
|---|---|---|
| SOA / NS | ns6135.hostgator.com (50.87.144.87), ns6136.hostgator.com (192.232.216.131) | BIND 9.16.23-RH version exposed |
| A | networkwalks.com: 192.232.216.135 | Web server |
| MX | mail.networkwalks.com: 192.232.216.135 | Mail on the same IP as the web server |
| TXT | `v=spf1 +a +mx +ip4:50.87.144.87 +include:websitewelcome.com ~all` | SPF with soft-fail |
| TXT | google-site-verification token | Domain ownership verification |
| SRV | `_autodiscover._tcp` to cpanelemaildiscovery.cpanel.net (8 hosts, port 443) | cPanel e-mail autodiscovery |
| DNSSEC | No answer for DNSSEC query | DNSSEC not detected |

dnsrecon reported 8 records.


### 4.2 Network Scanning with Zenmap

I ran a **Ping scan** (`-sn`) from Zenmap against the lab subnet to find live hosts, then opened the Topology tab with the legend enabled.

```bash
nmap -sn 10.131.40.0/24
```

| Item | Result |
|---|---|
| Scanner | Nmap 7.993 (Zenmap) |
| Scan time | 14 November 2026, 11:03 (+05:30) |
| Addresses scanned | 256 |
| Hosts up | **2** |
| Host 1 | 10.131.40.102 (up, latency 0.042 s, MAC 8A:F0:29:8E:F9:2C, vendor unknown) |
| Host 2 | 10.131.40.41 (up) |
| Duration | 12.05 seconds |


The topology view shows `localhost` linked to both hosts with dashed lines. Dashed lines mean no traceroute data was collected, which is expected for a ping scan. The green node colour comes from the Zenmap legend and does not describe open ports, because no ports were scanned.


## 5. Risk Analysis / Impact

| # | Risk / Finding | Evidence | Potential Impact | Risk Level |
|---|---|---|---|---|
| 1 | CMS and plugin versions disclosed | WhatWeb: WordPress 7.1.4, Download Manager 3.3.76 | Exact versions help an attacker match known vulnerabilities | Low |
| 2 | DNS server version disclosed | dnsrecon: BIND 9.16.23-RH | Helps profile the DNS infrastructure | Low |
| 3 | DNSSEC not detected | dnsrecon: no DNSSEC answer | DNS responses cannot be cryptographically validated | Low |
| 4 | SPF soft-fail policy | TXT record ends in `~all` | Spoofed mail may be accepted by some receivers | Low |
| 5 | Security headers not observed | curl: no HSTS, CSP, X-Frame-Options, X-Content-Type-Options | Weaker browser-side protection | Low |
| 6 | Session cookie without visible SameSite | curl: `__wpdm_client; secure; HttpOnly` | Slightly higher CSRF exposure | Low |
| 7 | REST API discoverable | `Link` header: `/wp-json/` | Starting point for user and endpoint enumeration | Info |
| 8 | Caching and proxy details leaked | `X-nginx-cache`, `X-Endurance-Cache-Level` | Reveals infrastructure details | Info |
| 9 | WAF identifiable | wafw00f: ModSecurity (SpiderLabs) | Reveals security architecture | Info |
| 10 | Live hosts visible on lab network | Zenmap: 2 hosts up on 10.131.40.0/24 | Unknown devices could go unnoticed | Info |

Risk levels: Critical, High, Medium, Low, Info. No item was rated above Low.

These are observations, not confirmed vulnerabilities. Only information gathering and host discovery were performed, with no exploitation or vulnerability validation. A software version, IP address or DNS record does not by itself mean a system is vulnerable. Further authorised testing would be needed to confirm any real weakness.

## 6. Recommendations

1. **Reduce technology disclosure.** Remove version information from the page source (generator tags) and hide the DNS server version where possible.
2. **Keep software updated.** Update WordPress core, themes and plugins, and check them against current security advisories.
3. **Add security headers.** Add HSTS, Content-Security-Policy, X-Frame-Options and X-Content-Type-Options, and tighten the Referrer-Policy.
4. **Harden e-mail authentication.** Move SPF to `-all` after checking legitimate senders, and publish DMARC and DKIM records.
5. **Enable DNSSEC** if the registrar and DNS host support it.
6. **Restrict the REST API.** Limit unauthenticated user endpoints and disable unused features such as XML-RPC.
7. **Tune and monitor the WAF.** Keep ModSecurity enabled with a current rule set and review its logs.
8. **Scan the internal network regularly** and investigate any unknown device that appears.
9. **Document the network.** Keep topology and device lists up to date.
10. **Test only with authorisation.** Reconnaissance and scanning should only target systems where permission has been given.

## 7. Conclusion

In this phase I gathered information about networkwalks.com with six tools (whois, nslookup, curl, WhatWeb, wafw00f and dnsrecon) and discovered live hosts on a lab network with Zenmap. The website runs WordPress on Apache behind a ModSecurity WAF on shared hosting. It showed no high-risk issues at this stage, only a few low-risk hardening gaps and some information disclosure. The lab scan found two live hosts.

The exercises showed how much can be learned before any exploitation is attempted, and why findings need clear documentation: what was done, what was found, what it means, what risk it creates and how to reduce it. They also showed that all scanning must stay within an authorised scope.

**Next steps:** port and service scanning of 192.232.216.135 and of the two lab hosts (for example `nmap -sV -O`), WordPress enumeration, TLS review, and DMARC/DKIM checks, all within the agreed scope.

## 8. Evidence Collected

Screenshots are stored in the root of this repository:


*-End-*

