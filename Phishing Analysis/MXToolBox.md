Using MXToolbox for Phishing Analysis
MXToolbox is a free online suite of network diagnostic tools that's very useful for investigating suspicious emails and potential phishing attempts. Here's how to use it effectively:

1. Start at mxtoolbox.com
Go to mxtoolbox.com — the main dashboard gives you a search bar where you can look up domains, IPs, email headers, and more.

2. Email Header Analysis
This is the most powerful feature for phishing analysis.
How to use it:

In your email client, find the option to view the raw/original headers (in Gmail: three dots → "Show original"; in Outlook: File → Properties)
Copy the full header block
Go to mxtoolbox.com/EmailHeaders and paste it in
Click Analyze Header

What to look for in results:

Received chain — traces the email's path across servers; mismatches between claimed and actual origin are a red flag
SPF result — did the sending server have permission to send on behalf of that domain?
DKIM result — was the email cryptographically signed and unaltered?
DMARC result — does the domain have a policy, and did the email comply?
Delay analysis — unusual routing delays can indicate spam infrastructure


3. Domain Lookup
Investigate the sender's domain or any domain in the email.

Use the main search bar → type the suspicious domain → select MX Lookup
Also try Blacklist Check to see if the domain or its mail server is on spam/phishing blocklists (MXToolbox checks 100+ lists)

Red flags:

Very recently registered domains (pair with WHOIS lookup)
Domain not matching the brand it claims to be (e.g., paypa1-secure.com)
MX records pointing to free/generic mail hosts (e.g., Gmail, Outlook) for a "corporate" sender


4. IP Blacklist Check
If you have the sending IP (found in email headers):

Go to mxtoolbox.com/blacklists or type the IP in the search bar
Select Blacklist Check
A legitimate company's mail server should not appear on any blacklists


5. SPF Record Lookup
Check if the domain has a valid SPF record:

Type the domain → select SPF Lookup
A missing SPF record means anyone can spoof that domain
Check if the sending IP is actually included in the SPF record


6. DKIM Lookup
Verify if DKIM is properly configured:

Go to SuperTool → DKIM Lookup
Enter: selector._domainkey.domain.com (the selector is in the email headers under DKIM-Signature: s=)
Missing or misconfigured DKIM is common in spoofed/phishing emails


7. DMARC Lookup
Check the domain's DMARC policy:

Type _dmarc.domain.com in the SuperTool
Look for p=reject or p=quarantine — a policy of p=none offers no protection and is often exploited


Phishing Analysis Checklist with MXToolbox
CheckToolRed FlagEmail routing pathHeader AnalyzerUnexpected foreign serversSPFSPF Lookup / Headerfail or softfailDKIMDKIM Lookup / Headerfail or missingDMARCDMARC Lookup / Headernone policy or failSending IP reputationBlacklist CheckListed on any blacklistDomain reputationBlacklist CheckListed or newly registeredMX RecordsMX LookupGeneric/free mail hosts

Pro Tips

Combine with other tools: Use MXToolbox alongside VirusTotal (scan URLs/attachments), URLScan.io (analyze links), and WHOIS lookups for full investigation
Don't click links in the suspicious email — copy the URL and analyze it separately
Screenshot everything before the phishing infrastructure goes offline

MXToolbox gives you a solid technical picture of whether an email's infrastructure is legitimate, making it a great first step in any phishing investigation.
