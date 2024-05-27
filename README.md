

def urlEnrichmentHTML(anomalits, virustotal, url):
    
    rawData = ""
    resultData = ""
    returnData = ""
    keyfields = ""
    contextData = ""
    error = ""
    
    urllength = len(url)
        
    body_html_table = "<!DOCTYPE html><html><head><title>URL Enrichment</title><style>table.table1 {table-layout: fixed; width: 800px; border: 1px solid white; border-collapse: collapse;} table.table1 td {border: 0.5px solid white; padding: 0; white-space:normal; font-weight: lighter;} table.table1 th {border: 0.5px solid white; padding: 0; white-space:normal;}</style></head><body>"
    
    try: 
    
        i = 0
    
        while i < urllength:
        
            #Populate URL
            body_html_table = body_html_table + "<div style=\"overflow-x:auto;\"><table class=\"table1\"; style=\"font-family:arial; color:white; font-size: 12px;\"><tr><th align=\"left\"; valign=\"top\"; width=\"20%\";>URL</th></tr>"
        
            body_html_table = body_html_table + "<tr><td align=\"left\"; valign=\"top\";>" + str(url[i]) + "</td></tr></table></div><br>"
        
            body_html_table = body_html_table + "<div style=\"overflow-x:auto;\"><table class=\"table1\"; style=\"font-family:arial; color:white; font-size: 12px;\"><tr><th align=\"left\"; valign=\"top\"; width=\"20%\";>Anomali</th></tr>"
            
            body_html_table = body_html_table + "<tr><th align=\"left\"; valign=\"top\"; width=\"20%\"; colspan=\"5\";>Confidence</th><th align=\"left\"; valign=\"top\"; width=\"20%\";>Severity</th><th align=\"left\"; valign=\"top\"; width=\"20%\";>Itype</th><th align=\"left\"; valign=\"top\"; width=\"20%\";>Status</th><th align=\"left\"; valign=\"top\"; width=\"20%\";>Source</th></tr>"
        
            anomaliresults = len(anomalits)
        
            if anomaliresults > 0:
            
                j = 0
            
                while j < anomaliresults:
            
                    if url[i] == anomalits[j]['url']:
                    
                        confidence = anomalits[j]['Confidence']
                        severity = anomalits[j]['Severity']
                        itype = anomalits[j]['itype']
                        status = anomalits[j]['Status']
                        source = anomalits[j]['Source']
                    
                        j+=1
                
                        body_html_table = body_html_table + "<tr><td align=\"left\"; valign=\"top\";>" + str(confidence) + "</td><td align=\"left\"; valign=\"top\";>" + str(severity) + "</td><td align=\"left\"; valign=\"top\";>" + str(itype) + "</td><td align=\"left\"; valign=\"top\";>" + str(status) + "</td><td align=\"left\"; valign=\"top\";>" + str(source) + "</td></tr>"
        
                    else:
                        j+=1
            
                body_html_table = body_html_table + "</table></div><br>"
        
            else:
                confidence = ""
                severity = ""
                itype = ""
                status = ""
                source = ""
            
                body_html_table = body_html_table + "<tr><td align=\"left\"; valign=\"top\"; >" + str(confidence) + "</td><td align=\"left\"; valign=\"top\";>" + str(severity) + "</td><td align=\"left\"; valign=\"top\";>" + str(itype) + "</td><td align=\"left\"; valign=\"top\";>" + str(status) + "</td><td align=\"left\"; valign=\"top\";>" + str(source) + "</td></tr></table></div><br>"
            
            if len(virustotal)>0 and len(virustotal[i]) > 0:
                harmless = virustotal[i]['data']['attributes']['last_analysis_stats']['harmless']
                malicious = virustotal[i]['data']['attributes']['last_analysis_stats']['malicious']
                suspicious = virustotal[i]['data']['attributes']['last_analysis_stats']['suspicious']
                undetected = virustotal[i]['data']['attributes']['last_analysis_stats']['undetected']
                timeout = virustotal[i]['data']['attributes']['last_analysis_stats']['timeout']
                reputation = virustotal[i]['data']['reputation']
                Type = virustotal[i]['data']['type']
        
            else:
                harmless = ""
                malicious = ""
                suspicious = ""
                undetected = ""
                timeout = ""
                status = ""
                Type = ""
        
            #HTML Table VirusTotal Enrichment
            body_html_table = body_html_table + "<div style=\"overflow-x:auto;\"><table class=\"table1\"; style=\"font-family:arial; color:white; font-size: 12px;\"><tr><th colspan=\"3\";>VirusTotal</th></tr>"
        
            body_html_table = body_html_table + "<tr><th align=\"left\"; valign=\"top\"; width=\"20%\";>Last Analysis Stats</th><th align=\"left\"; valign=\"top\"; width=\"20%\";>Status</th><th align=\"left\"; valign=\"top\"; width=\"20%\";>Type</th></tr>"
        
            body_html_table = body_html_table + "<tr><td align=\"left\"; valign=\"top\";>" + "harmless: " + str(harmless) + " malicious: " + str(malicious) + " suspicious: " + str(suspicious) + " undetected: " + str(undetected) + " timeout: " + str(timeout) + "</td><td align=\"left\"; valign=\"top\";>" + str(status) + "</td><td align=\"left\"; valign=\"top\";>" + str(Type) +  "</td></tr></table></div><br>"
            
            i+=1
    
            if i == (urllength):
                #End the HTML content
                body_html_table = body_html_table + "</div></body></html>"
                
                returnData = body_html_table

            else:
                continue
    
    except Exception as ex:
        error = str(ex)
    
    if error == "":
        resultData = "Successful"
    else:
        resultData = "Failed"
    
    return resultData


Inputs are
anomalits:

[
  {
    "Confidence": 0,
    "Severity": "high",
    "Created": "2023-04-26T23:06:10.075Z",
    "Modified": "2024-05-07T22:26:48.869Z",
    "itype": "phish_domain",
    "Source": "Mandiant - Indicators",
    "Status": "falsepos",
    "RiskScore": 0,
    "Reputation": 0.0,
    "ASN": "15169",
    "Country": "US",
    "Latitude": 37.751,
    "Longitude": -97.822,
    "Organization": "Google Servers",
    "IPAddress": "172.217.168.68",
    "Details": "imported by user 42060 Confirmed as false positive",
    "url": "www.google.com",
    "riskLevel": "1"
  }
]


          }
        },
        "reputation": 198,
        "whois": "Admin Country: US\nAdmin Organization: Google LLC\nAdmin State/Province: CA\nCreation Date: 1997-09-15T04:00:00Z\nCreation Date: 1997-09-15T07:00:00+0000\nDNSSEC: unsigned\nDomain Name: GOOGLE.COM\nDomain Name: google.com\nDomain Status: clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)\nDomain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\nDomain Status: clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)\nDomain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\nDomain Status: clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)\nDomain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited\nDomain Status: serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)\nDomain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited\nDomain Status: serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)\nDomain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited\nDomain Status: serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)\nDomain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited\nName Server: NS1.GOOGLE.COM\nName Server: NS2.GOOGLE.COM\nName Server: NS3.GOOGLE.COM\nName Server: NS4.GOOGLE.COM\nName Server: ns1.google.com\nName Server: ns2.google.com\nName Server: ns3.google.com\nName Server: ns4.google.com\nRegistrant Country: US\nRegistrant Email: ca4484b9e50182bds@\nRegistrant Organization: 3307059bbb3149c4\nRegistrant State/Province: b1952dfc047df18a\nRegistrar Abuse Contact Email: abusecomplaints@markmonitor.com\nRegistrar Abuse Contact Phone: +1.2086851750\nRegistrar IANA ID: 292\nRegistrar Registration Expiration Date: 2028-09-13T07:00:00+0000\nRegistrar URL: http://www.markmonitor.com\nRegistrar WHOIS Server: whois.markmonitor.com\nRegistrar: MarkMonitor Inc.\nRegistrar: MarkMonitor, Inc.\nRegistry Domain ID: 2138514_DOMAIN_COM-VRSN\nRegistry Expiry Date: 2028-09-14T04:00:00Z\nTech Country: US\nTech Organization: Google LLC\nTech State/Province: CA\nUpdated Date: 2019-09-09T15:39:04+0000\nUpdated Date: 2019-09-09T15:39:04Z",
        "last_analysis_stats": {
          "malicious": 0,
          "suspicious": 1,
          "undetected": 23,
          "harmless": 69,
          "timeout": 0
        },
        "last_update_date": 1568043544,
        "tld": "com",
        "threat_severity": {
          "version": "D3",
          "threat_severity_level": "SEVERITY_NONE",
          "threat_severity_data": {
            "has_bad_communicating_files_high": true,
            "has_bad_communicating_files_medium": true,
            "has_bad_downloaded_files_medium": true,
            "belongs_to_bad_collection": true,
            "domain_rank": "3"
          },
          "last_analysis_date": "1716595213",
          "level_description": "Severity NONE because it has no detections."
        },
        "last_dns_records_date": 1716665532
      },
      "context_attributes": {
        "detected_communicating_files_count": 100,
        "referring_files_max_detections": 58,
        "detected_downloaded_files_count": 100,
        "detected_referring_files_count": 100,
        "detected_urls_count": 100,
        "communicating_files_max_detections": 67,
        "downloaded_files_max_detections": 38,
        "urls_max_detections": 3
      }
    }
  ],
  "meta": {
    "total_hits": 5,
    "allowed_orders": [
      "creation_date",
      "last_modification_date",
      "last_update_date",
      "positives"
    ],
    "days_back": 90
  },
  "links": {
    "self": "https://www.virustotal.com/api/v3/intelligence/search?query=entity:domain+domain_regex:www.google.com&descriptors_only=false"
  }
}


Url:

["www.google.com"]


The output is error that. list indices must be integers or slices, not str
ChatGPT
The error you're encountering, "list indices must be integers or slices, not str," suggests that somewhere in your code, a list is being accessed using a string index instead of an integer. In the provided function, it's likely happening within the loops where you're working with the anomalits and virustotal dictionaries.

Here's the corrected version of your function with improved structure and better handling of the dictionaries:

python
Copy code
def urlEnrichmentHTML(anomalits, virustotal, url):
    
    body_html_table = "<!DOCTYPE html><html><head><title>URL Enrichment</title><style>table.table1 {table-layout: fixed; width: 800px; border: 1px solid white; border-collapse: collapse;} table.table1 td {border: 0.5px solid white; padding: 0; white-space:normal; font-weight: lighter;} table.table1 th {border: 0.5px solid white; padding: 0; white-space:normal;}</style></head><body>"
    
    try: 
        for i in range(len(url)):
            # Populate URL
            body_html_table += f"<div style=\"overflow-x:auto;\"><table class=\"table1\"; style=\"font-family:arial; color:white; font-size: 12px;\"><tr><th align=\"left\"; valign=\"top\"; width=\"20%\";>URL</th></tr>"
            body_html_table += f"<tr><td align=\"left\"; valign=\"top\";>{url[i]}</td></tr></table></div><br>"

            # Anomali Data
            body_html_table += "<div style=\"overflow-x:auto;\"><table class=\"table1\"; style=\"font-family:arial; color:white; font-size: 12px;\"><tr><th align=\"left\"; valign=\"top\"; width=\"20%\";>Anomali</th></tr>"
            body_html_table += "<tr><th align=\"left\"; valign=\"top\"; width=\"20%\"; colspan=\"5\";>Confidence</th><th align=\"left\"; valign=\"top\"; width=\"20%\";>Severity</th><th align=\"left\"; valign=\"top\"; width=\"20%\";>Itype</th><th align=\"left\"; valign=\"top\"; width=\"20%\";>Status</th><th align=\"left\"; valign=\"top\"; width=\"20%\";>Source</th></tr>"

            for anomali in anomalits:
                if url[i] == anomali['url']:
                    confidence = anomali.get('Confidence', "")
                    severity = anomali.get('Severity', "")
                    itype = anomali.get('itype', "")
                    status = anomali.get('Status', "")
                    source = anomali.get('Source', "")

                    body_html_table += f"<tr><td align=\"left\"; valign=\"top\";>{confidence}</td><td align=\"left\"; valign=\"top\";>{severity}</td><td align=\"left\"; valign=\"top\";>{itype}</td><td align=\"left\"; valign=\"top\";>{status}</td><td align=\"left\"; valign=\"top\";>{source}</td></tr>"

            body_html_table += "</table></div><br>"

            # VirusTotal Data
            if len(virustotal) > 0 and len(virustotal[i]) > 0:
                vt_data = virustotal[i]['data']['attributes']['last_analysis_stats']
                harmless = vt_data.get('harmless', "")
                malicious = vt_data.get('malicious', "")
                suspicious = vt_data.get('suspicious', "")
                undetected = vt_data.get('undetected', "")
                timeout = vt_data.get('timeout', "")
                reputation = virustotal[i]['data'].get('reputation', "")
                vtype = virustotal[i]['data'].get('type', "")

                body_html_table += "<div style=\"overflow-x:auto;\"><table class=\"table1\"; style=\"font-family:arial; color:white; font-size: 12px;\"><tr><th colspan=\"3\";>VirusTotal</th></tr>"
                body_html_table += "<tr><th align=\"left\"; valign=\"top\"; width=\"20%\";>Last Analysis Stats</th><th align=\"left\"; valign=\"top\"; width=\"20%\";>Reputation</th><th align=\"left\"; valign=\"top\"; width=\"20%\";>Type</th></tr>"
                body_html_table += f"<tr><td align=\"left\"; valign=\"top\";>harmless: {harmless} malicious: {malicious} suspicious: {suspicious} undetected: {undetected} timeout: {timeout}</td><td align=\"left\"; valign=\"top\";>{reputation}</td><td align=\"left\"; valign=\"top\";>{vtype}</td></tr></table></div><br>"
        
        body_html_table += "</div></body></html>"
        return body_html_table

    except Exception as ex:
        return f"Failed: {str(ex)}"
Key Improvements
Loop Structure: Used for loops for better readability and clarity.
Accessing Dictionary Values: Used .get() to access dictionary values safely and avoid KeyError.
String Concatenation: Improved string concatenation using f-strings for better readability.
Usage
To call this function, simply pass the anomalits, virustotal, and url lists:

python
Copy code
anomalits = [
    {
        "Confidence": 0,
        "Severity": "high",
        "Created": "2023-04-26T23:06:10.075Z",
        "Modified": "2024-05-07T22:26:48.869Z",
        "itype": "phish_domain",
        "Source": "Mandiant - Indicators",
        "Status": "falsepos",
        "RiskScore": 0,
        "Reputation": 0.0,
        "ASN": "15169",
        "Country": "US",
        "Latitude": 37.751,
        "Longitude": -97.822,
        "Organization": "Google Servers",
        "IPAddress": "172.217.168.68",
        "Details": "imported by user 42060 Confirmed as false positive",
        "url": "www.google.com",
        "riskLevel": "1"
    }
]

virustotal = [
    {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 1,
                    "undetected": 23,
                    "harmless": 69,
                    "timeout": 0
                },
                "reputation": 198,
                "type": "domain"
            }
        }
    }
]

url = ["www.google.com"]

html_output = urlEnrichmentHTML(anomalits, virustotal, url)
print(html_output)
This function should now handle the data correctly and generate the HTML output as expected.





Failed: list indices must be integers or slices, not str

5 s 633 ms
ChatGPT
The error message indicates that there's an issue with how the function accesses elements within the virustotal list. Let's correct the function to properly handle the data structures, ensuring all indices and accesses are correctly handled.

Here's the revised function:

python
Copy code
def urlEnrichmentHTML(anomalits, virustotal, url):
    
    body_html_table = "<!DOCTYPE html><html><head><title>URL Enrichment</title><style>table.table1 {table-layout: fixed; width: 800px; border: 1px solid white; border-collapse: collapse;} table.table1 td {border: 0.5px solid white; padding: 0; white-space:normal; font-weight: lighter;} table.table1 th {border: 0.5px solid white; padding: 0; white-space:normal;}</style></head><body>"
    
    try: 
        for i in range(len(url)):
            # Populate URL
            body_html_table += f"<div style=\"overflow-x:auto;\"><table class=\"table1\" style=\"font-family:arial; color:white; font-size: 12px;\"><tr><th align=\"left\" valign=\"top\" width=\"20%\">URL</th></tr>"
            body_html_table += f"<tr><td align=\"left\" valign=\"top\">{url[i]}</td></tr></table></div><br>"

            # Anomali Data
            body_html_table += "<div style=\"overflow-x:auto;\"><table class=\"table1\" style=\"font-family:arial; color:white; font-size: 12px;\"><tr><th align=\"left\" valign=\"top\" width=\"20%\">Anomali</th></tr>"
            body_html_table += "<tr><th align=\"left\" valign=\"top\" width=\"20%\" colspan=\"5\">Confidence</th><th align=\"left\" valign=\"top\" width=\"20%\">Severity</th><th align=\"left\" valign=\"top\" width=\"20%\">Itype</th><th align=\"left\" valign=\"top\" width=\"20%\">Status</th><th align=\"left\" valign=\"top\" width=\"20%\">Source</th></tr>"

            for anomali in anomalits:
                if url[i] == anomali['url']:
                    confidence = anomali.get('Confidence', "")
                    severity = anomali.get('Severity', "")
                    itype = anomali.get('itype', "")
                    status = anomali.get('Status', "")
                    source = anomali.get('Source', "")

                    body_html_table += f"<tr><td align=\"left\" valign=\"top\">{confidence}</td><td align=\"left\" valign=\"top\">{severity}</td><td align=\"left\" valign=\"top\">{itype}</td><td align=\"left\" valign=\"top\">{status}</td><td align=\"left\" valign=\"top\">{source}</td></tr>"

            body_html_table += "</table></div><br>"

            # VirusTotal Data
            if i < len(virustotal):
                vt_data = virustotal[i]['data']['attributes']['last_analysis_stats']
                harmless = vt_data.get('harmless', "")
                malicious = vt_data.get('malicious', "")
                suspicious = vt_data.get('suspicious', "")
                undetected = vt_data.get('undetected', "")
                timeout = vt_data.get('timeout', "")
                reputation = virustotal[i]['data'].get('reputation', "")
                vtype = virustotal[i]['data'].get('type', "")

                body_html_table += "<div style=\"overflow-x:auto;\"><table class=\"table1\" style=\"font-family:arial; color:white; font-size: 12px;\"><tr><th colspan=\"3\">VirusTotal</th></tr>"
                body_html_table += "<tr><th align=\"left\" valign=\"top\" width=\"20%\">Last Analysis Stats</th><th align=\"left\" valign=\"top\" width=\"20%\">Reputation</th><th align=\"left\" valign=\"top\" width=\"20%\">Type</th></tr>"
                body_html_table += f"<tr><td align=\"left\" valign=\"top\">harmless: {harmless} malicious: {malicious} suspicious: {suspicious} undetected: {undetected} timeout: {timeout}</td><td align=\"left\" valign=\"top\">{reputation}</td><td align=\"left\" valign=\"top\">{vtype}</td></tr></table></div><br>"
        
        body_html_table += "</div></body></html>"
        return body_html_table

    except Exception as ex:
        return f"Failed: {str(ex)}"
    
    
    import re

def enrichment_python(input_value):
    rawData = ""
    resultData = ""
    returnData = ""
    keyFields = ""
    contextData = []
    error = ""
    artifacttype = ""
    artifactvalue = input_value
    
    patterns = {
        'domain': r'^(?!-)[A-Za-z0-9-]+([-\\.]{1}[a-z0-9]+)*\.[A-Za-z]{2,6}$',
        'url': r'^(https?://)?[a-z0-9-]+(\.[a-z0-9-]+)*\.([a-z]{2,})(:[0-9]{1,5})?(/.*)?$',
        'ip': (r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
               r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
               r'|^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|'
               r'([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:'
               r'[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}'
               r'(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}'
               r'(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}'
               r'(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}'
               r'(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:'
               r'((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$'),
        'hash': r'^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$'
    }
    
    for indicator, pattern in patterns.items():
        if re.match(pattern, input_value, re.IGNORECASE):
            returnData = indicator
            artifacttype = indicator
            break
   
    if artifacttype:
        contextData.append({
            "artifactType": artifacttype,
            "artifactValue": artifactvalue
        })

    return contextData


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Horizontal Report Details Display</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <style>
        .collapsible, .nested-collapsible {
            background-color: DodgerBlue;
            color: white;
            cursor: pointer;
            padding: 12px;
            border: none;
            text-align: left;
            outline: none;
            font-size: 14px;
            display: block;
            width: 100%;
            box-sizing: border-box;
            margin-top: 5px;
        }

        .active, .collapsible:hover, .nested-collapsible:hover {
            background-color: #1E90FF;
        }

        .content, .nested-content {
            padding: 0 18px;
            display: none;
            overflow: hidden;
            background-color: #f1f1f1;
            transition: max-height 0.2s ease-out;
            width: 100%;
            box-sizing: border-box;
        }

        table, .nested-table {
            border-collapse: collapse;
            width: 100%;
            margin-top: 10px;
        }

        th, td, .nested-table th, .nested-table td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }

        th, .nested-table th {
            background-color: #f3f3f3;
        }

        input[type="text"] {
            padding: 8px;
            width: 100%;
            margin-bottom: 12px;
        }
    </style>
</head>
<body>
    <div class="container mx-auto">
        <h1 class="text-3xl font-bold mb-8 text-center">Enhanced ID-Based Report Details</h1>
        <input type="text" id="searchInput" placeholder="Search by Name..." onkeyup="filterReports()">
        <div id="jsonContainer"></div>
    </div>

    <script>
        const jsonData = [
            // Your JSON data array here
        ];

        const detailedKeys = ['schedule', 'last_execution', 'report_metadata', 'report_params', 'notifications', 'shared_with'];
        const container = document.getElementById('jsonContainer');

        jsonData.forEach((report, index) => {
            const reportButton = document.createElement('button');
            reportButton.textContent = report.name ? `${report.name} (ID: ${report.id})` : 'Unnamed Report';
            reportButton.className = 'collapsible';
            reportButton.dataset.name = report.name ? report.name.toLowerCase() : ''; // For searching by name

            const reportContent = document.createElement('div');
            reportContent.className = 'content';

            const reportTable = document.createElement('table');
            reportContent.appendChild(reportTable);

            Object.entries(report).forEach(([key, value]) => {
                const row = reportTable.insertRow();
                const keyCell = row.insertCell();
                keyCell.textContent = key;

                const valueCell = row.insertCell();
                if (detailedKeys.includes(key) && typeof value === 'object') {
                    const detailButton = document.createElement('button');
                    detailButton.textContent = `Toggle ${key}`;
                    detailButton.className = 'nested-collapsible';

                    const detailContent = document.createElement('div');
                    detailContent.className = 'nested-content';

                    const nestedTable = document.createElement('table');
                    nestedTable.className = 'nested-table';
                    Object.entries(value).forEach(([nestedKey, nestedValue]) => {
                        const nestedRow = nestedTable.insertRow();
                        const nestedKeyCell = nestedRow.insertCell();
                        nestedKeyCell.textContent = nestedKey;
                        const nestedValueCell = nestedRow.insertCell();
                        nestedValueCell.textContent = JSON.stringify(nestedValue, null, 2);
                    });

                    detailButton.onclick = function() {
                        this.classList.toggle("active");
                        detailContent.style.display = detailContent.style.display === 'block' ? 'none' : 'block';
                    };

                    detailContent.appendChild(nestedTable);
                    valueCell.appendChild(detailButton);
                    valueCell.appendChild(detailContent);
                } else {
                    valueCell.textContent = JSON.stringify(value, null, 2);
                }
            });

            container.appendChild(reportButton);
            container.appendChild(reportContent);

            reportButton.addEventListener('click', function() {
                this.classList.toggle("active");
                reportContent.style.display = reportContent.style.display === 'block' ? 'none' : 'block';
            });
        });

        function filterReports() {
            const input = document.getElementById('searchInput');
            const filter = input.value.toLowerCase();
            const buttons = container.getElementsByTagName('button');
            for (let i = 0; i < buttons.length; i++) {
                let name = buttons[i].dataset.name;
                if (name.indexOf(filter) > -1) {
                    buttons[i].style.display = "";
                    buttons[i].nextElementSibling.style.display = buttons[i].classList.contains('active') ? "block" : "none";
                } else {
                    buttons[i].style.display = "none";
                    buttons[i].nextElementSibling.style.display = "none";
                }
            }
        }
    </script>
</body>
</html>

function filterReports() {
    const input = document.getElementById('searchInput');
    const filter = input.value.toLowerCase();
    const buttons = container.getElementsByClassName('collapsible');

    for (let i = 0; i < buttons.length; i++) {
        let name = buttons[i].dataset.name;
        const reportContent = buttons[i].nextElementSibling;

        if (name && name.includes(filter)) {
            buttons[i].style.display = "block";
            if (buttons[i].classList.contains('active')) {
                reportContent.style.display = "block";
            } else {
                reportContent.style.display = "none";
            }
        } else {
            buttons[i].style.display = "none";
            reportContent.style.display = "none";
        }
    }
}

function filterReports() {
    const input = document.getElementById('searchInput');
    const filter = input.value.trim().toLowerCase();
    const buttons = container.getElementsByClassName('collapsible');

    for (let i = 0; i < buttons.length; i++) {
        const reportName = buttons[i].textContent.trim().toLowerCase();
        const reportContent = buttons[i].nextElementSibling;

        if (reportName.includes(filter)) {
            buttons[i].style.display = "block";
            if (buttons[i].classList.contains('active')) {
                reportContent.style.display = "block";
            } else {
                reportContent.style.display = "none";
            }
        } else {
            buttons[i].style.display = "none";
            reportContent.style.display = "none";
        }
    }
}
function filterReports() {
    const input = document.getElementById('searchInput');
    const filter = input.value.trim().toLowerCase();
    const buttons = container.getElementsByClassName('collapsible');

    for (let i = 0; i < buttons.length; i++) {
        const reportName = buttons[i].textContent.trim().toLowerCase();
        const reportContent = buttons[i].nextElementSibling;

        // Split the report name into individual words
        const reportWords = reportName.split(/\s+/);

        // Check if any word matches the search input
        const match = reportWords.some(word => word.includes(filter));

        if (match) {
            buttons[i].style.display = "block";
            if (buttons[i].classList.contains('active')) {
                reportContent.style.display = "block";
            } else {
                reportContent.style.display = "none";
            }
        } else {
            buttons[i].style.display = "none";
            reportContent.style.display = "none";
        }
    }
}



function updateSearchCount(count) {
    const searchCount = document.getElementById('searchCount');
    if (searchCount) {
        searchCount.textContent = `Number of search results: ${count}`;
    }
}

// Function to clear search input and update search count
function clearSearch() {
    const input = document.getElementById('searchInput');
    input.value = ''; // Clear the search input
    filterReports(); // Reapply filter to update display
}

// Clear search input and update count when input is cleared
document.getElementById('searchInput').addEventListener('change




const input = document.getElementById('searchInput');
const filter = input.value.trim().toLowerCase();
const buttons = container.getElementsByClassName('collapsible');

for (let i = 0; i < buttons.length; i++) {
    const reportName = buttons[i].textContent.trim().toLowerCase();
    const reportContent = buttons[i].nextElementSibling;

    // Split the search query into individual words
    const searchWords = filter.split(/\s+/);

    // Split the report name into individual words
    const reportWords = reportName.split(/\s+/);

    // Check if any word from search query matches any word in the report name
    const match = searchWords.some(searchWord => reportWords.some(reportWord => reportWord.includes(searchWord)));

    if (match) {
        buttons[i].style.display = "block";
        if (buttons[i].classList.contains('active')) {
            reportContent.style.display = "block";
        } else {
            reportContent.style.display = "none";
        }
    } else {
        buttons[i].style.display = "none";
        reportContent.style.display = "none";
    }
}




















def urlEnrichmentHTML(anomalits, virustotal, url):
    
    rawData = ""
    resultData = ""
    returnData = ""
    keyfields = ""
    contextData = ""
    error = ""
    
    urllength = len(url)
        
    body_html_table = "<!DOCTYPE html><html><head><title>URL Enrichment</title><style>table.table1 {table-layout: fixed; width: 800px; border: 1px solid white; border-collapse: collapse;} table.table1 td {border: 0.5px solid white; padding: 0; white-space:normal; font-weight: lighter;} table.table1 th {border: 0.5px solid white; padding: 0; white-space:normal;}</style></head><body>"
    
    try: 
    
        i = 0
    
        while i < urllength:
        
            #Populate URL
            body_html_table = body_html_table + "<div style=\"overflow-x:auto;\"><table class=\"table1\"; style=\"font-family:arial; color:white; font-size: 12px;\"><tr><th align=\"left\"; valign=\"top\"; width=\"20%\";>URL</th></tr>"
        
            body_html_table = body_html_table + "<tr><td align=\"left\"; valign=\"top\";>" + str(url[i]) + "</td></tr></table></div><br>"
        
            body_html_table = body_html_table + "<div style=\"overflow-x:auto;\"><table class=\"table1\"; style=\"font-family:arial; color:white; font-size: 12px;\"><tr><th align=\"left\"; valign=\"top\"; width=\"20%\";>Anomali</th></tr>"
            
            body_html_table = body_html_table + "<tr><th align=\"left\"; valign=\"top\"; width=\"20%\"; colspan=\"5\";>Confidence</th><th align=\"left\"; valign=\"top\"; width=\"20%\";>Severity</th><th align=\"left\"; valign=\"top\"; width=\"20%\";>Itype</th><th align=\"left\"; valign=\"top\"; width=\"20%\";>Status</th><th align=\"left\"; valign=\"top\"; width=\"20%\";>Source</th></tr>"
        
            anomaliresults = len(anomalits)
        
            if anomaliresults > 0:
            
                j = 0
            
                while j < anomaliresults:
            
                    if url[i] == anomalits[j]['url']:
                    
                        confidence = anomalits[j]['Confidence']
                        severity = anomalits[j]['Severity']
                        itype = anomalits[j]['itype']
                        status = anomalits[j]['Status']
                        source = anomalits[j]['Source']
                    
                        j+=1
                
                        body_html_table = body_html_table + "<tr><td align=\"left\"; valign=\"top\";>" + str(confidence) + "</td><td align=\"left\"; valign=\"top\";>" + str(severity) + "</td><td align=\"left\"; valign=\"top\";>" + str(itype) + "</td><td align=\"left\"; valign=\"top\";>" + str(status) + "</td><td align=\"left\"; valign=\"top\";>" + str(source) + "</td></tr>"
        
                    else:
                        j+=1
            
                body_html_table = body_html_table + "</table></div><br>"
        
            else:
                confidence = ""
                severity = ""
                itype = ""
                status = ""
                source = ""
            
                body_html_table = body_html_table + "<tr><td align=\"left\"; valign=\"top\"; >" + str(confidence) + "</td><td align=\"left\"; valign=\"top\";>" + str(severity) + "</td><td align=\"left\"; valign=\"top\";>" + str(itype) + "</td><td align=\"left\"; valign=\"top\";>" + str(status) + "</td><td align=\"left\"; valign=\"top\";>" + str(source) + "</td></tr></table></div><br>"
            
            if len(virustotal)>0 and len(virustotal[i]) > 0:
                harmless = virustotal[i]['data']['attributes']['last_analysis_stats']['harmless']
                malicious = virustotal[i]['data']['attributes']['last_analysis_stats']['malicious']
                suspicious = virustotal[i]['data']['attributes']['last_analysis_stats']['suspicious']
                undetected = virustotal[i]['data']['attributes']['last_analysis_stats']['undetected']
                timeout = virustotal[i]['data']['attributes']['last_analysis_stats']['timeout']
                reputation = virustotal[i]['data']['reputation']
                Type = virustotal[i]['data']['type']
        
            else:
                harmless = ""
                malicious = ""
                suspicious = ""
                undetected = ""
                timeout = ""
                status = ""
                Type = ""
        
            #HTML Table VirusTotal Enrichment
            body_html_table = body_html_table + "<div style=\"overflow-x:auto;\"><table class=\"table1\"; style=\"font-family:arial; color:white; font-size: 12px;\"><tr><th colspan=\"3\";>VirusTotal</th></tr>"
        
            body_html_table = body_html_table + "<tr><th align=\"left\"; valign=\"top\"; width=\"20%\";>Last Analysis Stats</th><th align=\"left\"; valign=\"top\"; width=\"20%\";>Status</th><th align=\"left\"; valign=\"top\"; width=\"20%\";>Type</th></tr>"
        
            body_html_table = body_html_table + "<tr><td align=\"left\"; valign=\"top\";>" + "harmless: " + str(harmless) + " malicious: " + str(malicious) + " suspicious: " + str(suspicious) + " undetected: " + str(undetected) + " timeout: " + str(timeout) + "</td><td align=\"left\"; valign=\"top\";>" + str(status) + "</td><td align=\"left\"; valign=\"top\";>" + str(Type) +  "</td></tr></table></div><br>"
            
            i+=1
    
            if i == (urllength):
                #End the HTML content
                body_html_table = body_html_table + "</div></body></html>"
                
                returnData = body_html_table

            else:
                continue
    
    except Exception as ex:
        error = str(ex)
    
    if error == "":
        resultData = "Successful"
    else:
        resultData = "Failed"
    
    return resultData

anomalits
[
  {
    "Confidence": 0,
    "Severity": "high",
    "Created": "2023-04-26T23:06:10.075Z",
    "Modified": "2024-05-07T22:26:48.869Z",
    "itype": "phish_domain",
    "Source": "Mandiant - Indicators",
    "Status": "falsepos",
    "RiskScore": 0,
    "Reputation": 0.0,
    "ASN": "15169",
    "Country": "US",
    "Latitude": 37.751,
    "Longitude": -97.822,
    "Organization": "Google Servers",
    "IPAddress": "172.217.168.68",
    "Details": "imported by user 42060 Confirmed as false positive",
    "url": "www.google.com",
    "riskLevel": "1"
  }
]


virus
{
  "data": [
    {
      "id": "www.google.com",
      "type": "domain",
      "links": {
        "self": "https://www.virustotal.com/api/v3/domains/www.google.com"
      },
      "attributes": {
        "tags": [],
        "last_modification_date": 1716801185,
        "favicon": {
          "raw_md5": "d3c1e781578a47997a9e9c335baf61b6",
          "dhash": "71cc969aba96cc71"
        },
        "last_https_certificate": {
          "cert_signature": {
            "signature_algorithm": "sha256RSA",
            "signature": "2f46d72c71cbd4e6e19681ac66c928ae37d420341accf873341f4b415428817040f56cd976c92c145f3f6b2418559b68ace7b62557d190d4fc69273e9ded511217d2f3a2e8c61474c58b2cd869e40dc2596c08067e3513f5eb3b360a058835777205a245f1c73179370f1cec7d062023787153f086c719f56f9d9cd7ff8d8364a6bf101c530df09d69baadafdcf53737cbcf368febb896b2fb78974bb7b9bc536edd0e43dbc7bf16a7b583b475a89603fcfab2f97c1979e6f3d938e50c32b734bee8a521011f39cf1870ac215a504e02d366d6f1d90a1dd6c636055aab61491aef4974dd82f5a2cc0870d7c2baea7ad54f57b5b16812ea015d477da424595185"
          },
          "extensions": {
            "key_usage": [
              "digitalSignature"
            ],
            "extended_key_usage": [
              "serverAuth"
            ],
            "CA": false,
            "subject_key_identifier": "a5d1d3c2d5ed39371aa9ec5fa95d394d37de81d2",
            "authority_key_identifier": {
              "keyid": "8a747faf85cdee95cd3d9cd0e24614f371351d27"
            },
            "ca_information_access": {
              "OCSP": "http://ocsp.pki.goog/gts1c3",
              "CA Issuers": "http://pki.goog/repo/certs/gts1c3.der"
            },
            "subject_alternative_name": [
              "www.google.com"
            ],
            "certificate_policies": [
              "2.23.140.1.2.1",
              "1.3.6.1.4.1.11129.2.5.3"
            ],
            "crl_distribution_points": [
              "http://crls.pki.goog/gts1c3/QOvJ0N1sT2A.crl"
            ],
            "1.3.6.1.4.1.11129.2.4.2": "0481f200f0007600eecdd064d5db1acec55cb79db4cd13a23287467cbcecdec3"
          },
          "validity": {
            "not_after": "2024-07-29 14:44:49",
            "not_before": "2024-05-06 14:44:50"
          },
          "size": 1164,
          "version": "V3",
          "public_key": {
            "algorithm": "EC",
            "ec": {
              "oid": "secp256r1",
              "pub": "3059301306072a8648ce3d020106082a8648ce3d03010703420004c1dc1fdd25029fc752e2868425bfe64a551c393cd97a340b008356e6f02b82bac645cf67e3ea5866741178cedee83642aaa7c7cc1ea33f82753eff811979bdce"
            }
          },
          "thumbprint_sha256": "9f4533b0e8b04dbc50415f992db0219e2d6a66c230812ef940b403681accc8a5",
          "thumbprint": "835e48e259c5ebb86a08d75690a5f5184bc8b1df",
          "serial_number": "815c75bd499012c10a63e95edc4cd136",
          "issuer": {
            "C": "US",
            "O": "Google Trust Services LLC",
            "CN": "GTS CA 1C3"
          },
          "subject": {
            "CN": "www.google.com"
          }
        },
        "last_dns_records": [
          {
            "type": "AAAA",
            "ttl": 300,
            "value": "2a00:1450:4009:81e::2004"
          },
          {
            "type": "A",
            "ttl": 136,
            "value": "142.250.180.4"
          }
        ],
        "popularity_ranks": {
          "Cisco Umbrella": {
            "rank": 5,
            "timestamp": 1716717121
          }
        },
        "jarm": "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d",
        "categories": {},
        "last_analysis_date": 1716665530,
        "creation_date": 874306800,
        "registrar": "MarkMonitor Inc.",
        "total_votes": {
          "harmless": 77,
          "malicious": 17
        },
        "last_https_certificate_date": 1716665532,
        "last_analysis_results": {
          "Acronis": {
            "method": "blacklist",
            "engine_name": "Acronis",
            "category": "harmless",
            "result": "clean"
          },
          "0xSI_f33d": {
            "method": "blacklist",
            "engine_name": "0xSI_f33d",
            "category": "undetected",
            "result": "unrated"
          },
          "Abusix": {
            "method": "blacklist",
            "engine_name": "Abusix",
            "category": "harmless",
            "result": "clean"
          },
          "ADMINUSLabs": {
            "method": "blacklist",
            "engine_name": "ADMINUSLabs",
            "category": "harmless",
            "result": "clean"
          },
          "Criminal IP": {
            "method": "blacklist",
            "engine_name": "Criminal IP",
            "category": "harmless",
            "result": "clean"
          },
          "AILabs (MONITORAPP)": {
            "method": "blacklist",
            "engine_name": "AILabs (MONITORAPP)",
            "category": "harmless",
            "result": "clean"
          },
          "AlienVault": {
            "method": "blacklist",
            "engine_name": "AlienVault",
            "category": "harmless",
            "result": "clean"
          },
          "alphaMountain.ai": {
            "method": "blacklist",
            "engine_name": "alphaMountain.ai",
            "category": "harmless",
            "result": "clean"
          },
          "AlphaSOC": {
            "method": "blacklist",
            "engine_name": "AlphaSOC",
            "category": "undetected",
            "result": "unrated"
          },
          "Antiy-AVL": {
            "method": "blacklist",
            "engine_name": "Antiy-AVL",
            "category": "harmless",
            "result": "clean"
          },
          "ArcSight Threat Intelligence": {
            "method": "blacklist",
            "engine_name": "ArcSight Threat Intelligence",
            "category": "suspicious",
            "result": "suspicious"
          },
          "AutoShun": {
            "method": "blacklist",
            "engine_name": "AutoShun",
            "category": "undetected",
            "result": "unrated"
          },
          "benkow.cc": {
            "method": "blacklist",
            "engine_name": "benkow.cc",
            "category": "harmless",
            "result": "clean"
          },
          "Bfore.Ai PreCrime": {
            "method": "blacklist",
            "engine_name": "Bfore.Ai PreCrime",
            "category": "undetected",
            "result": "unrated"
          },
          "BitDefender": {
            "method": "blacklist",
            "engine_name": "BitDefender",
            "category": "harmless",
            "result": "clean"
          },
          "Bkav": {
            "method": "blacklist",
            "engine_name": "Bkav",
            "category": "undetected",
            "result": "unrated"
          },
          "Blueliv": {
            "method": "blacklist",
            "engine_name": "Blueliv",
            "category": "harmless",
            "result": "clean"
          },
          "Certego": {
            "method": "blacklist",
            "engine_name": "Certego",
            "category": "harmless",
            "result": "clean"
          },
          "Chong Lua Dao": {
            "method": "blacklist",
            "engine_name": "Chong Lua Dao",
            "category": "harmless",
            "result": "clean"
          },
          "CINS Army": {
            "method": "blacklist",
            "engine_name": "CINS Army",
            "category": "harmless",
            "result": "clean"
          },
          "Cluster25": {
            "method": "blacklist",
            "engine_name": "Cluster25",
            "category": "undetected",
            "result": "unrated"
          },
          "CRDF": {
            "method": "blacklist",
            "engine_name": "CRDF",
            "category": "harmless",
            "result": "clean"
          },
          "CSIS Security Group": {
            "method": "blacklist",
            "engine_name": "CSIS Security Group",
            "category": "undetected",
            "result": "unrated"
          },
          "Snort IP sample list": {
            "method": "blacklist",
            "engine_name": "Snort IP sample list",
            "category": "harmless",
            "result": "clean"
          },
          "CMC Threat Intelligence": {
            "method": "blacklist",
            "engine_name": "CMC Threat Intelligence",
            "category": "harmless",
            "result": "clean"
          },
          "Cyan": {
            "method": "blacklist",
            "engine_name": "Cyan",
            "category": "undetected",
            "result": "unrated"
          },
          "Cyble": {
            "method": "blacklist",
            "engine_name": "Cyble",
            "category": "harmless",
            "result": "clean"
          },
          "CyRadar": {
            "method": "blacklist",
            "engine_name": "CyRadar",
            "category": "harmless",
            "result": "clean"
          },
          "DNS8": {
            "method": "blacklist",
            "engine_name": "DNS8",
            "category": "harmless",
            "result": "clean"
          },
          "Dr.Web": {
            "method": "blacklist",
            "engine_name": "Dr.Web",
            "category": "harmless",
            "result": "clean"
          },
          "Ermes": {
            "method": "blacklist",
            "engine_name": "Ermes",
            "category": "undetected",
            "result": "unrated"
          },
          "ESET": {
            "method": "blacklist",
            "engine_name": "ESET",
            "category": "harmless",
            "result": "clean"
          },
          "ESTsecurity": {
            "method": "blacklist",
            "engine_name": "ESTsecurity",
            "category": "harmless",
            "result": "clean"
          },
          "EmergingThreats": {
            "method": "blacklist",
            "engine_name": "EmergingThreats",
            "category": "harmless",
            "result": "clean"
          },
          "Emsisoft": {
            "method": "blacklist",
            "engine_name": "Emsisoft",
            "category": "harmless",
            "result": "clean"
          },
          "Forcepoint ThreatSeeker": {
            "method": "blacklist",
            "engine_name": "Forcepoint ThreatSeeker",
            "category": "harmless",
            "result": "clean"
          },
          "Fortinet": {
            "method": "blacklist",
            "engine_name": "Fortinet",
            "category": "harmless",
            "result": "clean"
          },
          "G-Data": {
            "method": "blacklist",
            "engine_name": "G-Data",
            "category": "harmless",
            "result": "clean"
          },
          "Google Safebrowsing": {
            "method": "blacklist",
            "engine_name": "Google Safebrowsing",
            "category": "harmless",
            "result": "clean"
          },
          "GreenSnow": {
            "method": "blacklist",
            "engine_name": "GreenSnow",
            "category": "harmless",
            "result": "clean"
          },
          "Gridinsoft": {
            "method": "blacklist",
            "engine_name": "Gridinsoft",
            "category": "undetected",
            "result": "unrated"
          },
          "Heimdal Security": {
            "method": "blacklist",
            "engine_name": "Heimdal Security",
            "category": "harmless",
            "result": "clean"
          },
          "Hunt.io Intelligence": {
            "method": "blacklist",
            "engine_name": "Hunt.io Intelligence",
            "category": "undetected",
            "result": "unrated"
          },
          "IPsum": {
            "method": "blacklist",
            "engine_name": "IPsum",
            "category": "harmless",
            "result": "clean"
          },
          "Juniper Networks": {
            "method": "blacklist",
            "engine_name": "Juniper Networks",
            "category": "harmless",
            "result": "clean"
          },
          "K7AntiVirus": {
            "method": "blacklist",
            "engine_name": "K7AntiVirus",
            "category": "harmless",
            "result": "clean"
          },
          "Kaspersky": {
            "method": "blacklist",
            "engine_name": "Kaspersky",
            "category": "harmless",
            "result": "clean"
          },
          "Lionic": {
            "method": "blacklist",
            "engine_name": "Lionic",
            "category": "harmless",
            "result": "clean"
          },
          "Lumu": {
            "method": "blacklist",
            "engine_name": "Lumu",
            "category": "undetected",
            "result": "unrated"
          },
          "MalwarePatrol": {
            "method": "blacklist",
            "engine_name": "MalwarePatrol",
            "category": "harmless",
            "result": "clean"
          },
          "MalwareURL": {
            "method": "blacklist",
            "engine_name": "MalwareURL",
            "category": "undetected",
            "result": "unrated"
          },
          "Malwared": {
            "method": "blacklist",
            "engine_name": "Malwared",
            "category": "harmless",
            "result": "clean"
          },
          "Netcraft": {
            "method": "blacklist",
            "engine_name": "Netcraft",
            "category": "undetected",
            "result": "unrated"
          },
          "OpenPhish": {
            "method": "blacklist",
            "engine_name": "OpenPhish",
            "category": "harmless",
            "result": "clean"
          },
          "Phishing Database": {
            "method": "blacklist",
            "engine_name": "Phishing Database",
            "category": "harmless",
            "result": "clean"
          },
          "PhishFort": {
            "method": "blacklist",
            "engine_name": "PhishFort",
            "category": "undetected",
            "result": "unrated"
          },
          "PhishLabs": {
            "method": "blacklist",
            "engine_name": "PhishLabs",
            "category": "undetected",
            "result": "unrated"
          },
          "Phishtank": {
            "method": "blacklist",
            "engine_name": "Phishtank",
            "category": "harmless",
            "result": "clean"
          },
          "PREBYTES": {
            "method": "blacklist",
            "engine_name": "PREBYTES",
            "category": "harmless",
            "result": "clean"
          },
          "PrecisionSec": {
            "method": "blacklist",
            "engine_name": "PrecisionSec",
            "category": "undetected",
            "result": "unrated"
          },
          "Quick Heal": {
            "method": "blacklist",
            "engine_name": "Quick Heal",
            "category": "harmless",
            "result": "clean"
          },
          "Quttera": {
            "method": "blacklist",
            "engine_name": "Quttera",
            "category": "harmless",
            "result": "clean"
          },
          "SafeToOpen": {
            "method": "blacklist",
            "engine_name": "SafeToOpen",
            "category": "undetected",
            "result": "unrated"
          },
          "Sansec eComscan": {
            "method": "blacklist",
            "engine_name": "Sansec eComscan",
            "category": "undetected",
            "result": "unrated"
          },
          "Scantitan": {
            "method": "blacklist",
            "engine_name": "Scantitan",
            "category": "harmless",
            "result": "clean"
          },
          "SCUMWARE.org": {
            "method": "blacklist",
            "engine_name": "SCUMWARE.org",
            "category": "harmless",
            "result": "clean"
          },
          "Seclookup": {
            "method": "blacklist",
            "engine_name": "Seclookup",
            "category": "harmless",
            "result": "clean"
          },
          "SecureBrain": {
            "method": "blacklist",
            "engine_name": "SecureBrain",
            "category": "harmless",
            "result": "clean"
          },
          "Segasec": {
            "method": "blacklist",
            "engine_name": "Segasec",
            "category": "harmless",
            "result": "clean"
          },
          "SOCRadar": {
            "method": "blacklist",
            "engine_name": "SOCRadar",
            "category": "harmless",
            "result": "clean"
          },
          "Sophos": {
            "method": "blacklist",
            "engine_name": "Sophos",
            "category": "harmless",
            "result": "clean"
          },
          "Spam404": {
            "method": "blacklist",
            "engine_name": "Spam404",
            "category": "harmless",
            "result": "clean"
          },
          "StopForumSpam": {
            "method": "blacklist",
            "engine_name": "StopForumSpam",
            "category": "harmless",
            "result": "clean"
          },
          "Sucuri SiteCheck": {
            "method": "blacklist",
            "engine_name": "Sucuri SiteCheck",
            "category": "harmless",
            "result": "clean"
          },
          "ThreatHive": {
            "method": "blacklist",
            "engine_name": "ThreatHive",
            "category": "harmless",
            "result": "clean"
          },
          "Threatsourcing": {
            "method": "blacklist",
            "engine_name": "Threatsourcing",
            "category": "harmless",
            "result": "clean"
          },
          "Trustwave": {
            "method": "blacklist",
            "engine_name": "Trustwave",
            "category": "harmless",
            "result": "clean"
          },
          "Underworld": {
            "method": "blacklist",
            "engine_name": "Underworld",
            "category": "undetected",
            "result": "unrated"
          },
          "URLhaus": {
            "method": "blacklist",
            "engine_name": "URLhaus",
            "category": "harmless",
            "result": "clean"
          },
          "URLQuery": {
            "method": "blacklist",
            "engine_name": "URLQuery",
            "category": "harmless",
            "result": "clean"
          },
          "Viettel Threat Intelligence": {
            "method": "blacklist",
            "engine_name": "Viettel Threat Intelligence",
            "category": "harmless",
            "result": "clean"
          },
          "VIPRE": {
            "method": "blacklist",
            "engine_name": "VIPRE",
            "category": "undetected",
            "result": "unrated"
          },
          "VX Vault": {
            "method": "blacklist",
            "engine_name": "VX Vault",
            "category": "harmless",
            "result": "clean"
          },
          "ViriBack": {
            "method": "blacklist",
            "engine_name": "ViriBack",
            "category": "harmless",
            "result": "clean"
          },
          "Webroot": {
            "method": "blacklist",
            "engine_name": "Webroot",
            "category": "harmless",
            "result": "clean"
          },
          "Yandex Safebrowsing": {
            "method": "blacklist",
            "engine_name": "Yandex Safebrowsing",
            "category": "harmless",
            "result": "clean"
          },
          "ZeroCERT": {
            "method": "blacklist",
            "engine_name": "ZeroCERT",
            "category": "harmless",
            "result": "clean"
          },
          "desenmascara.me": {
            "method": "blacklist",
            "engine_name": "desenmascara.me",
            "category": "harmless",
            "result": "clean"
          },
          "malwares.com URL checker": {
            "method": "blacklist",
            "engine_name": "malwares.com URL checker",
            "category": "harmless",
            "result": "clean"
          },
          "securolytics": {
            "method": "blacklist",
            "engine_name": "securolytics",
            "category": "harmless",
            "result": "clean"
          },
          "Xcitium Verdict Cloud": {
            "method": "blacklist",
            "engine_name": "Xcitium Verdict Cloud",
            "category": "harmless",
            "result": "clean"
          },
          "zvelo": {
            "method": "blacklist",
            "engine_name": "zvelo",
            "category": "undetected",
            "result": "unrated"
          },
          "ZeroFox": {
            "method": "blacklist",
            "engine_name": "ZeroFox",
            "category": "undetected",
            "result": "unrated"
          }
        },
        "reputation": 198,
        "whois": "Admin Country: US\nAdmin Organization: Google LLC\nAdmin State/Province: CA\nCreation Date: 1997-09-15T04:00:00Z\nCreation Date: 1997-09-15T07:00:00+0000\nDNSSEC: unsigned\nDomain Name: GOOGLE.COM\nDomain Name: google.com\nDomain Status: clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)\nDomain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\nDomain Status: clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)\nDomain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\nDomain Status: clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)\nDomain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited\nDomain Status: serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)\nDomain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited\nDomain Status: serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)\nDomain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited\nDomain Status: serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)\nDomain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited\nName Server: NS1.GOOGLE.COM\nName Server: NS2.GOOGLE.COM\nName Server: NS3.GOOGLE.COM\nName Server: NS4.GOOGLE.COM\nName Server: ns1.google.com\nName Server: ns2.google.com\nName Server: ns3.google.com\nName Server: ns4.google.com\nRegistrant Country: US\nRegistrant Email: ca4484b9e50182bds@\nRegistrant Organization: 3307059bbb3149c4\nRegistrant State/Province: b1952dfc047df18a\nRegistrar Abuse Contact Email: abusecomplaints@markmonitor.com\nRegistrar Abuse Contact Phone: +1.2086851750\nRegistrar IANA ID: 292\nRegistrar Registration Expiration Date: 2028-09-13T07:00:00+0000\nRegistrar URL: http://www.markmonitor.com\nRegistrar WHOIS Server: whois.markmonitor.com\nRegistrar: MarkMonitor Inc.\nRegistrar: MarkMonitor, Inc.\nRegistry Domain ID: 2138514_DOMAIN_COM-VRSN\nRegistry Expiry Date: 2028-09-14T04:00:00Z\nTech Country: US\nTech Organization: Google LLC\nTech State/Province: CA\nUpdated Date: 2019-09-09T15:39:04+0000\nUpdated Date: 2019-09-09T15:39:04Z",
        "last_analysis_stats": {
          "malicious": 0,
          "suspicious": 1,
          "undetected": 23,
          "harmless": 69,
          "timeout": 0
        },
        "last_update_date": 1568043544,
        "tld": "com",
        "threat_severity": {
          "version": "D3",
          "threat_severity_level": "SEVERITY_NONE",
          "threat_severity_data": {
            "has_bad_communicating_files_high": true,
            "has_bad_communicating_files_medium": true,
            "has_bad_downloaded_files_medium": true,
            "belongs_to_bad_collection": true,
            "domain_rank": "3"
          },
          "last_analysis_date": "1716595213",
          "level_description": "Severity NONE because it has no detections."
        },
        "last_dns_records_date": 1716665532
      },
      "context_attributes": {
        "detected_communicating_files_count": 100,
        "referring_files_max_detections": 58,
        "detected_downloaded_files_count": 100,
        "detected_referring_files_count": 100,
        "detected_urls_count": 100,
        "communicating_files_max_detections": 67,
        "downloaded_files_max_detections": 38,
        "urls_max_detections": 3
      }
    }
  ],
  "meta": {
    "total_hits": 5,
    "allowed_orders": [
      "creation_date",
      "last_modification_date",
      "last_update_date",
      "positives"
    ],
    "days_back": 90
  },
  "links": {
    "self": "https://www.virustotal.com/api/v3/intelligence/search?query=entity:domain+domain_regex:www.google.com&descriptors_only=false"
  }
}


  url
  ["www.google.com"]


