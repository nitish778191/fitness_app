def enrichment_python(input_value):
    
    rawData = ""
    resultData = ""
    returnData = ""
    keyFields = ""
    contextData = ""
    error = ""
    artifacttype=""
    artifactvalue=input_value
    
    patterns =   {
                    
                    'domain': r'^(?!-)[A-Za-z0-9-]+([\\-\\.]{1}[a-z0-9]+)*\\.[A-Za-z]{2,6}$',
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
                    'hash': r'^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$'  }
                      
    
    
    
    for indicator, pattern in patterns.items():
        if re.match(pattern, input_value,re.IGNORECASE):
            returnData=indicator
            artifacttype=indicator
            
            break
        else:
            returnData=""
   
   
    contextData=[{
                      "artifactType":artifacttype ,
                      "artifactValue":artifactvalue
                  } ]

# Example usage:
# print("URL Valid:", validate("https://www.example.com", "url"))
# print("Domain Valid:", validate("example.com", "domain"))
# print("IP Valid:", validate("192.168.0.1", "ip"))
# print("Hash Valid:", validate("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", "hash"))

    # input_value=input()
    
    # if validate(input_value,"url"):
    #     returnData="URL"
    # elif(input_value,"domain"):
    #     returnData="Domain"
    # elif(input_value,"IP"):
    #     returnData="IP"
    # elif(input_value,"hash"):
    #     returnData="Hash"
    # else:
    #     returnData=""
    

    


    
    
    
    return pb.returnOutputModel(resultData, returnData, keyFields, contextData, rawData, error)
    
    
    
    
    



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



