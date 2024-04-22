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



