let currentScanDomain = null;
let statusInterval = null;
let scanResults = {};

document.addEventListener('DOMContentLoaded', function() {
    console.log('CyberScan Pro initialized');
    
    document.getElementById('scan-form').addEventListener('submit', function(e) {
        e.preventDefault();
        startScan();
    });

    document.getElementById('stop-button').addEventListener('click', function() {
        stopScan();
    });

    document.getElementById('download-results').addEventListener('click', function(e) {
        e.preventDefault();
        if (currentScanDomain) {
            window.location.href = `/download_results/${currentScanDomain}`;
        } else {
            addLogMessage('No scan results available to download', 'error');
        }
    });
});

function updateStats(data) {
    const results = data.scan_results || {};
    
    // Update stats counters
    document.getElementById('stat-subdomains').textContent = 
        results.subdomains ? results.subdomains.length : 0;
    document.getElementById('stat-ports').textContent = 
        results.ports ? results.ports.length : 0;
    document.getElementById('stat-urls').textContent = 
        results.directory_scan ? results.directory_scan.found_urls.length : 0;
    document.getElementById('stat-vulns').textContent = 
        results.vulnerabilities ? results.vulnerabilities.length : 0;
}

function setButtonStates(scanning, completed) {
    const scanBtn = document.getElementById('scan-button');
    const stopBtn = document.getElementById('stop-button');
    const downloadBtn = document.getElementById('download-results');
    
    if (scanning) {
        scanBtn.disabled = true;
        stopBtn.disabled = false;
        downloadBtn.disabled = false;
    } else if (completed) {
        scanBtn.disabled = false;
        stopBtn.disabled = true;
        downloadBtn.disabled = false;
    } else {
        // Ready state
        scanBtn.disabled = false;
        stopBtn.disabled = true;
        downloadBtn.disabled = false;
    }
}

function startScan() {
    const domain = document.getElementById('domain').value.trim();
    if (!domain) {
        alert('Please enter a domain to scan');
        return;
    }

    if (!/^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/i.test(domain)) {
        alert('Please enter a valid domain name (e.g., example.com)');
        return;
    }

    clearAllSections();
    addLogMessage(`Starting scan for ${domain}`, 'info');

    // Set button states
    setButtonStates(true, false);
    
    document.getElementById('status-text').innerHTML = '<i class="bi bi-hourglass"></i> Initializing scan...';
    document.getElementById('global-status').querySelector('span:last-child').textContent = 'Scanning';

    fetch('/start_scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ domain: domain })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        if (data.error) {
            addLogMessage(data.error, 'error');
            setButtonStates(false, false);
            document.getElementById('global-status').querySelector('span:last-child').textContent = 'Error';
            return;
        }

        currentScanDomain = data.domain;
        if (statusInterval) clearInterval(statusInterval);
        statusInterval = setInterval(updateScanStatus, 1500);
    })
    .catch(error => {
        addLogMessage('Error starting scan: ' + error.message, 'error');
        setButtonStates(false, false);
        document.getElementById('status-text').innerHTML = '<i class="bi bi-exclamation-triangle"></i> Scan failed to start';
        document.getElementById('global-status').querySelector('span:last-child').textContent = 'Error';
    });
}

function updateScanStatus() {
    if (!currentScanDomain) return;

    fetch(`/scan_status/${currentScanDomain}`)
    .then(response => {
        if (!response.ok) {
            throw new Error('Failed to get scan status');
        }
        return response.json();
    })
    .then(data => {
        if (data.error) {
            addLogMessage(data.error, 'error');
            clearInterval(statusInterval);
            document.getElementById('global-status').querySelector('span:last-child').textContent = 'Error';
            setButtonStates(false, false);
            return;
        }

        // Update progress
        document.getElementById('progress-bar').style.width = `${data.progress}%`;
        document.getElementById('progress-text').textContent = `${data.progress}%`;
        
        // Update status text
        let statusIcon, statusText;
        if (data.active) {
            statusIcon = '<i class="bi bi-activity"></i>';
            statusText = 'Scan in progress...';
            setButtonStates(true, false);
            document.getElementById('scan-button').disabled=true ;
            document.getElementById('stop-button').disabled=false ;

        } else {
            statusIcon = '<i class="bi bi-check-circle"></i>';
            statusText = 'Scan completed';
            setButtonStates(false, data.progress === 100);
            clearInterval(statusInterval);
            document.getElementById('scan-button').disabled=false ;
            document.getElementById('stop-button').disabled=true ;
        }
        
        document.getElementById('status-text').innerHTML = `${statusIcon} ${statusText}`;
        document.getElementById('global-status').querySelector('span:last-child').textContent = 
            data.active ? 'Scanning' : (data.progress === 100 ? 'Completed' : 'Stopped');

        // Update all sections with the latest data
        updateAllSections(data);
        updateStats(data);

        // Update logs
        if (data.log_messages && data.log_messages.length > 0) {
            updateLogs(data.log_messages);
        }
    })
    .catch(error => {
        console.error('Error updating scan status:', error);
        addLogMessage('Error getting scan status: ' + error.message, 'error');
        document.getElementById('global-status').querySelector('span:last-child').textContent = 'Error';
        setButtonStates(false, false);
    });
}

function stopScan() {
    if (!currentScanDomain) return;

    addLogMessage(`Stopping scan for ${currentScanDomain}`, 'warning');
    document.getElementById('stop-button').disabled = true;

    fetch(`/stop_scan/${currentScanDomain}`)
    .then(response => {
        if (!response.ok) {
            throw new Error('Failed to stop scan');
        }
        return response.json();
    })
    .then(data => {
        addLogMessage(data.message, 'warning');
        setButtonStates(false, document.getElementById('progress-bar').style.width !== '0%');
        document.getElementById('status-text').innerHTML = '<i class="bi bi-pause-fill"></i> Scan stopped by user';
        document.getElementById('global-status').querySelector('span:last-child').textContent = 'Stopped';
    })
    .catch(error => {
        addLogMessage('Error stopping scan: ' + error.message, 'error');
        document.getElementById('stop-button').disabled = false;
    });
}

function updateAllSections(data) {
    const results = data.scan_results || {};
    
    // Update Overview tab
    if (results.whois) {
        updateDomainInfo(results.whois);
    }
    if (results.geolocation) {
        updateGeoInfo(results.geolocation);
    }
    if (results.ssl) {
        updateSSLInfo(results.ssl);
    }
    if (results.subdomains) {
        updateSubdomains(results.subdomains);
    }

    // Update WHOIS tab
    if (results.whois) {
        updateKeyValueTable('whois-table', results.whois);
    }

    // Update DNS tab
    if (results.dns) {
        updateList('dns-list', results.dns);
    }

    // Update Ports tab
    if (results.ports) {
        updatePortsList(results.ports);
    }
    if (results.os_detection) {
        updateOSDetection(results.os_detection);
    }
    if (results.vulnerabilities) {
        updateVulnerabilities(results.vulnerabilities);
    }

    // Update URLs tab
    if (results.directory_scan && results.directory_scan.found_urls) {
        updateUrlResults(results.directory_scan.found_urls);
    }
}

function updatePortsList(ports) {
    const list = document.getElementById('ports-list');
    list.innerHTML = '';
    
    if (!ports || ports.length === 0) {
        list.innerHTML = '<li class="list-group-item ">No open ports found</li>';
        return;
    }

    // Filter out duplicates
    const uniquePorts = ports.reduce((acc, current) => {
        const x = acc.find(item => item.port === current.port);
        if (!x) {
            return acc.concat([current]);
        } else {
            return acc;
        }
    }, []);

    uniquePorts.forEach(port => {
        const li = document.createElement('li');
        li.className = 'list-group-item';
        
        if (typeof port === 'object') {
            let portInfo = `<strong>Port ${port.port}</strong>`;
            if (port.protocol) portInfo += `/${port.protocol}`;
            if (port.service) portInfo += ` (${port.service})`;
            if (port.name) portInfo += `: ${port.name}`;
            if (port.product) portInfo += ` - ${port.product}`;
            if (port.version) portInfo += ` ${port.version}`;
            if (port.extrainfo) portInfo += ` (${port.extrainfo})`;
            
            li.innerHTML = portInfo;
        } else {
            li.textContent = port;
        }
        list.appendChild(li);
    });
}

function updateVulnerabilities(vulns) {
    const list = document.getElementById('vulns-list');
    list.innerHTML = '';
    
    if (!vulns || vulns.length === 0) {
        list.innerHTML = '<li class="list-group-item ">No vulnerabilities found</li>';
        return;
    }

    vulns.forEach(vuln => {
        const li = document.createElement('li');
        li.className = 'list-group-item text-danger';
        
        if (typeof vuln === 'string') {
            li.textContent = vuln;
        } else if (vuln.id && vuln.output) {
            li.innerHTML = `<strong>${vuln.id}</strong>: ${vuln.output.substring(0, 100)}...`;
        } else if (vuln.name && vuln.description) {
            li.innerHTML = `<strong>${vuln.name}</strong>: ${vuln.description.substring(0, 100)}...`;
        } else {
            li.textContent = JSON.stringify(vuln);
        }
        
        list.appendChild(li);
    });
}

function updateUrlResults(urls) {
    const urls200 = urls.filter(u => u.status === 200);
    const urls403 = urls.filter(u => u.status === 403);
    const urlsOther = urls.filter(u => u.status !== 200 && u.status !== 403);

    updateUrlContainer('urls-200-container', urls200);
    updateUrlContainer('urls-403-container', urls403);
    updateUrlContainer('urls-other-container', urlsOther);
}

function updateOSDetection(osInfo) {
    const container = document.getElementById('os-detection-info');
    container.innerHTML = '';
    
    if (!osInfo || Object.keys(osInfo).length === 0) {
        container.innerHTML = '<p>OS detection not performed or inconclusive</p>';
        return;
    }
    
    container.innerHTML = `
        <div class="alert alert-info bg-dark border-info">
            <strong>Detected OS:</strong> ${osInfo.os_name || 'Unknown'}<br>
            <strong>Confidence:</strong> ${osInfo.accuracy || 'Unknown'}
        </div>
    `;
}

function updateDomainInfo(info) {
    const container = document.getElementById('domain-info');
    container.innerHTML = Object.entries(info).map(([key, val]) => `<p><strong>${key}:</strong> ${val}</p>`).join('');
}

function updateGeoInfo(info) {
    const container = document.getElementById('geo-info');
    container.innerHTML = Object.entries(info).map(([key, val]) => `<p><strong>${key}:</strong> ${val}</p>`).join('');
}

function updateSSLInfo(info) {
    const container = document.getElementById('ssl-info');
    container.innerHTML = Object.entries(info).map(([key, val]) => `<p><strong>${key}:</strong> ${val}</p>`).join('');
}

function updateSubdomains(subs) {
    const container = document.getElementById('subdomains-info');
    if (!subs || subs.length === 0) {
        container.innerHTML = '<p>No subdomains found</p>';
    } else {
        container.innerHTML = subs.map(sub => `<p class="terminal-effect">${sub}</p>`).join('');
    }
}

function updateKeyValueTable(tableId, data) {
    const table = document.getElementById(tableId).querySelector('tbody');
    table.innerHTML = '';
    
    if (typeof data === 'object' && data !== null) {
        for (const [key, val] of Object.entries(data)) {
            const row = document.createElement('tr');
            row.innerHTML = `<td>${key}</td><td>${val || 'N/A'}</td>`;
            table.appendChild(row);
        }
    } else {
        table.innerHTML = '<tr><td colspan="2">No WHOIS data available</td></tr>';
    }
}

function updateList(listId, items) {
    const list = document.getElementById(listId);
    list.innerHTML = '';
    if (items && items.length > 0) {
        items.forEach(item => {
            const li = document.createElement('li');
            li.className = 'list-group-item terminal-effect';
            li.textContent = item;
            list.appendChild(li);
        });
    } else {
        list.innerHTML = '<li class="list-group-item text-muted">No data</li>';
    }
}

function updateUrlContainer(containerId, urls) {
    const container = document.getElementById(containerId);
    container.innerHTML = '';

    if (!urls || urls.length === 0) {
        container.innerHTML = '<p>No URLs found</p>';
        return;
    }

    urls.forEach(url => {
        const div = document.createElement('div');
        div.className = `url-item url-${url.status}`;
        
        const link = document.createElement('a');
        link.href = url.url;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.textContent = `[${url.status}] ${url.url}`;
        
        div.appendChild(link);
        container.appendChild(div);
    });
}

function updateLogs(logMessages) {
    const container = document.getElementById('logs-container');
    if (!container) return;
    
    // Remove auto-scroll behavior completely
    container.innerHTML = '';
    
    if (!logMessages || logMessages.length === 0) {
        container.innerHTML = '<p class="text-muted">No logs yet</p>';
        return;
    }
    
    logMessages.forEach(log => {
        const logEntry = document.createElement('div');
        logEntry.className = `log-entry log-${log.level || 'info'}`;
        logEntry.innerHTML = `
            <small class="text-muted">${log.timestamp}</small>
            <div>${log.message}</div>
        `;
        container.appendChild(logEntry);
    });
}

function addLogMessage(message, level = 'info') {
    const now = new Date();
    const timestamp = now.toLocaleTimeString();
    const container = document.getElementById('logs-container');

    // Check if container exists (might not be loaded yet)
    if (!container) return;

    const div = document.createElement('div');
    div.className = `log-entry log-${level}`;
    div.innerHTML = `<small class="text-muted">[${timestamp}]</small> ${message}`;
    container.appendChild(div);
}

function clearAllSections() {
    const sections = ['domain-info', 'geo-info', 'ssl-info', 'subdomains-info'];
    sections.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.innerHTML = '<p class="text-muted">Scan not started</p>';
    });

    ['whois-table', 'dns-list', 'ports-list'].forEach(id => {
        const el = document.getElementById(id);
        if (!el) return;
        
        if (el.tagName === 'TABLE') {
            const tbody = el.querySelector('tbody');
            if (tbody) tbody.innerHTML = '<tr><td colspan="2" class="text-muted">Scan not started</td></tr>';
        } else {
            el.innerHTML = '<li class="list-group-item text-muted">Scan not started</li>';
        }
    });

    ['urls-200-container', 'urls-403-container', 'urls-other-container'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.innerHTML = '<p>No URLs found yet</p>';
    });

    const logsContainer = document.getElementById('logs-container');
    if (logsContainer) logsContainer.innerHTML = '<p class="text-muted">No logs yet</p>';

    document.getElementById('progress-bar').style.width = '0%';
    document.getElementById('progress-text').textContent = '0%';
    document.getElementById('status-text').innerHTML = '<i class="bi bi-info-circle"></i> Ready to scan';
    
    // Reset stats
    ['stat-subdomains', 'stat-ports', 'stat-urls', 'stat-vulns'].forEach(id => {
        document.getElementById(id).textContent = '0';
    });
}