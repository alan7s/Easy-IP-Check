async function checkIP() {
    const ipInput = document.getElementById('ipInput');
    const vtContainer = document.getElementById('vtContainer');
    const shodanContainer = document.getElementById('shodanContainer');

    // Gerenciamento API VirusTotal
    let virusTotalApiKey = localStorage.getItem('virusTotalApiKey');
    if (!virusTotalApiKey) {
        virusTotalApiKey = prompt('Please enter your VirusTotal API key:');
        localStorage.setItem('virusTotalApiKey', virusTotalApiKey);
    }

    // Gerenciamento API Shodan
    let shodanApiKey = localStorage.getItem('shodanApiKey');
    if (!shodanApiKey) {
        shodanApiKey = prompt('Please enter your Shodan API key:');
        localStorage.setItem('shodanApiKey', shodanApiKey);
    }

    // Confere entrada usuário
    const ipRegex = /^(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4})?|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){0,1}:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){0,2}:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){0,3}:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9a-fA-F]{1,4}:){1,1}(?::[0-9a-fA-F]{1,4}){0,4}:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|:(?::[0-9a-fA-F]{1,4}){0,6}:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9a-fA-F]{1,4}:){0,1}(?::[0-9a-fA-F]{1,4}){0,5}:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|:(?::[0-9a-fA-F]{1,4}){1,7}|[0-9a-fA-F]{1,4}:((?::[0-9a-fA-F]{1,4}){0,5}:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|:)|:(?::[0-9a-fA-F]{1,4}){0,6}:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?::[0-9a-fA-F]{1,4}){2,7})$/;

    if (!ipInput.value || !ipRegex.test(ipInput.value)) {
        alert('Please enter a valid IP address.');
        return;
    }

    try {
        vtContainer.innerHTML = '<p><strong>Requesting VirusTotal...</strong></p>';
        shodanContainer.innerHTML = '<p><strong>Requesting Shodan...</strong></p>';

        // Consulta a API do VirusTotal
        const virusTotalResponse = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ipInput.value}`, {
            headers: {
                'x-apikey': virusTotalApiKey,
            },
        });

        if (virusTotalResponse.ok) {
            const virusTotalData = await virusTotalResponse.json();

            // Calcula o total de vendors do VirusTotal
            const totalVendors = Object.keys(virusTotalData.data.attributes.last_analysis_results).length;

            // Exibe o resultado do VirusTotal na página com botão de acesso
            vtContainer.innerHTML = `<p><strong>VirusTotal scan:</strong> <a href="https://www.virustotal.com/gui/ip-address/${ipInput.value}" target="_blank">${virusTotalData.data.attributes.last_analysis_stats.malicious}/${totalVendors}</a> security vendors flagged that IP address.</p>`;
        } else {
            const errorData = await virusTotalResponse.json();
            console.error('Error when requesting the VirusTotal API:', errorData.error.message);
            vtContainer.innerHTML = `<p><strong>VirusTotal scan:</strong>${errorData.error.message}</p>`;
        }

        // Consulta a API do Shodan
        const shodanResponse = await fetch(`https://api.shodan.io/shodan/host/${ipInput.value}?key=${shodanApiKey}`);

        if (shodanResponse.ok) {
            const shodanData = await shodanResponse.json();
            if (shodanData.domains.length > 3) {
                const first3domains = shodanData.domains.slice(0, 4); // Limita a 3 domains o resultado
                first3domains[3] = ` <a href="https://www.shodan.io/host/${ipInput.value}" target="_blank">and others</a>`;
                shodanData.domains = first3domains;
            }
            // Exibe o resultado do Shodan na página com botão de acesso
            if (shodanData.vulns) {
                shodanContainer.innerHTML = `<p><strong>Shodan scan:</strong> <ul><li>Organization: ${shodanData.org}</li><li>Domains: ${shodanData.domains}</li><li>Ports: ${shodanData.ports}</li><li>Vulnerabilities: <a href="https://www.shodan.io/host/${ipInput.value}" target="_blank">${shodanData.vulns.length}</a></li></ul></p>`;
            } else {
                shodanContainer.innerHTML = `<p><strong>Shodan scan:</strong> <ul><li>Organization: ${shodanData.org}</li><li>Domains: ${shodanData.domains}</li><li>Ports: ${shodanData.ports}</li><li>Vulnerabilities: <a href="https://www.shodan.io/host/${ipInput.value}" target="_blank">0</a></li></ul></p>`;
            }
        } else {
            const errorData = await shodanResponse.json();
            console.error('Error when requesting the Shodan API:', errorData.error);
            shodanContainer.innerHTML = `<p><strong>Shodan scan:</strong> ${errorData.error}</p>`;
        }

    } catch (error) {
        console.error('Error when requesting APIs:', error);
        vtContainer.innerHTML = '<p>An error occurred while processing the request. Try again later.</p>';
    }
}

function clearAPIKeys() {
    localStorage.removeItem('virusTotalApiKey');
    localStorage.removeItem('shodanApiKey');
    alert('API keys have been removed. Please enter again when querying.');
}