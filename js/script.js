async function checkIP() {
    const ipInput = document.getElementById('ipInput');
    const vtContainer = document.getElementById('vtContainer');
    const shodanContainer = document.getElementById('shodanContainer');
    const virusTotalApiKey = 'YOUR-API-KEY';
    const shodanApiKey = 'YOUR-API-KEY';

    // Confere entrada usuário
    const ipRegex = /^(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4})?|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){0,1}:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){0,2}:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){0,3}:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9a-fA-F]{1,4}:){1,1}(?::[0-9a-fA-F]{1,4}){0,4}:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|:(?::[0-9a-fA-F]{1,4}){0,6}:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9a-fA-F]{1,4}:){0,1}(?::[0-9a-fA-F]{1,4}){0,5}:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|:(?::[0-9a-fA-F]{1,4}){1,7}|[0-9a-fA-F]{1,4}:((?::[0-9a-fA-F]{1,4}){0,5}:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|:)|:(?::[0-9a-fA-F]{1,4}){0,6}:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?::[0-9a-fA-F]{1,4}){2,7})$/;

    if (!ipInput.value || !ipRegex.test(ipInput.value)) {
        alert('Please enter a valid IP address.');
        return;
    }

    try {
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
            vtContainer.innerHTML = `<p><strong>VirusTotal scan:</strong> <a href="https://www.virustotal.com/gui/ip-address/${ipInput.value}">${virusTotalData.data.attributes.last_analysis_stats.malicious}/${totalVendors}</a> security vendors flagged that IP address.</p>`;
        } else {
            const errorData = await virusTotalResponse.json();
            console.error('Error when requesting the VirusTotal API:', errorData.error.message);
            vtContainer.innerHTML = `<p>${errorData.error.message}</p>`;
        }

        // Consulta a API do Shodan
        const shodanResponse = await fetch(`https://api.shodan.io/shodan/host/${ipInput.value}?key=${shodanApiKey}`);

        if (shodanResponse.ok) {
            const shodanData = await shodanResponse.json();

            // Exibe o resultado do Shodan na página com botão de acesso
            if (shodanData.vulns) {
                shodanContainer.innerHTML = `<p><strong>Shodan scan:</strong> <a href="https://www.shodan.io/host/${ipInput.value}">${shodanData.vulns.length}</a> vulnerabilities.`;
            } else {
                shodanContainer.innerHTML = `<p><strong>Shodan scan:</strong> <a href="https://www.shodan.io/host/${ipInput.value}">0</a> vulnerabilities.</p>`;
            }
        } else {
            const errorData = await shodanResponse.json();
            console.error('Error in requesting the Shodan API:', errorData.error);
            shodanContainer.innerHTML = `<p>${errorData.error}</p>`;
        }

    } catch (error) {
        console.error('Error when requesting APIs:', error);
        vtContainer.innerHTML = '<p>An error occurred while processing the request. Try again later.</p>';
    }
}
