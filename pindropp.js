#!/usr/bin/env node
/**
 * Enhanced Pindropp Tool with Advanced Features
 *
 * Overview:
 *   Pindropp is now a more advanced network exploration tool with features for analyzing networks and websites.
 *   It can scan ports (single host or entire subnets), perform Nmap scans, traceroute, ping,
 *   DNS lookups, Whois queries, and HTTP/HTTPS scans.
 *
 * New Features:
 *   - DNS Lookup: Perform forward and reverse lookups.
 *   - Whois Query: Retrieve domain/IP registration details.
 *   - Subnet Scanning: Scan a range of IP addresses using CIDR notation.
 *   - HTTP/HTTPS Scanning: Check website availability and server headers.
 *   - Saving Scan Results: Option to save findings to a file.
 *   - Service Identification: Maps common ports (e.g., 80 → HTTP, 22 → SSH).
 *   - User Action Logging: All actions are logged to "pindropp.log" with timestamps.
 *
 * Ethical Use:
 *   - The tool asks for explicit permission before scanning.
 *   - Sensitive data is handled only after warning the user.
 *   - A help section details ethical guidelines and legal notices.
 *
 * Requirements:
 *   npm install inquirer ping whois ip
 */

// Fix for potential ESM default export issues with Inquirer:
const inquirerModule = require('inquirer');
const inquirer = inquirerModule.default || inquirerModule;

const net = require('net');
const os = require('os');
const { exec } = require('child_process');
const fs = require('fs');
const ping = require('ping');
const dns = require('dns');
const http = require('http');
const https = require('https');
const whois = require('whois');
const ipLib = require('ip');
const util = require('util');
const execPromise = util.promisify(exec);

// Service mapping for common ports
const serviceMap = {
    20: 'FTP',
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS'
};

// Log user actions with timestamps for accountability
function logAction(action, target) {
    const timestamp = new Date().toISOString();
    const logEntry = `${timestamp} - ${action} - Target: ${target}\n`;
    fs.appendFile('pindropp.log', logEntry, (err) => {
        if (err) {
            console.error("Error writing to log file:", err);
        }
    });
}

// Prompt user to save scan results to a file
async function promptToSaveResults(results) {
    const { save } = await inquirer.prompt({
        type: 'confirm',
        name: 'save',
        message: 'Do you want to save the results to a file?',
        default: false
    });
    if (save) {
        const { filename } = await inquirer.prompt({
            type: 'input',
            name: 'filename',
            message: 'Enter the filename to save results (e.g., results.txt):',
            validate: input => input ? true : 'Filename cannot be empty'
        });
        fs.writeFile(filename, results, (err) => {
            if (err) {
                console.error("Error saving results:", err);
            } else {
                console.log(`Results saved to ${filename}`);
            }
        });
    }
}

// ------------------- Port Scanning (Single Host) -------------------
async function portScan() {
    console.log("\n--- Port Scanning (Single Host) ---");

    // Confirm that the user is authorized to scan
    const { permission } = await inquirer.prompt({
        type: 'confirm',
        name: 'permission',
        message: 'Do you have permission to scan this target? (Unauthorized scanning may be illegal)',
        default: false
    });
    if (!permission) {
        console.log("Permission not granted. Aborting port scan.\n");
        return;
    }

    // Get target and port range details
    const { target } = await inquirer.prompt({
        type: 'input',
        name: 'target',
        message: 'Enter target IP address:',
        validate: input => input ? true : 'Target IP cannot be empty'
    });
    const { startPort, endPort } = await inquirer.prompt([
        {
            type: 'input',
            name: 'startPort',
            message: 'Enter starting port number:',
            validate: input => {
                const num = parseInt(input, 10);
                return (!isNaN(num) && num > 0 && num <= 65535) ? true : 'Please enter a valid starting port (1-65535)';
            }
        },
        {
            type: 'input',
            name: 'endPort',
            message: 'Enter ending port number:',
            validate: input => {
                const num = parseInt(input, 10);
                return (!isNaN(num) && num > 0 && num <= 65535) ? true : 'Please enter a valid ending port (1-65535)';
            }
        }
    ]);

    const start = parseInt(startPort, 10);
    const end = parseInt(endPort, 10);
    if (end - start > 1000) {
        console.log("Warning: Scanning a large range of ports may take a significant amount of time.");
    }

    let results = `Port scan results for ${target}:\n`;
    const portPromises = [];
    const openPorts = [];

    for (let port = start; port <= end; port++) {
        portPromises.push(new Promise((resolve) => {
            const client = new net.Socket();
            client.setTimeout(1000);
            client.connect(port, target, () => {
                console.log(`[OPEN] Port ${port} is open.`);
                openPorts.push(port);
                results += `[OPEN] Port ${port} is open.\n`;
                client.destroy();
                resolve();
            });
            client.on("error", () => {
                client.destroy();
                resolve();
            });
            client.on("timeout", () => {
                client.destroy();
                resolve();
            });
        }));
    }
    await Promise.all(portPromises);

    // Service identification for open ports
    if (openPorts.length > 0) {
        console.log(`\nService Identification for open ports on ${target}:`);
        results += `\nService Identification for open ports on ${target}:\n`;
        for (let port of openPorts) {
            if (serviceMap[port]) {
                console.log(`Port ${port}: ${serviceMap[port]}`);
                results += `Port ${port}: ${serviceMap[port]}\n`;
            }
        }
    } else {
        results += "No open ports found.\n";
    }
    console.log("Port scanning completed.\n");
    logAction("Port Scan", target);
    await promptToSaveResults(results);
}

// ------------------- Subnet Scanning -------------------
async function subnetScan() {
    console.log("\n--- Subnet Scanning ---");

    // Confirm permission to scan the subnet
    const { permission } = await inquirer.prompt({
        type: 'confirm',
        name: 'permission',
        message: 'Do you have permission to scan this subnet? (Unauthorized scanning may be illegal)',
        default: false
    });
    if (!permission) {
        console.log("Permission not granted. Aborting subnet scan.\n");
        return;
    }

    // Get the subnet in CIDR notation
    const { subnet } = await inquirer.prompt({
        type: 'input',
        name: 'subnet',
        message: 'Enter subnet in CIDR notation (e.g., 192.168.1.0/24):',
        validate: input => {
            const parts = input.split('/');
            if (parts.length !== 2) return 'Invalid CIDR notation';
            const ipPart = parts[0];
            const maskPart = parts[1];
            if (!net.isIP(ipPart) || isNaN(parseInt(maskPart))) return 'Invalid CIDR notation';
            return true;
        }
    });

    const subnetInfo = ipLib.cidrSubnet(subnet);
    const first = ipLib.toLong(subnetInfo.firstAddress);
    const last = ipLib.toLong(subnetInfo.lastAddress);
    const targets = [];
    for (let i = first; i <= last; i++) {
        targets.push(ipLib.fromLong(i));
    }
    if (targets.length > 256) {
        console.log("Warning: Scanning a large subnet may take a significant amount of time.");
    }

    // Get port range for scanning
    const { startPort, endPort } = await inquirer.prompt([
        {
            type: 'input',
            name: 'startPort',
            message: 'Enter starting port number:',
            validate: input => {
                const num = parseInt(input, 10);
                return (!isNaN(num) && num > 0 && num <= 65535) ? true : 'Please enter a valid starting port (1-65535)';
            }
        },
        {
            type: 'input',
            name: 'endPort',
            message: 'Enter ending port number:',
            validate: input => {
                const num = parseInt(input, 10);
                return (!isNaN(num) && num > 0 && num <= 65535) ? true : 'Please enter a valid ending port (1-65535)';
            }
        }
    ]);
    const start = parseInt(startPort, 10);
    const end = parseInt(endPort, 10);
    console.log(`\nStarting subnet scan on ${subnet} from port ${start} to ${end}...\n`);

    let overallResults = "";
    for (const target of targets) {
        let results = `Scanning target: ${target}\n`;
        let openPorts = [];
        let portPromises = [];
        for (let port = start; port <= end; port++) {
            portPromises.push(new Promise((resolve) => {
                const client = new net.Socket();
                client.setTimeout(1000);
                client.connect(port, target, () => {
                    openPorts.push(port);
                    results += `[OPEN] Port ${port} is open.\n`;
                    client.destroy();
                    resolve();
                });
                client.on("error", () => {
                    client.destroy();
                    resolve();
                });
                client.on("timeout", () => {
                    client.destroy();
                    resolve();
                });
            }));
        }
        await Promise.all(portPromises);
        if (openPorts.length > 0) {
            results += `\nService Identification for ${target}:\n`;
            for (let port of openPorts) {
                if (serviceMap[port]) {
                    results += `Port ${port}: ${serviceMap[port]}\n`;
                }
            }
        } else {
            results += "No open ports found.\n";
        }
        console.log(results);
        overallResults += results + "\n";
    }
    console.log("Subnet scanning completed.\n");
    logAction("Subnet Scan", subnet);
    await promptToSaveResults(overallResults);
}

// ------------------- Nmap Scan -------------------
async function checkNmapInstalled() {
    return new Promise((resolve) => {
        exec("nmap --version", (error) => {
            if (error) {
                console.error("Nmap is not installed or not found in PATH.");
                resolve(false);
            } else {
                resolve(true);
            }
        });
    });
}

async function nmapScan() {
    console.log("\n--- Nmap Scan ---");
    const nmapInstalled = await checkNmapInstalled();
    if (!nmapInstalled) {
        console.log("Please install Nmap and ensure it is in your PATH.\n");
        return;
    }
    const { target } = await inquirer.prompt({
        type: 'input',
        name: 'target',
        message: 'Enter target IP address for Nmap scan:',
        validate: input => input ? true : 'Target cannot be empty'
    });
    logAction("Nmap Scan", target);
    try {
        const { stdout, stderr } = await execPromise(`nmap ${target}`);
        let results = stdout;
        if (stderr) {
            results += "\n" + stderr;
        }
        console.log(`Nmap scan results:\n${results}`);
        await promptToSaveResults(results);
    } catch (error) {
        console.error(`Error during Nmap scan: ${error.message}`);
    }
}

// ------------------- Traceroute -------------------
async function tracerouteScan() {
    console.log("\n--- Traceroute ---");
    const { target } = await inquirer.prompt({
        type: 'input',
        name: 'target',
        message: 'Enter target IP address for traceroute:',
        validate: input => input ? true : 'Target cannot be empty'
    });
    const platform = os.platform();
    const command = (platform === "win32") ? "tracert" : "traceroute";
    logAction("Traceroute", target);
    try {
        const { stdout, stderr } = await execPromise(`${command} ${target}`);
        let results = stdout;
        if (stderr) {
            results += "\n" + stderr;
        }
        console.log(`Traceroute results:\n${results}`);
        await promptToSaveResults(results);
    } catch (error) {
        console.error(`Error during traceroute: ${error.message}`);
    }
}

// ------------------- Ping -------------------
async function pingHost() {
    console.log("\n--- Ping ---");
    const { target } = await inquirer.prompt({
        type: 'input',
        name: 'target',
        message: 'Enter target IP address for ping:',
        validate: input => input ? true : 'Target cannot be empty'
    });
    try {
        const res = await ping.promise.probe(target);
        let results = `Ping results for ${target}:\nAlive: ${res.alive}\nTime: ${res.time} ms\nOutput:\n${res.output}\n`;
        console.log(results);
        logAction("Ping", target);
        await promptToSaveResults(results);
    } catch (err) {
        console.error(`Error during ping: ${err.message}`);
    }
}

// ------------------- DNS Lookup -------------------
async function dnsLookup() {
    console.log("\n--- DNS Lookup ---");
    const { query } = await inquirer.prompt({
        type: 'input',
        name: 'query',
        message: 'Enter a domain name or IP address:'
    });
    let results = "";
    if (net.isIP(query)) {
        // Reverse DNS lookup
        try {
            const hostnames = await dns.promises.reverse(query);
            results = `Reverse DNS lookup for ${query}: ${hostnames.join(", ")}`;
            console.log(results);
        } catch (error) {
            results = `Error in reverse DNS lookup: ${error.message}`;
            console.error(results);
        }
    } else {
        // Forward DNS lookup (IPv4 and IPv6)
        try {
            const addresses = await dns.promises.resolve(query, 'A');
            results = `IPv4 addresses for ${query}: ${addresses.join(", ")}`;
            console.log(results);
            try {
                const addresses6 = await dns.promises.resolve(query, 'AAAA');
                if (addresses6.length) {
                    results += `\nIPv6 addresses for ${query}: ${addresses6.join(", ")}`;
                    console.log(`IPv6 addresses for ${query}: ${addresses6.join(", ")}`);
                }
            } catch (err) {
                // No AAAA records found; ignore
            }
        } catch (error) {
            results = `Error in DNS lookup: ${error.message}`;
            console.error(results);
        }
    }
    logAction("DNS Lookup", query);
    await promptToSaveResults(results);
}

// ------------------- Whois Query -------------------
async function whoisQuery() {
    console.log("\n--- Whois Query ---");
    const { query } = await inquirer.prompt({
        type: 'input',
        name: 'query',
        message: 'Enter a domain name or IP address for Whois query:'
    });
    try {
        const data = await new Promise((resolve, reject) => {
            whois.lookup(query, (err, data) => {
                if (err) reject(err);
                else resolve(data);
            });
        });
        console.log(`Whois information for ${query}:\n${data}`);
        logAction("Whois Query", query);
        await promptToSaveResults(data);
    } catch (error) {
        console.error(`Error in Whois query: ${error.message}`);
    }
}

// ------------------- HTTP/HTTPS Scan -------------------
function httpCheck(url) {
    return new Promise((resolve, reject) => {
        http.get(url, (res) => {
            resolve(res);
        }).on('error', (e) => reject(e));
    });
}

function httpsCheck(url) {
    return new Promise((resolve, reject) => {
        https.get(url, (res) => {
            resolve(res);
        }).on('error', (e) => reject(e));
    });
}

async function webScan() {
    console.log("\n--- HTTP/HTTPS Scan ---");
    const { url } = await inquirer.prompt({
        type: 'input',
        name: 'url',
        message: 'Enter the URL to scan (e.g., http://example.com):',
        validate: input => input ? true : 'URL cannot be empty'
    });
    let checkFunction;
    if (url.startsWith("http://")) {
        checkFunction = httpCheck;
    } else if (url.startsWith("https://")) {
        checkFunction = httpsCheck;
    } else {
        console.error("Invalid URL: Please include http:// or https://");
        return;
    }
    try {
        const res = await checkFunction(url);
        let results = `Status code: ${res.statusCode}\nServer software: ${res.headers.server || 'Unknown'}\n`;
        console.log(results);
        logAction("Web Scan", url);
        await promptToSaveResults(results);
    } catch (error) {
        console.error(`Error checking ${url}: ${error.message}`);
    }
}

// ------------------- Sensitive Data Extraction -------------------
async function extractSensitiveData() {
    console.log("\n--- Extract and Save Sensitive Data ---");
    console.log("Warning: Handling sensitive data. Ensure you have authorization and handle the file securely.\n");

    const { sensitiveData } = await inquirer.prompt({
        type: 'editor',
        name: 'sensitiveData',
        message: 'Enter the sensitive data to be saved:'
    });
    fs.writeFile('sensitive_data.json', sensitiveData, (err) => {
        if (err) {
            console.error("Error saving sensitive data:", err);
        } else {
            console.log("Sensitive data saved to sensitive_data.json\n");
            logAction("Sensitive Data Extraction", "sensitive_data.json");
        }
    });
}

// ------------------- Help / Ethical Guidelines -------------------
async function helpSection() {
    console.log("\n--- Help / Ethical Guidelines ---\n");
    console.log("Ethical Guidelines and Legal Notices:");
    console.log("1. Always obtain proper authorization before performing any network operations.");
    console.log("2. Unauthorized scanning or accessing systems may be illegal and unethical.");
    console.log("3. Use this tool only for legitimate purposes such as network administration and security testing.");
    console.log("4. Handle sensitive data with care and ensure it is stored securely.");
    console.log("5. All user actions are logged for accountability. Use responsibly.");
    console.log("6. The developer is not responsible for any misuse of this tool.\n");
}

// ------------------- Main Menu -------------------
async function mainMenu() {
    while (true) {
        const { choice } = await inquirer.prompt({
            type: 'list',
            name: 'choice',
            message: 'Select an action:',
            choices: [
                'Port Scan (Single Host)',
                'Subnet Scan',
                'Nmap Scan',
                'Traceroute',
                'Ping',
                'DNS Lookup',
                'Whois Query',
                'HTTP/HTTPS Scan',
                'Extract Sensitive Data',
                'Help / Ethical Guidelines',
                'Exit'
            ]
        });

        switch (choice) {
            case 'Port Scan (Single Host)':
                await portScan();
                break;
            case 'Subnet Scan':
                await subnetScan();
                break;
            case 'Nmap Scan':
                await nmapScan();
                break;
            case 'Traceroute':
                await tracerouteScan();
                break;
            case 'Ping':
                await pingHost();
                break;
            case 'DNS Lookup':
                await dnsLookup();
                break;
            case 'Whois Query':
                await whoisQuery();
                break;
            case 'HTTP/HTTPS Scan':
                await webScan();
                break;
            case 'Extract Sensitive Data':
                await extractSensitiveData();
                break;
            case 'Help / Ethical Guidelines':
                await helpSection();
                break;
            case 'Exit':
                console.log("Exiting Enhanced Pindropp Tool. Goodbye!");
                process.exit(0);
                break;
            default:
                console.log("Invalid choice. Please select a valid option.");
        }
    }
}

// ------------------- Start Application -------------------
(async () => {
    console.log("Welcome to the Enhanced Pindropp Network Exploration Tool");
    await mainMenu();
})();
