
const issues = [
  // ─── NETWORK ───────────────────────────────────────────────────────────────
  {
    cat: 'network', catLabel: 'Network',
    sev: 'critical', sevLabel: 'CRITICAL',
    problem: 'No Internet Connectivity',
    sub: 'Complete network outage',
    symptoms: ['No websites load','DNS fails','All devices affected'],
    diag: ['Check modem/router lights','Ping default gateway (e.g. 192.168.1.1)','Run ipconfig /all — check IP assignment','Try DNS lookup: nslookup google.com'],
    resolution: 'Restart modem → wait 60s → restart router → test',
    resDetail: 'Power cycle modem first, then router. If DHCP fails, try static IP. Contact ISP if WAN light is off.',
    time: '5–30 min',
    tools: ['ipconfig', 'ping', 'nslookup', 'tracert'],
    escalate: 'If WAN light is off after reboot, ISP issue — open a ticket',
    prevention: 'Configure UPS for modem/router; set up network monitoring alerts'
  },
  {
    cat: 'network', catLabel: 'Network',
    sev: 'high', sevLabel: 'HIGH',
    problem: 'Slow Network / Low Bandwidth',
    sub: 'Speed degradation',
    symptoms: ['Pages load slowly','File transfers timeout','High latency on speed tests'],
    diag: ['Run speed test at speedtest.net','Check bandwidth utilization on router','Identify top bandwidth consumers (QoS logs)','Test with wired vs wireless'],
    resolution: 'Identify & throttle bandwidth-hungry apps; check for malware',
    resDetail: 'Enable QoS on router. Check for background updates, video streaming, or P2P software consuming bandwidth.',
    time: '15–60 min',
    tools: ['speedtest.net', 'Wireshark', 'router QoS', 'netstat'],
    escalate: 'If issue persists on wired connections, check switch/router or ISP line quality',
    prevention: 'Set up QoS rules; monitor bandwidth with PRTG or similar'
  },
  {
    cat: 'network', catLabel: 'Network',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Wi-Fi Keeps Disconnecting',
    sub: 'Intermittent wireless drops',
    symptoms: ['Wi-Fi drops every few minutes','"No Internet" while connected','Only on specific devices'],
    diag: ['Check signal strength (aim for -65 dBm or better)','Review router DHCP lease time','Check for RF interference (microwaves, neighbors)','Update wireless adapter driver'],
    resolution: 'Switch to 5 GHz band; update firmware; adjust power management settings',
    resDetail: 'Disable "Allow computer to turn off device to save power" in adapter settings. Try different Wi-Fi channel.',
    time: '20–45 min',
    tools: ['inSSIDer', 'Device Manager', 'netsh wlan'],
    escalate: 'Replace router if channel congestion persists across all settings',
    prevention: 'Use Wi-Fi analyzer to select least congested channel; consider mesh system'
  },
  {
    cat: 'network', catLabel: 'Network',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'IP Address Conflict',
    sub: 'Duplicate IP on network',
    symptoms: ['"IP address conflict" warning','Intermittent connectivity','Two devices share same IP'],
    diag: ['Run: ipconfig /release && ipconfig /renew','Check DHCP server lease pool','Identify static IPs outside DHCP range','Use arp -a to find duplicates'],
    resolution: 'Reassign static IP or expand DHCP pool; release/renew all affected devices',
    resDetail: 'Reserve MACs in DHCP server. Move static IPs outside DHCP range (e.g., .200–.254).',
    time: '10–20 min',
    tools: ['ipconfig', 'arp', 'DHCP server console'],
    escalate: 'Check rogue DHCP servers if conflicts persist',
    prevention: 'Use DHCP reservations; document all static IP assignments'
  },
  {
    cat: 'network', catLabel: 'Network',
    sev: 'high', sevLabel: 'HIGH',
    problem: 'VPN Not Connecting',
    sub: 'Remote access failure',
    symptoms: ['VPN client times out','Authentication fails','Connected but no access to resources'],
    diag: ['Verify credentials and server address','Check firewall allows VPN ports (UDP 1194, TCP 443, etc.)','Test with different network (mobile hotspot)','Review VPN client logs'],
    resolution: 'Check credentials → firewall rules → reinstall client → contact VPN admin',
    resDetail: 'Common causes: expired password, blocked ports, certificate mismatch, or split-tunnel misconfiguration.',
    time: '10–60 min',
    tools: ['VPN client logs', 'netstat', 'ping', 'telnet'],
    escalate: 'If server-side, escalate to network team for firewall/cert review',
    prevention: 'Set VPN certificate expiry alerts; document required firewall rules'
  },
  {
    cat: 'network', catLabel: 'Network',
    sev: 'low', sevLabel: 'LOW',
    problem: 'Can\'t Access Network Share / Drive',
    sub: 'SMB / mapped drive failure',
    symptoms: ['Drive shows red X','"Network path not found"','Credentials prompt loop'],
    diag: ['Ping the file server by name and IP','Test: net use \\\\server\\share','Check Windows Firewall on server','Verify SMB is enabled'],
    resolution: 'Re-map drive with correct credentials; enable SMB 1/2 if required; check share permissions',
    resDetail: 'Run: net use * /delete then remap. Check both share AND NTFS permissions. Ensure "File and Printer Sharing" is on.',
    time: '10–30 min',
    tools: ['net use', 'ping', 'Event Viewer', 'compmgmt.msc'],
    escalate: 'If permissions issue, involve file server admin',
    prevention: 'Use Group Policy to auto-map drives; document share permissions'
  },

  // ─── HARDWARE ──────────────────────────────────────────────────────────────
  {
    cat: 'hardware', catLabel: 'Hardware',
    sev: 'critical', sevLabel: 'CRITICAL',
    problem: 'Computer Won\'t Turn On',
    sub: 'No power / no POST',
    symptoms: ['No lights or fans','Power button unresponsive','Fans spin then stop'],
    diag: ['Check power cable & surge protector','Test with different outlet','Inspect for capacitor bulge on motherboard','Disconnect all peripherals and retry'],
    resolution: 'Verify power supply → reseat RAM → test PSU with multimeter → replace PSU',
    resDetail: 'Try RAM stick individually in different slots. Clear CMOS. If PSU fan doesn\'t spin, PSU is likely dead.',
    time: '30–120 min',
    tools: ['Multimeter', 'Spare PSU', 'Antistatic wristband'],
    escalate: 'If no POST after PSU/RAM test, likely motherboard failure — hardware replacement needed',
    prevention: 'UPS protects against power surges; regular PSU health checks'
  },
  {
    cat: 'hardware', catLabel: 'Hardware',
    sev: 'critical', sevLabel: 'CRITICAL',
    problem: 'Blue Screen of Death (BSOD)',
    sub: 'Windows stop error',
    symptoms: ['Blue screen with error code','Automatic restart loop','System unstable after startup'],
    diag: ['Note the STOP error code','Check Event Viewer → Windows Logs → System','Run: sfc /scannow','Check memory with Windows Memory Diagnostic'],
    resolution: 'Analyze minidump with WinDbg; update/rollback recent drivers; run memory test',
    resDetail: 'Common codes: IRQL_NOT_LESS_OR_EQUAL (driver), MEMORY_MANAGEMENT (RAM), CRITICAL_PROCESS_DIED (OS corruption).',
    time: '30–180 min',
    tools: ['WinDbg', 'Minidump analyzer', 'MemTest86', 'sfc /scannow'],
    escalate: 'Persistent BSOD after driver fix and RAM test → motherboard or CPU fault',
    prevention: 'Keep drivers updated; ensure proper cooling; test RAM periodically'
  },
  {
    cat: 'hardware', catLabel: 'Hardware',
    sev: 'high', sevLabel: 'HIGH',
    problem: 'Monitor No Signal / Black Screen',
    sub: 'Display failure',
    symptoms: ['Black screen after boot','Monitor shows "No Signal"','Display cuts out randomly'],
    diag: ['Check cable connection (both ends)','Try different cable (HDMI/DP/VGA)','Test monitor on another PC','Check GPU seating in PCIe slot'],
    resolution: 'Reseat GPU → test with onboard graphics → replace cable → update GPU drivers',
    resDetail: 'Boot into Safe Mode. If onboard works, GPU is suspect. Check GPU fans are spinning. Reseat in different PCIe slot.',
    time: '15–60 min',
    tools: ['Known-good cable', 'Another monitor', 'Compressed air'],
    escalate: 'GPU replacement if hardware confirmed faulty',
    prevention: 'Secure cable connections; periodic GPU cleaning'
  },
  {
    cat: 'hardware', catLabel: 'Hardware',
    sev: 'high', sevLabel: 'HIGH',
    problem: 'Overheating / Thermal Shutdown',
    sub: 'CPU/GPU temperature critical',
    symptoms: ['PC shuts off under load','CPU temp > 90°C','Fans running at max speed constantly'],
    diag: ['Monitor temps with HWMonitor or HWiNFO','Check CPU cooler seating','Inspect thermal paste condition','Check airflow: filter clogs, cable management'],
    resolution: 'Clean dust from heatsink/fans → reapply thermal paste → improve case airflow',
    resDetail: 'Remove heatsink, clean off old paste with isopropyl, apply pea-sized dot of quality paste (e.g., Arctic MX-4).',
    time: '30–90 min',
    tools: ['HWMonitor', 'Compressed air', 'Isopropyl 90%+', 'Thermal paste'],
    escalate: 'Replace cooler if thermal paste change doesn\'t help; check for bent CPU pins',
    prevention: 'Clean PC every 6 months; monitor temps with alerts set in BIOS'
  },
  {
    cat: 'hardware', catLabel: 'Hardware',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Keyboard / Mouse Not Working',
    sub: 'Input device failure',
    symptoms: ['No response from keyboard/mouse','Device not detected in Device Manager','Wireless device stops working'],
    diag: ['Try different USB port','Test on another PC','Check Device Manager for errors','For wireless: replace batteries, re-pair'],
    resolution: 'Try alternate port → reinstall drivers → test on another PC → replace device',
    resDetail: 'Uninstall device in Device Manager, unplug, replug. For wireless: reset receiver pairing. USB hubs can cause issues.',
    time: '5–20 min',
    tools: ['Device Manager', 'Another USB port/PC'],
    escalate: 'Replace device if fails on another PC with fresh drivers',
    prevention: 'Use quality USB hubs; keep firmware updated for wireless devices'
  },
  {
    cat: 'hardware', catLabel: 'Hardware',
    sev: 'critical', sevLabel: 'CRITICAL',
    problem: 'Hard Drive Failure / Bad Sectors',
    sub: 'HDD/SSD data risk',
    symptoms: ['Clicking sounds (HDD)','Very slow file access','SMART errors in diagnostics','Boot failures'],
    diag: ['Run CrystalDiskInfo — check SMART data','Run chkdsk /f /r on the drive','Listen for clicking (HDD death rattle)','Check Event Viewer for disk errors'],
    resolution: 'BACKUP DATA IMMEDIATELY → clone drive → replace with new SSD',
    resDetail: 'Priority #1: backup. Use Macrium Reflect or Clonezilla to clone. Do NOT run extensive diagnostics on a clicking drive.',
    time: '1–8 hours',
    tools: ['CrystalDiskInfo', 'Macrium Reflect', 'Clonezilla', 'chkdsk'],
    escalate: 'Data recovery service if drive is unreadable and data is critical',
    prevention: '3-2-1 backup rule; monitor SMART data monthly; replace drives > 5 years old'
  },

  // ─── SOFTWARE ──────────────────────────────────────────────────────────────
  {
    cat: 'software', catLabel: 'Software',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Application Crashes / Freezes',
    sub: 'Software instability',
    symptoms: ['App closes unexpectedly','"Not Responding" in Task Manager','Crash only with certain files'],
    diag: ['Check Windows Event Viewer → Application log','Run app as administrator','Check for pending updates','Test with different user profile'],
    resolution: 'Update app → repair installation → reinstall → check for conflicting software',
    resDetail: 'In Event Viewer, look for Application Error or Fault Module. Reinstall with VS C++ Redistributables. Disable extensions.',
    time: '15–60 min',
    tools: ['Event Viewer', 'Task Manager', 'Procmon', 'Dependency Walker'],
    escalate: 'Escalate to software vendor if crash persists after clean reinstall',
    prevention: 'Keep software patched; avoid beta software on production machines'
  },
  {
    cat: 'software', catLabel: 'Software',
    sev: 'low', sevLabel: 'LOW',
    problem: 'Software Won\'t Install',
    sub: 'Installer errors',
    symptoms: ['Error code during setup','"Access Denied" during install','Installer hangs at certain %'],
    diag: ['Run installer as Administrator','Check available disk space','Temporarily disable AV','Review installer log in %TEMP%'],
    resolution: 'Run as admin → clear temp files → check disk space → disable AV during install',
    resDetail: 'Common error 1603 = SYSTEM account issue. Try: msiexec /i setup.msi /log install.log to capture details.',
    time: '10–30 min',
    tools: ['msiexec', 'CCleaner', 'Autoruns'],
    escalate: 'Check with software vendor for enterprise deployment package (MSI/SCCM)',
    prevention: 'Use software deployment tools (SCCM, Intune) for standardized installs'
  },
  {
    cat: 'software', catLabel: 'Software',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'License / Activation Error',
    sub: 'Software activation failure',
    symptoms: ['"Product not activated" warning','Features locked or grayed out','License server unreachable'],
    diag: ['Verify license key is valid','Check network access to license server','Run activation troubleshooter','Check if license is already used on another machine'],
    resolution: 'Re-enter key → deactivate old machine → contact vendor for transfer → check network license server',
    resDetail: 'For Microsoft: slmgr /ato or use Activation Troubleshooter. For volume licenses, check KMS connectivity.',
    time: '10–45 min',
    tools: ['slmgr', 'Activation Troubleshooter', 'Vendor portal'],
    escalate: 'Contact software vendor with proof of purchase for manual activation',
    prevention: 'Track license usage in asset management system; set renewal reminders'
  },
  {
    cat: 'software', catLabel: 'Software',
    sev: 'low', sevLabel: 'LOW',
    problem: 'Browser Issues (Crashes, Slow, Errors)',
    sub: 'Web browser malfunction',
    symptoms: ['Browser crashes frequently','Pages won\'t load in one browser','Extensions causing slowdown'],
    diag: ['Test in incognito/private mode','Disable all extensions','Clear cache and cookies','Test different browser'],
    resolution: 'Clear cache → disable extensions → reset browser settings → reinstall',
    resDetail: 'Chrome: Settings → Reset & Clean Up. Firefox: about:support → Refresh Firefox. Check for malicious extensions.',
    time: '5–20 min',
    tools: ['Browser dev tools', 'Malwarebytes', 'Task Manager'],
    escalate: 'If all browsers fail, check proxy/DNS settings or AV interference',
    prevention: 'Limit extensions; keep browser updated; use enterprise policy to block malicious add-ons'
  },

  // ─── OS ────────────────────────────────────────────────────────────────────
  {
    cat: 'os', catLabel: 'OS',
    sev: 'critical', sevLabel: 'CRITICAL',
    problem: 'Windows Won\'t Boot',
    sub: 'OS startup failure',
    symptoms: ['Stuck on loading screen','Bootmgr missing error','Repair loop after update'],
    diag: ['Boot from Windows USB → Startup Repair','Run: bootrec /fixmbr && bootrec /fixboot','Check Boot Configuration: bcdedit','Run sfc /scannow from recovery'],
    resolution: 'Run Startup Repair → Rebuild BCD → System Restore → last resort: reinstall',
    resDetail: 'Try: bootrec /rebuildbcd. If corrupt BCD: bootsect /nt60 SYS. Safe Mode F8/Shift+F8. Check if recent driver/update caused it.',
    time: '30–240 min',
    tools: ['Windows Recovery USB', 'bootrec', 'bcdedit', 'sfc'],
    escalate: 'If all recovery options fail and no backup, consider OS reinstall with data preservation',
    prevention: 'Regular system backups; create recovery USB; test updates on non-critical machines first'
  },
  {
    cat: 'os', catLabel: 'OS',
    sev: 'high', sevLabel: 'HIGH',
    problem: 'Windows Update Failing',
    sub: 'Update errors / stuck',
    symptoms: ['Update stuck at %','Error codes (0x80070002, etc.)','Update reverts on reboot'],
    diag: ['Run Windows Update Troubleshooter','Check C:\\ drive free space (need 8+ GB)','Review WindowsUpdate.log','Reset Windows Update components'],
    resolution: 'Run troubleshooter → clear update cache → reset WUAUSERV service → try manual KB update',
    resDetail: 'Stop services: wuauserv, cryptSvc, bits, msiserver. Rename SoftwareDistribution folder. Restart services. Try again.',
    time: '30–90 min',
    tools: ['Windows Update Troubleshooter', 'DISM', 'sfc /scannow'],
    escalate: 'Use WSUS for enterprise; escalate to Microsoft if specific KB fails repeatedly',
    prevention: 'Maintain adequate disk space; use WSUS to test updates before rollout'
  },
  {
    cat: 'os', catLabel: 'OS',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'User Profile Corrupt',
    sub: 'Profile fails to load',
    symptoms: ['Logs in to temporary profile','Desktop appears empty','"We can\'t sign in" message'],
    diag: ['Log in with another admin account','Check ProfileList in Registry (HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList)','Rename .bak profile entry','Check for duplicate SID entries'],
    resolution: 'Fix registry ProfileList key → or create new user profile → migrate data',
    resDetail: 'In ProfileList, find user\'s SID. If there\'s a .bak version, rename existing to .bak2 and remove .bak from the good one.',
    time: '30–120 min',
    tools: ['regedit', 'File Explorer', 'USMT (User State Migration Tool)'],
    escalate: 'If profile data is critical and irrecoverable, use USMT for controlled migration',
    prevention: 'Redirect user folders (Documents, Desktop) to network share or OneDrive'
  },
  {
    cat: 'os', catLabel: 'OS',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Right-Click Context Menu Very Slow',
    sub: 'Shell extension delay',
    symptoms: ['Right-click takes 5+ seconds','Explorer freezes briefly','Issue only on desktop or specific folders'],
    diag: ['Use ShellExView to identify faulty extensions','Check for broken shell extensions in registry','Test in Safe Mode (fast = shell extension issue)'],
    resolution: 'Use ShellExView to disable non-Microsoft shell extensions one by one to find culprit',
    resDetail: 'Download ShellExView. Sort by Company. Disable all non-Microsoft items. Re-enable in batches to isolate.',
    time: '15–30 min',
    tools: ['ShellExView', 'Autoruns'],
    escalate: 'Uninstall problematic software causing the extension',
    prevention: 'Avoid installing software that adds many shell extensions'
  },

  // ─── SECURITY ──────────────────────────────────────────────────────────────
  {
    cat: 'security', catLabel: 'Security',
    sev: 'critical', sevLabel: 'CRITICAL',
    problem: 'Malware / Ransomware Infection',
    sub: 'Active compromise',
    symptoms: ['Files encrypted with .locked/.crypt extension','Pop-up ransom note','AV alerts firing repeatedly','High CPU from unknown process'],
    diag: ['Isolate machine from network immediately','Do NOT reboot — preserve volatile memory if forensics needed','Identify malware via Task Manager → suspicious processes','Check startup entries (Autoruns)'],
    resolution: 'ISOLATE → Do not pay ransom → restore from clean backup → reimage if needed',
    resDetail: 'Disconnect from network. Alert security team. Identify ransomware family (ID Ransomware tool). Restore from known-clean backup.',
    time: '2–48 hours',
    tools: ['Malwarebytes', 'ID Ransomware', 'Autoruns', 'HitmanPro'],
    escalate: 'Immediately escalate to security team / incident response; may require forensic investigation',
    prevention: '3-2-1 backups; EDR solution; user phishing training; disable macros; patch promptly'
  },
  {
    cat: 'security', catLabel: 'Security',
    sev: 'critical', sevLabel: 'CRITICAL',
    problem: 'Account Compromised / Unauthorized Access',
    sub: 'Credential breach',
    symptoms: ['User unrecognized login alerts','Emails sent without user knowledge','Password not working'],
    diag: ['Check login history in Azure AD / admin panel','Review email rules for forwarding','Check for MFA changes','Look for new OAuth app authorizations'],
    resolution: 'Reset password immediately → revoke all sessions → enable MFA → audit account activity',
    resDetail: 'Force sign-out all sessions (Azure: Revoke Sign-in Sessions). Remove malicious email rules/forwarding. Check for new admin roles.',
    time: '30–120 min',
    tools: ['Azure AD / M365 Admin Center', 'Audit logs', 'Have I Been Pwned'],
    escalate: 'Treat as full security incident if admin account is affected; involve CISO',
    prevention: 'MFA mandatory; phishing training; SSPR; monitor impossible travel alerts'
  },
  {
    cat: 'security', catLabel: 'Security',
    sev: 'high', sevLabel: 'HIGH',
    problem: 'Phishing Email Reported',
    sub: 'Social engineering attempt',
    symptoms: ['Suspicious email asking for credentials','Unexpected invoice/package links','Impersonation of known sender'],
    diag: ['Check sender\'s actual email address (not display name)','Hover links without clicking','Check email headers for SPF/DKIM/DMARC fails','Look up URL in VirusTotal'],
    resolution: 'Quarantine email → warn users → block sender domain → submit to security team',
    resDetail: 'In M365: Report Message add-in. Block sender in EAC. Check if others received it. Scan attachments in sandbox.',
    time: '15–45 min',
    tools: ['Message Header Analyzer', 'VirusTotal', 'Any.run sandbox', 'M365 Security Center'],
    escalate: 'If credentials were entered, treat as account compromise (above)',
    prevention: 'Enable DMARC/DKIM/SPF; deploy email security gateway; regular phishing simulations'
  },
  {
    cat: 'security', catLabel: 'Security',
    sev: 'high', sevLabel: 'HIGH',
    problem: 'Windows Firewall Blocking Application',
    sub: 'FW rule blocking traffic',
    symptoms: ['App can\'t connect to server','Works when firewall disabled','Error: Connection Refused / Timed Out'],
    diag: ['Test with firewall temporarily disabled','Check Windows Firewall logs (pfirewall.log)','Use netstat to confirm app is listening','Review inbound/outbound rules'],
    resolution: 'Add specific inbound/outbound firewall rule for the application or required ports',
    resDetail: 'Open wf.msc → New Rule → Port → add specific TCP/UDP port. Do NOT leave firewall disabled.',
    time: '10–25 min',
    tools: ['wf.msc', 'netstat', 'Telnet', 'Wireshark'],
    escalate: 'For enterprise, manage via Group Policy or network firewall (not host FW)',
    prevention: 'Document required firewall rules in change management; use GPO for standardized rules'
  },

  // ─── EMAIL ─────────────────────────────────────────────────────────────────
  {
    cat: 'email', catLabel: 'Email',
    sev: 'high', sevLabel: 'HIGH',
    problem: 'Outlook Not Receiving Emails',
    sub: 'Mail delivery failure',
    symptoms: ['Emails sent to user bounce or don\'t arrive','Sent items show delivered but not received','Inbox stuck, new mail not appearing'],
    diag: ['Check mailbox quota','Test send/receive with another account','Run Outlook Test Email AutoConfiguration','Check mail flow in Exchange/M365 admin'],
    resolution: 'Check mailbox size → repair Outlook profile → check mail flow rules → test from admin portal',
    resDetail: 'Use M365 admin Message Trace to track email flow. Check transport rules blocking delivery. Re-create Outlook profile if needed.',
    time: '15–60 min',
    tools: ['M365 Admin Message Trace', 'Outlook Profile Manager', 'MX Toolbox'],
    escalate: 'If mail flow confirmed delivered by server but not in Outlook, re-create profile or PST',
    prevention: 'Archive policy to manage mailbox size; monitor mail flow alerts'
  },
  {
    cat: 'email', catLabel: 'Email',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Emails Going to Spam / Junk',
    sub: 'Deliverability issue',
    symptoms: ['Recipients report emails in spam','Marketing emails have low delivery rate','Specific domains block emails'],
    diag: ['Check SPF record: dig TXT domain.com','Check DKIM signing','Check DMARC policy','Test sending IP reputation at MXToolbox Blacklist Check'],
    resolution: 'Set up SPF/DKIM/DMARC properly → check IP on blacklists → request delisting',
    resDetail: 'SPF: list all authorized sending IPs. DKIM: cryptographic signing. DMARC: policy enforcement. Use mail-tester.com to score.',
    time: '1–8 hours',
    tools: ['MXToolbox', 'mail-tester.com', 'Google Postmaster Tools', 'DNS editor'],
    escalate: 'If IP is blacklisted, submit delisting request — may take 24–72h',
    prevention: 'Implement SPF, DKIM, DMARC; monitor sender reputation; warm up new IPs'
  },
  {
    cat: 'email', catLabel: 'Email',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Outlook / Mail App Won\'t Sync',
    sub: 'Email client sync failure',
    symptoms: ['Sync icon spinning permanently','Emails show on webmail but not in client','Calendar/contacts not updating'],
    diag: ['Test connection via Outlook → File → Account Settings → Test Connection','Check autodiscover by pinging autodiscover.domain.com','Try removing and re-adding account','Check OAuth token expiry (modern auth)'],
    resolution: 'Re-authenticate account → clear credentials from Credential Manager → re-add account → clear OST/profile',
    resDetail: 'In Credential Manager, remove all Microsoft/Office entries. Sign in fresh. For OST corruption: rename .ost, let it rebuild.',
    time: '20–60 min',
    tools: ['Credential Manager', 'Outlook Profile Manager', 'Microsoft Support Recovery Assistant'],
    escalate: 'If autodiscover fails org-wide, check DNS/Exchange autodiscover configuration',
    prevention: 'Keep Outlook updated; monitor OAuth token expiry via Conditional Access'
  },

  // ─── PRINTER ───────────────────────────────────────────────────────────────
  {
    cat: 'printer', catLabel: 'Printer',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Printer Offline / Not Printing',
    sub: 'Printer communication failure',
    symptoms: ['Printer shows "Offline" in Windows','Jobs stuck in print queue','Printer powers on but won\'t print'],
    diag: ['Check physical connection (USB/network)','Ping printer IP','Clear print spooler: net stop spooler → del /Q /F /S "%systemroot%\\System32\\spool\\PRINTERS\\*.*" → net start spooler','Set printer Online: right-click → See what\'s printing → Printer → Use Printer Online'],
    resolution: 'Clear spooler → set online → verify IP → reinstall printer driver',
    resDetail: 'Print spooler corruption is the most common cause. If shared printer, verify server-side spooler too. Reinstall driver using manufacturer utility.',
    time: '10–30 min',
    tools: ['Print Management Console', 'Ping', 'Device Manager', 'Manufacturer driver utility'],
    escalate: 'If printer shows offline consistently, check network switch port or printer NIC',
    prevention: 'Use print server for centralized management; monitor printer status via SNMP'
  },
  {
    cat: 'printer', catLabel: 'Printer',
    sev: 'low', sevLabel: 'LOW',
    problem: 'Poor Print Quality / Streaks',
    sub: 'Print output degraded',
    symptoms: ['Horizontal lines or streaks on pages','Faded or patchy output','Smeared toner/ink'],
    diag: ['Print test page from printer panel (not computer)','Check ink/toner levels','Run print head cleaning from printer utility','Inspect drum/cartridge for damage'],
    resolution: 'Replace cartridge → run cleaning cycle → check drum → align print heads',
    resDetail: 'For laser: streaks on same position = drum damage. For inkjet: run 2–3 cleaning cycles. Check for paper quality issues.',
    time: '10–30 min',
    tools: ['Printer utility software', 'Test page', 'Replacement cartridge'],
    escalate: 'Fuser or drum replacement if cleaning doesn\'t resolve (laser printers)',
    prevention: 'Use genuine cartridges; print regularly to prevent ink drying'
  },
  {
    cat: 'printer', catLabel: 'Printer',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Paper Jam',
    sub: 'Media feed failure',
    symptoms: ['Paper jam error light','Paper visible inside printer','Partial page ejected'],
    diag: ['Open all access panels to find paper','Check for torn paper fragments','Inspect rollers for damage or debris','Test with new paper from a fresh ream'],
    resolution: 'Remove paper gently (do not tear) → check all trays → clean rollers → test print',
    resDetail: 'Always pull paper in the direction of travel. Use both hands. Look for small torn pieces. Rollers can be cleaned with isopropyl.',
    time: '5–20 min',
    tools: ['Flashlight', 'Isopropyl wipes', 'Fresh paper'],
    escalate: 'Frequent jams = roller wear → replace pickup roller kit',
    prevention: 'Fan paper before loading; use correct paper weight; clean rollers quarterly'
  },

  // ─── ACCOUNT ───────────────────────────────────────────────────────────────
  {
    cat: 'account', catLabel: 'Account',
    sev: 'high', sevLabel: 'HIGH',
    problem: 'User Locked Out of Account',
    sub: 'AD / Azure account lockout',
    symptoms: ['Login fails with "Account Locked" message','User can\'t authenticate anywhere','Happening repeatedly every few minutes'],
    diag: ['Check AD account status (ADUC or Get-ADUser)','Identify lockout source: run LockoutStatus.exe or check Event ID 4625','Check mapped drives and services using old credentials','Review Kerberos pre-auth failures'],
    resolution: 'Unlock account → identify lockout source → update stored credentials → reset password if needed',
    resDetail: 'Common cause: old password stored in credential manager or service. Event ID 4740 on DC shows lockout source machine.',
    time: '5–20 min',
    tools: ['LockoutStatus.exe', 'ADUC', 'PowerShell', 'Event Viewer on DCs'],
    escalate: 'If lockouts keep recurring, audit all services and apps using that account',
    prevention: 'Fine-grained password policy for service accounts; use MSAs/gMSAs for services'
  },
  {
    cat: 'account', catLabel: 'Account',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'MFA Not Working / Prompting Repeatedly',
    sub: 'Multi-factor auth failure',
    symptoms: ['MFA prompt loops even after approval','Authenticator app not receiving push','MFA code rejected'],
    diag: ['Check if device time is accurate (TOTP requires correct time)','Verify correct account in authenticator','Check conditional access policy in Azure AD','Test with SMS/call instead of app'],
    resolution: 'Sync device clock → re-register MFA method → reset MFA in Azure AD admin → reconfigure authenticator app',
    resDetail: 'TOTP codes require time within ±30s. In Azure AD: Users → [user] → Authentication Methods → Require re-register MFA.',
    time: '10–30 min',
    tools: ['Azure AD Admin Center', 'Microsoft Authenticator', 'M365 Admin Center'],
    escalate: 'If issue is org-wide, check Azure AD conditional access or MFA service health',
    prevention: 'Register multiple MFA methods per user; train users on app backup codes'
  },
  {
    cat: 'account', catLabel: 'Account',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Can\'t Access Shared Mailbox / Calendar',
    sub: 'Delegation / permission issue',
    symptoms: ['Shared mailbox missing from Outlook','"You don\'t have permission" accessing calendar','Delegate can\'t see certain folders'],
    diag: ['Verify mailbox permission in Exchange/M365','Check if user has Full Access or Send As','Confirm automapping (may need Outlook restart)','Test via Outlook Web App'],
    resolution: 'Grant permissions in Exchange Admin Center → remove & re-add Outlook account → test in OWA',
    resDetail: 'Use EAC or PowerShell: Add-MailboxPermission. Auto-mapping takes up to 1h. If OWA works but Outlook doesn\'t, re-create Outlook profile.',
    time: '15–45 min',
    tools: ['Exchange Admin Center', 'PowerShell', 'Outlook OWA'],
    escalate: 'Check if on-prem/hybrid mail routing is causing delay in permission sync',
    prevention: 'Document all shared mailbox delegations; review quarterly'
  },
  {
    cat: 'account', catLabel: 'Account',
    sev: 'low', sevLabel: 'LOW',
    problem: 'Password Reset Required / Forgot Password',
    sub: 'Self-service or admin reset',
    symptoms: ['User cannot log in','Password expired','SSPR not working'],
    diag: ['Verify SSPR is configured in Azure AD','Check if security info (phone/email) is registered','Confirm user\'s account is not locked or disabled','Check if password reset policy allows self-service'],
    resolution: 'Use SSPR (aka.ms/sspr) → or admin reset via Azure AD/ADUC → force change on next login',
    resDetail: 'For SSPR: user must have registered auth methods. For admin reset: Get-MgUser | Set-MgUserPassword or use ADUC.',
    time: '2–10 min',
    tools: ['Azure AD Admin Center', 'ADUC', 'PowerShell', 'aka.ms/sspr'],
    escalate: 'If SSPR fails org-wide, check Azure AD SSPR licensing and policy',
    prevention: 'Pre-register all users for SSPR; set password complexity + expiry reminders'
  },

  // ─── PERFORMANCE ────────────────────────────────────────────────────────────
  {
    cat: 'perf', catLabel: 'Performance',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Computer Running Very Slow',
    sub: 'General performance degradation',
    symptoms: ['Programs take minutes to open','High disk or CPU usage','System unresponsive after boot'],
    diag: ['Open Task Manager → sort by CPU/Memory/Disk','Check disk health with CrystalDiskInfo','Run msconfig → Startup tab','Check for malware with Malwarebytes'],
    resolution: 'Kill resource hogs → disable startup items → check for malware → upgrade RAM or switch to SSD',
    resDetail: '100% disk usage is common on machines with HDD + Windows 10/11. Disable Superfetch/SysMain, Windows Search indexing temporarily to test.',
    time: '30–120 min',
    tools: ['Task Manager', 'Malwarebytes', 'CrystalDiskInfo', 'Autoruns'],
    escalate: 'If hardware bottleneck confirmed, escalate for hardware upgrade (RAM/SSD)',
    prevention: 'Minimum 8GB RAM, SSD for OS; manage startup programs; regular malware scans'
  },
  {
    cat: 'perf', catLabel: 'Performance',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'High CPU Usage',
    sub: 'Process consuming 100% CPU',
    symptoms: ['Fan running at full speed','System sluggish','Specific process showing high CPU in Task Manager'],
    diag: ['Identify process in Task Manager','Search process name online to verify legitimacy','Use Process Monitor for detailed tracking','Check for runaway Windows Update or antivirus scan'],
    resolution: 'Identify process → end if safe → update or reinstall associated app → check for malware',
    resDetail: 'Known high CPU culprits: MsMpEng (Defender scan), svchost (Windows Update), Chrome/Edge (too many tabs), WMI Provider Host.',
    time: '15–60 min',
    tools: ['Task Manager', 'Process Monitor', 'Malwarebytes', 'Autoruns'],
    escalate: 'If legitimate Windows process, schedule update/scan during off-hours',
    prevention: 'Schedule AV scans and updates outside business hours; use per-process CPU limits'
  },
  {
    cat: 'perf', catLabel: 'Performance',
    sev: 'low', sevLabel: 'LOW',
    problem: 'Low Memory / RAM Exhaustion',
    sub: 'Out of RAM errors',
    symptoms: ['"Low Memory" warning popup','System using pagefile heavily','Apps crash due to out of memory'],
    diag: ['Check RAM usage in Task Manager → Performance tab','Identify memory-hungry processes','Check for memory leaks (usage climbs over time)','Verify total installed RAM is recognized'],
    resolution: 'Close unnecessary apps → increase virtual memory → upgrade RAM → check for memory leaks',
    resDetail: 'For virtual memory: System Properties → Advanced → Performance Settings → Virtual Memory. Set to 1.5–3x RAM.',
    time: '15–60 min',
    tools: ['Task Manager', 'RAMMap', 'Resource Monitor'],
    escalate: 'Hardware upgrade (RAM) if consistently at 90%+ usage',
    prevention: 'Right-size RAM for workload (minimum 16GB for power users); monitor with alerts'
  },
  {
    cat: 'perf', catLabel: 'Performance',
    sev: 'low', sevLabel: 'LOW',
    problem: 'Slow Application Load Times',
    sub: 'App startup performance',
    symptoms: ['Specific app takes 30+ seconds to open','Loading screen hangs','Other apps open normally'],
    diag: ['Check if app is on HDD vs SSD','Review startup impact in Task Manager','Profile app startup with ProcMon','Check for corrupt app cache or registry entries'],
    resolution: 'Move app/install to SSD → clear app cache → repair installation → rebuild index',
    resDetail: 'For Outlook: disable add-ins one by one. For browsers: profile with about:tracing. For office apps: disable hardware acceleration.',
    time: '20–60 min',
    tools: ['Process Monitor', 'Task Manager', 'App built-in diagnostics'],
    escalate: 'If app is server-based, check server response times and network latency',
    prevention: 'Install frequently-used apps on SSD; regularly review and disable unused add-ins'
  },

  // ─── STORAGE ────────────────────────────────────────────────────────────────
  {
    cat: 'storage', catLabel: 'Storage',
    sev: 'high', sevLabel: 'HIGH',
    problem: 'Disk Full — No Space Left',
    sub: 'Storage capacity exhausted',
    symptoms: ['"Disk is full" errors','Cannot save files','OS warnings about low disk space'],
    diag: ['Run: WinDirStat or TreeSize Free to identify large folders','Check for large log files in C:\\Windows\\Logs','Check Recycle Bin size','Look for large files in %TEMP%'],
    resolution: 'Run Disk Cleanup → clear %TEMP% → uninstall unused software → move data to network/external storage',
    resDetail: 'Common culprits: Windows.old (after upgrade), hiberfil.sys, pagefile.sys, large user downloads, application logs.',
    time: '30–120 min',
    tools: ['WinDirStat', 'Disk Cleanup', 'Storage Sense', 'TreeSize Free'],
    escalate: 'If recurring, escalate for disk expansion or cloud storage migration',
    prevention: 'Storage alerts at 80% full; automated cleanup policies; quotas for user profiles'
  },
  {
    cat: 'storage', catLabel: 'Storage',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'OneDrive / Cloud Sync Not Working',
    sub: 'Cloud sync failure',
    symptoms: ['Files not syncing to cloud','OneDrive shows error icon','Sync pending indefinitely'],
    diag: ['Check OneDrive status icon and error messages','Verify internet connectivity and account sign-in','Check for files with unsupported characters in name','Review sync exclusion list and bandwidth limits'],
    resolution: 'Reset OneDrive → re-sign in → check file names → adjust bandwidth throttling → unlink and relink account',
    resDetail: 'Reset OneDrive: %localappdata%\\Microsoft\\OneDrive\\onedrive.exe /reset. Files blocked by name: max 260 chars, no: \\ / : * ? " < > |',
    time: '15–60 min',
    tools: ['OneDrive status tray icon', 'OneDrive reset', 'M365 Admin Center'],
    escalate: 'If org-wide, check M365 service health and storage quota at tenant level',
    prevention: 'Enforce file naming conventions; monitor sync errors in M365 Admin; set appropriate storage quotas'
  },
  {
    cat: 'storage', catLabel: 'Storage',
    sev: 'low', sevLabel: 'LOW',
    problem: 'USB Drive / External Drive Not Recognized',
    sub: 'Removable media detection failure',
    symptoms: ['Drive plugged in but not in Explorer','Heard connection sound but no drive letter','Drive Manager shows unallocated'],
    diag: ['Open Disk Management (diskmgmt.msc)','Check Device Manager for unknown device','Try on another USB port (avoid hubs)','Test drive on another PC'],
    resolution: 'Assign drive letter in Disk Management → update driver → initialize disk → test on another port',
    resDetail: 'If unallocated: data risk — use TestDisk for partition recovery before formatting. If RAW: use Recuva first.',
    time: '10–30 min',
    tools: ['Disk Management', 'Device Manager', 'TestDisk', 'Recuva'],
    escalate: 'If drive clicking or not detected at all on multiple PCs, data recovery service needed',
    prevention: 'Always safely eject before unplugging; use quality USB hubs; backup critical data'
  },
  {
    cat: 'storage', catLabel: 'Storage',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Backup Failing / Not Running',
    sub: 'Backup job failure',
    symptoms: ['Backup job reports error','No recent successful backup','Backup software not responding'],
    diag: ['Review backup software logs for error codes','Check destination storage space and connectivity','Verify backup service is running','Test backup manually'],
    resolution: 'Check destination → free up space → fix connectivity → run test backup → verify integrity',
    resDetail: 'Common causes: destination full, network share unavailable, VSS errors, file locks. Always verify restores, not just backups.',
    time: '30–120 min',
    tools: ['Backup software logs', 'vssadmin list writers', 'Event Viewer', 'Storage console'],
    escalate: 'If no successful backup for > 24h in production: P1 incident; escalate to management',
    prevention: '3-2-1 backup rule; automated alerts on failure; monthly restore tests'
  },

  // ─── MORE ITEMS ─────────────────────────────────────────────────────────────
  {
    cat: 'network', catLabel: 'Network',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'DNS Resolution Failure',
    sub: 'Cannot resolve hostnames',
    symptoms: ['Websites unreachable by name but IP works','nslookup fails','"DNS_PROBE_FINISHED_NXDOMAIN"'],
    diag: ['Test: ping 8.8.8.8 (IP works?) vs ping google.com (name fails?)','Run: ipconfig /flushdns','Check DNS server settings: ipconfig /all','Try alternate DNS: 8.8.8.8 or 1.1.1.1'],
    resolution: 'Flush DNS → change to public DNS (8.8.8.8 / 1.1.1.1) → restart DNS Client service',
    resDetail: 'net stop dnscache && net start dnscache. If internal DNS broken, check DNS server service on domain controller.',
    time: '5–30 min',
    tools: ['ipconfig', 'nslookup', 'Resolve-DnsName (PowerShell)'],
    escalate: 'If internal DNS is broken, escalate to DNS server admin (usually same as DC admin)',
    prevention: 'Configure secondary DNS; monitor DNS server health; document internal DNS zones'
  },
  {
    cat: 'hardware', catLabel: 'Hardware',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'No Sound / Audio Not Working',
    sub: 'Audio output failure',
    symptoms: ['No audio from speakers or headphones','Audio icon has red X','Sound settings show no devices'],
    diag: ['Check volume mixer in system tray','Check Device Manager for audio device','Run audio troubleshooter','Test with different audio device'],
    resolution: 'Check volume → set correct default device → reinstall audio driver → check hardware connection',
    resDetail: 'Right-click speaker icon → Open Volume Mixer. Check Playback Devices. Roll back or reinstall Realtek/IDT driver from Device Manager.',
    time: '10–30 min',
    tools: ['Device Manager', 'Sound settings', 'Realtek/HD Audio driver'],
    escalate: 'If hardware audio chip failure, replace sound card or use USB audio adapter',
    prevention: 'Keep audio drivers updated via Windows Update or vendor software'
  },
  {
    cat: 'software', catLabel: 'Software',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Remote Desktop (RDP) Not Connecting',
    sub: 'Remote access failure',
    symptoms: ['"Can\'t connect to remote PC"','RDP times out','Credentials rejected on RDP'],
    diag: ['Verify RDP is enabled on target: SystemProperties → Remote → Allow RDP','Check Windows Firewall allows TCP 3389','Ping the target machine','Verify user account is in Remote Desktop Users group'],
    resolution: 'Enable RDP on target → open firewall port 3389 → add user to RDP group → verify NLA settings',
    resDetail: 'Enable via: reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f',
    time: '10–30 min',
    tools: ['mstsc', 'wf.msc', 'sysdm.cpl', 'PowerShell'],
    escalate: 'For enterprise, use Remote Desktop Gateway for external access instead of direct port exposure',
    prevention: 'Never expose port 3389 directly to internet; use RD Gateway or VPN'
  },
  {
    cat: 'os', catLabel: 'OS',
    sev: 'low', sevLabel: 'LOW',
    problem: 'Date / Time Wrong',
    sub: 'Clock synchronization failure',
    symptoms: ['System clock shows wrong time','SSL/HTTPS certificate errors','Kerberos auth failing (AD environments)'],
    diag: ['Check system clock and timezone','Test NTP sync: w32tm /query /status','Check internet time server reachability','In AD: check PDC emulator time'],
    resolution: 'Sync time: w32tm /resync → set correct timezone → configure NTP server → check CMOS battery',
    resDetail: 'AD requires time within 5 minutes. PDC emulator is authoritative. Non-domain: w32tm /config /manualpeerlist:"pool.ntp.org" /syncfromflags:manual /reliable:YES /update',
    time: '5–20 min',
    tools: ['w32tm', 'Date/Time settings', 'BIOS/UEFI'],
    escalate: 'CMOS battery replacement if clock resets after every reboot',
    prevention: 'Ensure all devices sync to reliable NTP; monitor clock drift in AD'
  },
  {
    cat: 'security', catLabel: 'Security',
    sev: 'high', sevLabel: 'HIGH',
    problem: 'SSL Certificate Error',
    sub: 'Certificate trust failure',
    symptoms: ['"Your connection is not private"','NET::ERR_CERT_EXPIRED in browser','Certificate name mismatch warning'],
    diag: ['Check cert expiry: click padlock in browser','Verify system date/time is correct','Check if cert CN matches domain','Inspect cert chain for missing intermediate'],
    resolution: 'Renew expired cert → install intermediate CA cert → fix date/time → update hostname',
    resDetail: 'Check cert dates. Renew via CA. Install intermediates in cert store. Use Qualys SSL Labs for full chain analysis.',
    time: '30–120 min',
    tools: ['SSL Labs (ssllabs.com)', 'OpenSSL', 'Certmgr.msc', 'Certreq'],
    escalate: 'If wildcard cert, renew and redeploy across all systems; set 60-day renewal reminder',
    prevention: 'Auto-renew via Let\'s Encrypt (ACME) or set calendar alerts 60 days before expiry'
  },
  {
    cat: 'perf', catLabel: 'Performance',
    sev: 'low', sevLabel: 'LOW',
    problem: 'Startup Taking Too Long',
    sub: 'Slow boot time',
    symptoms: ['PC takes 2–5+ minutes to be usable after login','Many startup programs running','HDDs worsen this significantly'],
    diag: ['Enable Boot Time in Task Manager (Settings → Startup tab)','Use autoruns.exe to view all startup items','Check Event Viewer → System → Bootup time','Run: reagentc /info to check WinRE status'],
    resolution: 'Disable unnecessary startup programs → delay non-essential services → upgrade to SSD',
    resDetail: 'In Task Manager Startup: disable anything non-essential. Use Autoruns for deeper control. SSD upgrade is the #1 fix for slow boots.',
    time: '20–60 min',
    tools: ['Task Manager Startup', 'Autoruns', 'msconfig'],
    escalate: 'Hardware upgrade (SSD) if startup time > 3 minutes on modern hardware',
    prevention: 'Limit installed software; SSD for OS; GPO to manage startup items enterprise-wide'
  },
  {
    cat: 'email', catLabel: 'Email',
    sev: 'low', sevLabel: 'LOW',
    problem: 'Large Attachment Can\'t Send',
    sub: 'Message size limit exceeded',
    symptoms: ['"Message too large" error','Email rejected by server','Attachment limit hit'],
    diag: ['Check max attachment size policy in Exchange/M365','Test recipient\'s server size limits (they may be lower)','Check NDR error code (e.g., 552 5.3.4)'],
    resolution: 'Use file sharing link instead (OneDrive/SharePoint/Google Drive) → increase limit if policy allows',
    resDetail: 'M365 default: 25MB. Max: 150MB. Recipient limits may differ. Best practice: share via link for files > 10MB.',
    time: '5–15 min',
    tools: ['Exchange Admin Center', 'OneDrive', 'SharePoint link sharing'],
    escalate: 'If regular need for large attachments, consider file collaboration platform policy',
    prevention: 'Train users to use file-sharing links; set appropriate size limits; automate large-file rerouting'
  },

  // ─── AUDIO / VIDEO ──────────────────────────────────────────────────────────
  {
    cat: 'audio', catLabel: 'Audio/Video',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Microphone Not Working in Meetings',
    sub: 'Audio input failure',
    symptoms: ['Others can\'t hear you in Teams/Zoom','Mic shows no input in sound settings','Mic works in one app but not another'],
    diag: ['Check default recording device in Sound settings → Recording tab','Verify app has mic permission (Settings → Privacy → Microphone)','Test in Voice Recorder app','Check if mic is muted in app AND in Windows'],
    resolution: 'Set correct default mic → grant app permissions → test in Voice Recorder → update driver',
    resDetail: 'Right-click speaker icon → Sounds → Recording → set mic as Default. In Teams: Settings → Devices → select correct mic. Restart audio service.',
    time: '5–20 min',
    tools: ['Sound settings', 'Voice Recorder', 'Device Manager', 'Teams/Zoom settings'],
    escalate: 'If driver reinstall fails, try USB audio adapter as workaround',
    prevention: 'Set default audio devices via GPO; test audio before meetings'
  },
  {
    cat: 'audio', catLabel: 'Audio/Video',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Webcam Not Detected',
    sub: 'Camera not recognized',
    symptoms: ['Camera missing from app dropdowns','Black screen in video call','"No camera found" error'],
    diag: ['Check Device Manager for camera device','Verify privacy setting: Settings → Privacy → Camera','Test in Windows Camera app','Check if physical camera shutter/switch is open'],
    resolution: 'Enable camera in privacy settings → reinstall driver → test in Camera app → check physical shutter',
    resDetail: 'Device Manager → Imaging Devices. If missing, scan for hardware changes. Uninstall then reinstall driver. Check USB connection for external cams.',
    time: '10–30 min',
    tools: ['Device Manager', 'Windows Camera app', 'Privacy Settings'],
    escalate: 'Replace webcam if hardware fault confirmed across multiple driver reinstalls',
    prevention: 'Keep camera drivers updated; configure privacy settings via MDM/Intune'
  },
  {
    cat: 'audio', catLabel: 'Audio/Video',
    sev: 'low', sevLabel: 'LOW',
    problem: 'Echo / Feedback During Calls',
    sub: 'Audio loopback problem',
    symptoms: ['Other callers hear echo','Feedback squeal during meetings','Only occurs with certain participants'],
    diag: ['Identify who is causing echo (mute participants one by one)','Check if speakerphone + open mic is the cause','Verify echo cancellation is enabled in app','Check headset vs speaker usage'],
    resolution: 'Switch to headset → enable echo cancellation in app → reduce speaker volume → mute when not speaking',
    resDetail: 'Echo usually comes from speaker audio entering open microphone. Headsets with built-in echo cancellation resolve 95% of cases.',
    time: '5–15 min',
    tools: ['Teams/Zoom audio settings', 'Headset with noise cancellation'],
    escalate: 'If echo persists with headset, check app-level noise suppression settings',
    prevention: 'Require headsets in meeting-heavy roles; enable noise suppression by default in collaboration tools'
  },
  {
    cat: 'audio', catLabel: 'Audio/Video',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Screen Share Showing Black / Blank',
    sub: 'Screen capture failure',
    symptoms: ['Others see black screen when you share','Screen share works but window shows blank','DRM content blocks screen capture'],
    diag: ['Check GPU driver (common after updates)','Test sharing full screen vs specific window','On Windows 11: check hardware-accelerated GPU scheduling','Check if DRM is blocking (Netflix, etc.)'],
    resolution: 'Update/rollback GPU driver → disable hardware acceleration in app → share full screen instead of window',
    resDetail: 'Teams/Zoom: Settings → General → disable GPU hardware acceleration. On older GPU drivers, window capture fails. Full-screen sharing usually works.',
    time: '10–25 min',
    tools: ['GPU driver update', 'Teams/Zoom settings', 'Device Manager'],
    escalate: 'Escalate to app vendor if persists after GPU driver update',
    prevention: 'Standardize GPU driver versions across org; test screen share after driver updates'
  },

  // ─── MOBILE ────────────────────────────────────────────────────────────────
  {
    cat: 'mobile', catLabel: 'Mobile',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Corporate Email Not Syncing on Mobile',
    sub: 'MDM / ActiveSync failure',
    symptoms: ['Email app shows sync error','Calendar not updating','Enrollment failed error'],
    diag: ['Check MDM enrollment status in Company Portal','Verify ActiveSync is enabled for user in EAC','Check device compliance policy (OS version, PIN, encryption)','Test with Outlook mobile app (more reliable than native)'],
    resolution: 'Re-enroll device in MDM → ensure device compliance → use Outlook mobile → check ActiveSync policy',
    resDetail: 'In M365 EAC: Recipients → Mailboxes → [user] → Mobile Devices → check device status. Block/allow device if needed. Require Outlook app via Intune app protection policies.',
    time: '20–60 min',
    tools: ['Intune/Company Portal', 'Exchange Admin Center', 'Outlook mobile'],
    escalate: 'Escalate to MDM admin if device compliance policies are blocking access',
    prevention: 'Deploy Outlook mobile via Intune; enforce app protection policies; require MFA for mobile access'
  },
  {
    cat: 'mobile', catLabel: 'Mobile',
    sev: 'low', sevLabel: 'LOW',
    problem: 'Mobile Device Won\'t Connect to Corporate Wi-Fi',
    sub: '802.1X / WPA2-Enterprise failure',
    symptoms: ['Can\'t authenticate to corporate SSID','Certificate error on connection','Works on guest Wi-Fi but not corporate'],
    diag: ['Check if device has required certificate installed','Verify 802.1X settings: EAP type, identity, password','Check RADIUS server logs','Test with known-good device credentials'],
    resolution: 'Install enterprise certificate → configure correct EAP settings → enroll in MDM for auto-configuration',
    resDetail: 'Enterprise Wi-Fi requires device/user certificate or domain credentials. Deploy Wi-Fi profile via Intune/MDM to auto-configure. PEAP-MSCHAPv2 is most common.',
    time: '15–45 min',
    tools: ['Intune Wi-Fi profiles', 'RADIUS logs', 'Certificates app (mobile)'],
    escalate: 'Escalate to network team if RADIUS authentication is failing server-side',
    prevention: 'Deploy Wi-Fi profiles via MDM; automate certificate enrollment with SCEP/NDES'
  },
  {
    cat: 'mobile', catLabel: 'Mobile',
    sev: 'high', sevLabel: 'HIGH',
    problem: 'Lost / Stolen Corporate Device',
    sub: 'Device security incident',
    symptoms: ['Device cannot be located','User reports device missing','Device not checking in to MDM'],
    diag: ['Locate device via MDM (Intune → Devices → [device])','Check last sync time and location','Verify if device is still active on cellular/Wi-Fi','Review recent access logs from device'],
    resolution: 'Remote lock immediately → remote wipe if data at risk → disable corporate credentials → report to security',
    resDetail: 'Intune: Actions → Remote Lock first (preserves data for recovery). If confirmed lost: Retire (remove corporate) or Wipe (factory reset). Revoke user tokens in Azure AD.',
    time: '15–60 min',
    tools: ['Intune/MDM console', 'Azure AD (revoke sessions)', 'Find My (iOS) / Find My Device (Android)'],
    escalate: 'Treat as security incident; notify CISO if sensitive data was on device',
    prevention: 'Enforce full-disk encryption and PIN via MDM; use app-level wipe (MAM) over full device wipe'
  },
  {
    cat: 'mobile', catLabel: 'Mobile',
    sev: 'low', sevLabel: 'LOW',
    problem: 'App Won\'t Install from Company Portal',
    sub: 'Managed app deployment failure',
    symptoms: ['App stuck in "Pending Install" in Company Portal','App installs but immediately fails','"This app is not available" error'],
    diag: ['Check device compliance in Intune','Verify app assignment targets the user/group','Check available storage on device','Review Intune app deployment logs'],
    resolution: 'Force device sync → check compliance → verify assignment → re-push app deployment',
    resDetail: 'In Intune: Devices → [device] → Managed Apps. Sync device: Company Portal → Settings → Sync. Check Intune for deployment errors (error codes).',
    time: '15–40 min',
    tools: ['Intune Admin Center', 'Company Portal app', 'Intune troubleshooting portal'],
    escalate: 'Escalate to Intune admin if deployment error code indicates policy conflict',
    prevention: 'Test app deployments on pilot group first; maintain device compliance to avoid blocks'
  },

  // ─── REMOTE WORK ────────────────────────────────────────────────────────────
  {
    cat: 'remote', catLabel: 'Remote Work',
    sev: 'high', sevLabel: 'HIGH',
    problem: 'Remote Desktop Gateway Failing',
    sub: 'RD Gateway connection error',
    symptoms: ['Cannot connect via RD Gateway externally','SSL certificate error on RDG','Authenticates but session won\'t launch'],
    diag: ['Check RD Gateway certificate validity and SAN names','Verify RD Gateway port 443 is open on firewall','Test internal RDP to confirm target is reachable','Review RD Gateway event logs (TerminalServices-Gateway)'],
    resolution: 'Renew/fix gateway certificate → check firewall rule for 443 → verify CAP/RAP policies → check target availability',
    resDetail: 'RD Gateway uses HTTPS (443). Check Connection Authorization Policy (CAP) and Resource Authorization Policy (RAP). Ensure user is in correct AD group for access.',
    time: '30–90 min',
    tools: ['Remote Desktop Gateway Manager', 'Event Viewer', 'SSL checker', 'netstat'],
    escalate: 'Consider moving to Azure Virtual Desktop or Windows 365 for modern remote access',
    prevention: 'Auto-renew certificates; monitor RDG uptime; document CAP/RAP policies'
  },
  {
    cat: 'remote', catLabel: 'Remote Work',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Split Tunneling / VPN Routing Issues',
    sub: 'Traffic routing misconfiguration',
    symptoms: ['VPN connected but can\'t reach internet','Internal resources work but cloud apps slow','Corporate traffic going through VPN unnecessarily'],
    diag: ['Check route table while VPN is connected: route print','Identify what traffic is being tunneled','Review VPN client split-tunnel configuration','Test with VPN connected: curl ifconfig.me (external IP check)'],
    resolution: 'Configure split tunneling to only tunnel corporate subnets → exclude cloud services (M365, etc.) from VPN',
    resDetail: 'Add exclusion routes for M365 IPs (Microsoft publishes these). Configure VPN to tunnel only RFC1918 ranges. M365 traffic should NOT go through VPN.',
    time: '30–120 min',
    tools: ['route print', 'VPN admin console', 'Microsoft M365 IP/URL feed'],
    escalate: 'Escalate to network team for VPN concentrator configuration changes',
    prevention: 'Follow Microsoft\'s VPN split tunneling guidance; use Conditional Access instead of VPN for cloud apps'
  },
  {
    cat: 'remote', catLabel: 'Remote Work',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Home Internet Too Slow for Work',
    sub: 'Residential bandwidth insufficient',
    symptoms: ['Video calls dropping/pixelating','File uploads/downloads very slow','VPN further degrades performance'],
    diag: ['Run speed test before and during work hours','Check router QoS settings','Identify other bandwidth consumers on home network','Test wired vs wireless performance'],
    resolution: 'Use wired connection → enable QoS to prioritize work traffic → upgrade ISP plan → schedule heavy transfers off-hours',
    resDetail: 'For Teams: requires 1.5Mbps up/down per call. Ethernet eliminates Wi-Fi variability. Consider mobile hotspot as backup. Use Together Mode or lower video quality in calls.',
    time: '20–60 min',
    tools: ['Speedtest.net', 'Router QoS', 'Ethernet cable', 'Teams bandwidth settings'],
    escalate: 'IT can provide mobile hotspot stipend or access to local coworking space',
    prevention: 'Provide home networking guidelines; consider ISP reimbursement policy; use cloud apps to reduce VPN dependency'
  },

  // ─── CLOUD / M365 ──────────────────────────────────────────────────────────
  {
    cat: 'cloud', catLabel: 'Cloud/M365',
    sev: 'high', sevLabel: 'HIGH',
    problem: 'SharePoint / OneDrive Site Access Denied',
    sub: 'Permission denied on SharePoint',
    symptoms: ['"Access Denied" on SharePoint site','User can see site in search but not open it','Shared link says "You need access"'],
    diag: ['Check if user has been granted site access','Verify sharing permissions: Site Settings → Site Permissions','Check if site has unique permissions or inherits','Review Access Requests in site settings'],
    resolution: 'Add user to correct SharePoint group → grant direct permissions → check if site is restricted → process access request',
    resDetail: 'In SharePoint: Site Settings → Permissions → Grant Permissions. Use groups (Members/Visitors/Owners) not individual permissions. Check if hub site is restricting access.',
    time: '5–20 min',
    tools: ['SharePoint Admin Center', 'M365 Admin Center', 'SharePoint Site Settings'],
    escalate: 'If external sharing is needed, verify tenant-level external sharing policy first',
    prevention: 'Use M365 Groups for SharePoint access; enable Access Request emails; review permissions quarterly'
  },
  {
    cat: 'cloud', catLabel: 'Cloud/M365',
    sev: 'high', sevLabel: 'HIGH',
    problem: 'Azure AD / Entra Sign-In Conditional Access Blocking',
    sub: 'CA policy blocking access',
    symptoms: ['"Your organization has blocked this device"','Compliant device required error','Can\'t sign in from certain locations'],
    diag: ['Check Sign-in Logs in Entra ID → review failure reason','Identify which Conditional Access policy is triggering','Check device compliance status in Intune','Verify user location matches allowed countries'],
    resolution: 'Check CA policy → enroll device in Intune → verify device compliance → update policy exclusion if legitimate',
    resDetail: 'Entra ID → Sign-in logs → [event] → Conditional Access tab shows exactly which policy blocked. Add user/device to policy exclusion if needed. Compliance issues: fix in Intune.',
    time: '15–45 min',
    tools: ['Entra ID Sign-in Logs', 'Intune Admin Center', 'CA Policy What-If tool'],
    escalate: 'Use Entra CA What-If tool to simulate policy impact before changes',
    prevention: 'Use CA report-only mode before enabling; maintain policy documentation; create break-glass accounts'
  },
  {
    cat: 'cloud', catLabel: 'Cloud/M365',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'M365 License Not Assigned / Feature Missing',
    sub: 'Licensing gap',
    symptoms: ['User missing Teams, Exchange, or other M365 app','Feature greyed out in portal','"Your admin has disabled" message'],
    diag: ['Check license assignment in M365 Admin → Users → Active Users → [user] → Licenses','Verify specific service plan is enabled within license','Check if feature requires add-on license (Copilot, Audio Conf, etc.)','Review group-based licensing if used'],
    resolution: 'Assign correct license → enable required service plan → wait up to 24h for propagation → check service plan conflicts',
    resDetail: 'Licenses can be assigned directly or via groups. Service plan conflicts (e.g., two Exchange Online plans) can cause issues. Use PowerShell: Get-MgUserLicenseDetail.',
    time: '5–30 min',
    tools: ['M365 Admin Center', 'Azure AD Licensing', 'Microsoft 365 Admin PowerShell'],
    escalate: 'Procurement required if additional licenses needed (budget approval)',
    prevention: 'License tracking in IT asset management; automate license assignment via Entra groups; monitor utilization'
  },
  {
    cat: 'cloud', catLabel: 'Cloud/M365',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Teams / SharePoint Files Tab Not Loading',
    sub: 'SharePoint document library error in Teams',
    symptoms: ['Files tab shows error in Teams channel','Documents won\'t load or sync','"Something went wrong" in Teams files'],
    diag: ['Test accessing SharePoint site directly in browser','Clear Teams cache: %appdata%\\Microsoft\\Teams','Check if SharePoint site is accessible','Verify channel\-linked SharePoint isn\'t deleted'],
    resolution: 'Clear Teams cache → access SharePoint directly → re-pin Files tab → check SharePoint site health',
    resDetail: 'Teams Files tab is a SharePoint document library frame. If SharePoint site was deleted/moved, re-link is needed. Clear cache: close Teams → delete %appdata%\\Microsoft\\Teams\\Cache → restart.',
    time: '10–30 min',
    tools: ['Teams cache folder', 'SharePoint Admin Center', 'Browser (direct SP access)'],
    escalate: 'If SharePoint site was deleted, check SharePoint Admin recycle bin (90-day recovery window)',
    prevention: 'Protect Teams-linked SharePoint sites; back up before deleting channels'
  },
  {
    cat: 'cloud', catLabel: 'Cloud/M365',
    sev: 'low', sevLabel: 'LOW',
    problem: 'OneDrive Storage Quota Exceeded',
    sub: 'User cloud storage full',
    symptoms: ['OneDrive sync paused with quota warning','Can\'t upload new files','Storage indicator at 100%'],
    diag: ['Check storage usage: OneDrive web → Settings → Storage','Identify largest folders/files','Check if versioning is consuming excessive space','Look for large files in recycle bin'],
    resolution: 'Delete unnecessary files → empty OneDrive recycle bin → reduce version history limits → request quota increase',
    resDetail: 'OneDrive recycle bin counts against quota. Version history default: unlimited. Reduce via SharePoint admin: Libraries → Versioning → set major version limit.',
    time: '15–30 min',
    tools: ['OneDrive web', 'SharePoint Admin Center', 'M365 Admin Center'],
    escalate: 'Request additional storage via M365 admin (additional storage add-on) or enforce archival policy',
    prevention: 'Set storage quotas; monitor via M365 reports; educate users on version control'
  },

  // ─── VIRTUALIZATION ─────────────────────────────────────────────────────────
  {
    cat: 'virt', catLabel: 'Virtualization',
    sev: 'critical', sevLabel: 'CRITICAL',
    problem: 'VM Won\'t Start / Failed to Power On',
    sub: 'Virtual machine startup failure',
    symptoms: ['VM shows "Failed" status in vSphere/Hyper-V','Error: "Not enough CPU/Memory resources"','VM config file (.vmx/.xml) corrupt'],
    diag: ['Check host resource availability (CPU, RAM, storage)','Review VM event logs in hypervisor','Check if VM config files are intact','Verify datastore/storage is accessible and has free space'],
    resolution: 'Free host resources → check datastore → repair or restore VM config → migrate to another host',
    resDetail: 'In vSphere: right-click VM → Edit Settings → verify resource reservations. For Hyper-V: Get-VM | Where Status -eq "Off". Check event 18210 for config errors.',
    time: '20–120 min',
    tools: ['vSphere/vCenter', 'Hyper-V Manager', 'PowerCLI', 'PowerShell'],
    escalate: 'If hardware failure on host, migrate VMs via vMotion/Live Migration before host goes offline',
    prevention: 'Monitor host capacity; set alerts at 80% utilization; use VM HA/failover clusters'
  },
  {
    cat: 'virt', catLabel: 'Virtualization',
    sev: 'high', sevLabel: 'HIGH',
    problem: 'VM Performance Degraded / High Latency',
    sub: 'Virtual machine slow',
    symptoms: ['Guest OS sluggish while host is fine','High CPU Ready % in vSphere','Storage latency spikes in guest'],
    diag: ['Check CPU Ready in vSphere (should be < 5%)','Review memory balloon/swap in VM performance charts','Check datastore latency (aim < 20ms)','Verify VMware Tools / Hyper-V Integration Services installed and current'],
    resolution: 'Reduce CPU Ready by adding vCPUs or adjusting reservations → fix storage latency → update VMware Tools',
    resDetail: 'CPU Ready > 10% = CPU oversubscription. Add vCPUs or reduce NUMA misalignment. Storage: move VMDK to faster datastore. Update VMware Tools in guest.',
    time: '30–120 min',
    tools: ['vSphere Performance Charts', 'esxtop', 'Hyper-V Perf Monitor', 'VMware Tools'],
    escalate: 'Add physical host resources or migrate VM to less-loaded host',
    prevention: 'Never overcommit more than 4:1 vCPU to pCPU; monitor CPU Ready and storage KAVG continuously'
  },
  {
    cat: 'virt', catLabel: 'Virtualization',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Snapshot Storage Growing Uncontrolled',
    sub: 'VM snapshot chain bloat',
    symptoms: ['Datastore running out of space','VM snapshot files (VMDK-delta) very large','VM performance degrading over time'],
    diag: ['Check VM snapshot manager (right-click → Snapshots → Manage)','Review datastore usage: which VM is consuming most','Check for orphaned snapshots (not in VM manager)','Look for snapshots older than 7 days (warning sign)'],
    resolution: 'Consolidate or delete old snapshots → check for orphaned snapshot files → clean up delta VMDKs',
    resDetail: 'Never leave snapshots longer than 72h in production. Consolidate: VM → Snapshots → Consolidate. For orphans, use vSphere KB to identify and remove manually.',
    time: '30–180 min',
    tools: ['vSphere Snapshot Manager', 'PowerCLI', 'Datastore Browser'],
    escalate: 'Large snapshot removal can cause brief I/O spike — schedule during maintenance window',
    prevention: 'Enforce snapshot policy: max 3 days, alert if any snapshot > 24h via monitoring; use backup instead of snapshots'
  },
  {
    cat: 'virt', catLabel: 'Virtualization',
    sev: 'high', sevLabel: 'HIGH',
    problem: 'Hyper-V / VMware Network Adapter Not Working in VM',
    sub: 'Guest VM networking failure',
    symptoms: ['VM has no network connectivity','Virtual NIC missing in guest Device Manager','VM can ping host but not external'],
    diag: ['Check virtual switch assignment in hypervisor','Verify VLAN tag is correct','Test with different virtual switch or NIC type','Check Integration Services / VMware Tools status'],
    resolution: 'Reassign to correct virtual switch → fix VLAN config → reinstall virtual NIC driver → update Tools',
    resDetail: 'For vSphere: Edit VM → Network Adapter → change network/VMXNET3. For Hyper-V: check external virtual switch. VLAN mismatch is common cause of one-way traffic.',
    time: '15–45 min',
    tools: ['vSphere/Hyper-V manager', 'Guest Device Manager', 'VMware Tools installer'],
    escalate: 'Check physical switch port if VLAN issues persist at hypervisor level',
    prevention: 'Document VM network mappings; validate VLAN config after infrastructure changes'
  },

  // ─── TEAMS / COLLABORATION ───────────────────────────────────────────────────
  {
    cat: 'teams', catLabel: 'Teams/Collab',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Microsoft Teams Keeps Crashing',
    sub: 'Teams client instability',
    symptoms: ['Teams closes unexpectedly','White/blank screen in Teams','Teams won\'t open after update'],
    diag: ['Clear Teams cache: %appdata%\\Microsoft\\Teams','Check Windows Event Viewer for crash details','Try Teams Web app (teams.microsoft.com) to isolate client vs service','Check for conflicting app or GPU driver issue'],
    resolution: 'Clear cache → repair/reinstall Teams → try web app → roll back GPU driver if related',
    resDetail: 'Full cache clear: close Teams completely → delete entire %appdata%\\Microsoft\\Teams folder contents → relaunch. Avoid clearing Backgrounds folder if custom backgrounds used.',
    time: '10–30 min',
    tools: ['%appdata%\\Microsoft\\Teams', 'Event Viewer', 'Teams web app', 'Teams Machine-Wide Installer'],
    escalate: 'Switch to Teams web app as workaround; report to Microsoft via Feedback (Ctrl+Alt+Shift+1)',
    prevention: 'Use Teams Machine-Wide Installer for enterprise; manage via Intune for consistent deployment'
  },
  {
    cat: 'teams', catLabel: 'Teams/Collab',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Teams Meeting Audio / Video Poor Quality',
    sub: 'Call quality degradation',
    symptoms: ['Choppy audio in Teams calls','Pixelated or frozen video','Calls dropping frequently'],
    diag: ['Check Call Analytics in Teams Admin: Admin → Users → [user] → Meetings','Review CQD (Call Quality Dashboard) for network metrics','Test user\'s network: run Microsoft Network Assessment Tool','Check if issue is Wi-Fi or wired'],
    resolution: 'Diagnose via CQD → improve network path → switch to wired → adjust Teams video quality settings',
    resDetail: 'Teams requires < 150ms latency, < 1% packet loss, < 30ms jitter. Use Microsoft Network Assessment Tool to test. Split tunneling for Teams traffic over VPN is critical.',
    time: '30–120 min',
    tools: ['Teams Admin Center (Call Analytics)', 'CQD Dashboard', 'Network Assessment Tool', 'Wireshark'],
    escalate: 'Escalate to network team if CQD shows consistent packet loss on internal segments',
    prevention: 'Configure QoS DSCP markings for Teams traffic; use ExpressRoute for large orgs; enable Call Quality Dashboard monitoring'
  },
  {
    cat: 'teams', catLabel: 'Teams/Collab',
    sev: 'low', sevLabel: 'LOW',
    problem: 'Teams Status Showing Wrong (Away/Offline)',
    sub: 'Presence status inaccurate',
    symptoms: ['Teams shows Away even when actively working','Status stuck on "Offline"','Colleagues see wrong availability'],
    diag: ['Check Teams presence sync with Outlook calendar','Verify computer is not going to sleep (affecting activity detection)','Check if another Teams session on another device is overriding','Review Quiet Hours / Focus settings'],
    resolution: 'Reset presence: click status → Reset Status → wait 2 min → or sign out and back in',
    resDetail: 'Teams updates presence every 5 minutes based on activity. Calendar meetings set it to "In a meeting". Outlook integration must be enabled. Admin: Presence-based routing may affect status.',
    time: '5–15 min',
    tools: ['Teams settings', 'Outlook Calendar', 'Teams Admin Center'],
    escalate: 'If org-wide, check Microsoft 365 service health for Teams presence issues',
    prevention: 'Configure sleep/screen saver settings correctly; educate users on manual status override'
  },
  {
    cat: 'teams', catLabel: 'Teams/Collab',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Can\'t Schedule Teams Meeting in Outlook',
    sub: 'Teams Outlook add-in failure',
    symptoms: ['Teams Meeting button missing in Outlook','Add-in shows as disabled','Meeting link not generated in invite'],
    diag: ['Check: File → Options → Add-ins → COM Add-ins → Microsoft Teams Meeting Add-in','Look for add-in in Disabled Items list','Verify both Teams and Outlook are same-user signed in','Check Group Policy blocking add-ins'],
    resolution: 'Enable add-in in COM Add-ins list → remove from Disabled Items → re-register add-in DLL → repair Teams',
    resDetail: 'Run as admin: regsvr32 "C:\\Users\\[user]\\AppData\\Local\\Microsoft\\TeamsMeetingAddin\\[version]\\x64\\Microsoft.Teams.AddinLoader.dll". Then restart Outlook.',
    time: '10–25 min',
    tools: ['Outlook Add-ins manager', 'regsvr32', 'Registry Editor', 'Teams repair'],
    escalate: 'If GPO is blocking add-ins, work with AD admin to add Teams add-in to allowed list',
    prevention: 'Deploy Teams + Outlook via same MSI package; include add-in in allowed list via GPO'
  },

  // ─── ACTIVE DIRECTORY ────────────────────────────────────────────────────────
  {
    cat: 'active', catLabel: 'Active Directory',
    sev: 'critical', sevLabel: 'CRITICAL',
    problem: 'Domain Controller Down / Unreachable',
    sub: 'AD infrastructure failure',
    symptoms: ['Users can\'t log in to domain','Group Policy not applying','DNS resolution failing for internal names'],
    diag: ['Ping DC by name and IP','Test: nltest /sc_query:domainname','Check DC services: netlogon, kdc, adws, dns','Review DC event logs: Directory Services, System'],
    resolution: 'Restart critical DC services → check replication health → restore from backup if DC is unrecoverable',
    resDetail: 'dcdiag /test:replications — check for replication failures. repadmin /showrepl. If DC is down, ensure another DC can service authentication. Never run DC in VM without UPS.',
    time: '30–480 min',
    tools: ['dcdiag', 'repadmin', 'nltest', 'Active Directory Sites and Services'],
    escalate: 'P1 incident — escalate to senior AD/infrastructure engineer immediately',
    prevention: 'Minimum 2 DCs per site; monitor DC health via SCOM/other; VM snapshots before changes; documented DR plan'
  },
  {
    cat: 'active', catLabel: 'Active Directory',
    sev: 'high', sevLabel: 'HIGH',
    problem: 'Group Policy Not Applying',
    sub: 'GPO deployment failure',
    symptoms: ['Settings not enforced on machines','Software not deploying via GPO','gpresult shows GPO not applied'],
    diag: ['Run: gpresult /h gpreport.html → review in browser','Check: gpupdate /force → any errors?','Verify GPO link and scope (WMI filter, security filtering)','Check if computer/user is in correct OU'],
    resolution: 'gpupdate /force → check OU membership → verify security filtering → fix WMI filter → fix replication',
    resDetail: 'gpresult /R shows applied/denied GPOs with reasons. Common causes: security group not including computer/user, WMI filter returning false, OU misplacement, AD replication lag.',
    time: '15–60 min',
    tools: ['gpresult', 'gpupdate', 'Group Policy Management Console', 'rsop.msc'],
    escalate: 'If AD replication is broken, GPO changes won\'t propagate — escalate to DC admin',
    prevention: 'Use GPMC to test GPO scope before linking; document all custom WMI filters; use RSoP to validate'
  },
  {
    cat: 'active', catLabel: 'Active Directory',
    sev: 'high', sevLabel: 'HIGH',
    problem: 'AD Replication Failure',
    sub: 'Domain replication broken',
    symptoms: ['Password changes not syncing across DCs','User created on one DC not visible on another','repadmin showing errors'],
    diag: ['Run: repadmin /replsummary','Run: repadmin /showrepl → look for consecutive failures','Check: dcdiag /test:replications','Review DNS entries for all DC SRV records'],
    resolution: 'Fix DNS SRV records → resolve firewall blocking AD ports → force replication → fix USN rollback if present',
    resDetail: 'AD replication needs ports 135, 49152-65535 (RPC), 389, 636, 3268, 88. Force replication: repadmin /syncall /AdeP. USN rollback: restore DC from backup.',
    time: '30–240 min',
    tools: ['repadmin', 'dcdiag', 'AD Sites and Services', 'DNS Manager'],
    escalate: 'USN rollback requires DC demotion and repromoion — escalate to senior AD engineer',
    prevention: 'Monitor replication with repadmin /replsummary in scheduled task; never snapshot DCs in production'
  },
  {
    cat: 'active', catLabel: 'Active Directory',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Computer Not Joining Domain',
    sub: 'Domain join failure',
    symptoms: ['"The specified domain doesn\'t exist or can\'t be contacted"','DNS error during domain join','Account limit reached error'],
    diag: ['Verify DNS is set to DC/internal DNS server (not 8.8.8.8)','Ping domain FQDN: ping corp.company.com','Check account used to join has domain join rights','Check machine account limit (default: 10 per user)'],
    resolution: 'Fix DNS to point to DC → use admin account with join rights → pre-stage computer account → check account limit',
    resDetail: 'Set DNS to DC IP first. Test: nslookup corp.company.com. Pre-stage in ADUC: New Computer → name it exactly. Error 0x6BF = max machine accounts reached for user.',
    time: '15–45 min',
    tools: ['ADUC', 'nslookup', 'ipconfig /all', 'netdom join'],
    escalate: 'If machine account limit hit, either pre-stage account or use privileged account for joining',
    prevention: 'Use dedicated service account for domain joins with proper rights; automate via Autopilot/MDM'
  },
  {
    cat: 'active', catLabel: 'Active Directory',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Trust Relationship Failed',
    sub: 'Secure channel broken',
    symptoms: ['"Trust relationship between this workstation and the primary domain failed"','Cannot log in with domain credentials','Appears only on specific machine'],
    diag: ['Try logging in with local admin account','Test secure channel: Test-ComputerSecureChannel','Check if machine account exists in ADUC','Check last password sync for machine account'],
    resolution: 'Reset secure channel: Reset-ComputerMachinePassword or netdom resetpwd → or rejoin domain',
    resDetail: 'PowerShell (as domain admin): Reset-ComputerMachinePassword -Server DC01 -Credential (Get-Credential). If that fails: remove from domain (workgroup) → rejoin. Data is preserved.',
    time: '10–30 min',
    tools: ['PowerShell', 'netdom', 'ADUC', 'Local Administrator account'],
    escalate: 'If trust issues are org-wide, check DC replication and time synchronization',
    prevention: 'Never restore VM from snapshot (machine password changes every 30 days); ensure VMs stay online or use Autopilot re-enrollment'
  },

  // ─── MORE NETWORK ──────────────────────────────────────────────────────────
  {
    cat: 'network', catLabel: 'Network',
    sev: 'high', sevLabel: 'HIGH',
    problem: 'Network Switch Port Issues',
    sub: 'Physical switch port failure',
    symptoms: ['One device has no connectivity while others are fine','Port shows amber/no link light on switch','Device works with another cable/switch'],
    diag: ['Test with different cable (cable is #1 culprit)','Try different switch port','Check switch port status in management interface','Check for port security / 802.1X violation'],
    resolution: 'Replace cable → try different port → check port security config → check VLAN assignment on port',
    resDetail: 'Shutdown/no shutdown on switch port to reset. Check: show interface fa0/1 status. Port security violation: show port-security interface. Re-enable if errDisabled.',
    time: '10–45 min',
    tools: ['Cable tester', 'Switch management CLI', 'show interface', 'Fluke network tester'],
    escalate: 'Replace patch cable, keystone, or switch port if hardware issue confirmed',
    prevention: 'Label all ports; use network management system to monitor port health; spare cables on hand'
  },
  {
    cat: 'network', catLabel: 'Network',
    sev: 'critical', sevLabel: 'CRITICAL',
    problem: 'Broadcast Storm / Network Loop',
    sub: 'Layer 2 network loop',
    symptoms: ['Sudden complete network outage','Switch CPU at 100%, port lights flashing rapidly','Network was fine, then everything stopped'],
    diag: ['Check switch CPU usage via management','Look for rapid MAC table flapping in switch logs','Find where STP (Spanning Tree) is failing','Identify recently added network device or cable'],
    resolution: 'Physically disconnect recently added cables/devices → identify loop → verify STP is enabled on all switches',
    resDetail: 'Unplug suspect cables one by one until network recovers. Enable STP globally: spanning-tree mode rapid-pvst. Enable BPDU Guard on edge ports. Enable Storm Control.',
    time: '15–120 min',
    tools: ['Switch CLI', 'show spanning-tree', 'show mac address-table', 'Wireshark'],
    escalate: 'Escalate to network engineer for STP redesign if loops are recurring',
    prevention: 'Enable BPDU Guard on all access ports; configure Storm Control; use loop detection feature'
  },
  {
    cat: 'network', catLabel: 'Network',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Firewall / Proxy Blocking Legitimate Sites',
    sub: 'Overcautious content filtering',
    symptoms: ['Specific business website blocked','SSL inspection breaking site','User gets block page for legitimate content'],
    diag: ['Check block page for reason/category','Look up site in web filter category database','Test if SSL inspection is causing issues','Check if site is in blocklist or falls under blocked category'],
    resolution: 'Add site to whitelist/bypass list → recategorize if miscategorized → create SSL inspection bypass if needed',
    resDetail: 'For proxy bypass: add to PAC file or exclusion list. For SSL bypass: add cert pinned sites (banking, health). Submit recategorization to vendor (Fortinet/Cisco Umbrella/Zscaler).',
    time: '10–30 min',
    tools: ['Web filter admin console', 'PAC file editor', 'SSL bypass list', 'Vendor recategorization tool'],
    escalate: 'Document all bypass requests for security audit trail; review monthly',
    prevention: 'Implement tiered filtering with manager override; provide self-service whitelist request form'
  },
  {
    cat: 'network', catLabel: 'Network',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'DHCP Scope Exhaustion',
    sub: 'No IP addresses available',
    symptoms: ['New devices get 169.254.x.x APIPA address','DHCP server log shows scope full','Devices can\'t get IP during peak hours'],
    diag: ['Check DHCP scope statistics in DHCP server console','Review lease duration (default 8 days is often too long)','Identify unused leases (stale reservations)','Check scope size vs number of devices'],
    resolution: 'Reduce lease duration → clean up stale reservations → expand scope → add additional scope/superscope',
    resDetail: 'DHCP console → Scope → Properties → reduce to 4h for BYOD, 8h for corporate. Delete inactive leases. Expand scope /20 → /19. Consider DHCP relay to segment subnets.',
    time: '15–60 min',
    tools: ['DHCP Manager', 'PowerShell (Get-DhcpServerv4Lease)', 'Network diagram'],
    escalate: 'Subnet redesign required if scope cannot be expanded — network architecture decision',
    prevention: 'Monitor DHCP utilization alerts at 80%; use shorter lease times for guest/BYOD; segment VLANs by device type'
  },

  // ─── MORE OS ────────────────────────────────────────────────────────────────
  {
    cat: 'os', catLabel: 'OS',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Windows File / Folder Permissions Broken',
    sub: 'NTFS permission error',
    symptoms: ['"Access denied" opening own files','Can\'t edit files in own folder','Permission not inherited correctly'],
    diag: ['Right-click → Properties → Security tab → check effective permissions','Check for broken inheritance (red X on folder icon in some tools)','Run: icacls C:\\path\\folder','Check if SID is orphaned (account deleted)'],
    resolution: 'Take ownership → restore inheritance → apply correct NTFS permissions → replace orphaned SIDs',
    resDetail: 'Take ownership: icacls "C:\\folder" /setowner "DOMAIN\\user" /T /C. Restore inheritance: icacls "C:\\folder" /inheritance:e. Replace orphaned SID with correct group.',
    time: '15–45 min',
    tools: ['icacls', 'File Properties → Security', 'SetACL', 'Active Directory Users'],
    escalate: 'Large-scale permission issues require scripted remediation via icacls or PowerShell',
    prevention: 'Use AD groups for permissions, not individual users; audit permissions quarterly with AccessChk'
  },
  {
    cat: 'os', catLabel: 'OS',
    sev: 'high', sevLabel: 'HIGH',
    problem: 'Windows Activation Lost After Hardware Change',
    sub: 'License deactivation post-hardware swap',
    symptoms: ['Watermark "Activate Windows" appears','Activation settings shows "Windows is not activated"','Occurred after motherboard/major hardware change'],
    diag: ['Check activation status: slmgr /xpr','Check if digital license or product key was used','Verify if covered by volume license (KMS/MAK)','Try activation troubleshooter: Settings → Update & Security → Activation'],
    resolution: 'Run Activation Troubleshooter → use phone activation for hardware change → contact Microsoft for license transfer',
    resDetail: 'For digital license: link to Microsoft account before hardware change. For KMS: check connectivity to KMS server (slmgr /skms kmsserver). For OEM: motherboard replacement requires new license.',
    time: '15–60 min',
    tools: ['slmgr', 'Activation Troubleshooter', 'Microsoft Licensing portal', 'VAMT'],
    escalate: 'Volume License customers: contact Microsoft support with proof of license for reactivation',
    prevention: 'Link Windows license to Microsoft Account; document volume license keys; use KMS for enterprise'
  },
  {
    cat: 'os', catLabel: 'OS',
    sev: 'low', sevLabel: 'LOW',
    problem: 'Recycle Bin Corrupted / Won\'t Empty',
    sub: 'Recycle bin filesystem issue',
    symptoms: ['"Cannot empty Recycle Bin" error','Files appear to be deleted but disk space not freed','Recycle Bin icon doesn\'t change after emptying'],
    diag: ['Try deleting specific file from Recycle Bin','Check if protected system file is stuck in bin','Open Recycle Bin and look for files with strange names','Check disk errors: chkdsk /f'],
    resolution: 'Reset Recycle Bin via command: rd /s /q C:\\$Recycle.bin → Windows will recreate it on next login',
    resDetail: 'Run as admin: rd /s /q C:\\$Recycle.bin. Windows recreates the folder automatically. If protected file is stuck, use Unlocker tool or safe mode deletion.',
    time: '5–15 min',
    tools: ['cmd (as admin)', 'rd command', 'chkdsk', 'Unlocker'],
    escalate: 'If chkdsk finds file system errors, schedule full scan and monitor disk health',
    prevention: 'Regular chkdsk /f maintenance; monitor disk health via SMART'
  },

  // ─── MORE HARDWARE ──────────────────────────────────────────────────────────
  {
    cat: 'hardware', catLabel: 'Hardware',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'USB Device Keeps Disconnecting',
    sub: 'USB connection instability',
    symptoms: ['USB device disconnects/reconnects every few minutes','"USB device not recognized" repeat messages','Works in some ports, not others'],
    diag: ['Try different USB port (especially rear ports on desktop)','Check USB power management: Device Manager → USB Controllers → Properties','Test device on another computer','Check for bent/damaged USB connector'],
    resolution: 'Disable USB selective suspend → try rear ports → update USB host controller driver → check power supply capacity',
    resDetail: 'Disable selective suspend: Power Options → Change plan settings → Advanced → USB settings → USB selective suspend → Disabled. Also check in Device Manager → USB Root Hub → Power Management → uncheck "Allow computer to turn off".',
    time: '10–30 min',
    tools: ['Device Manager', 'Power Options', 'USB port tester'],
    escalate: 'If persists across multiple ports, USB host controller may be failing — motherboard service',
    prevention: 'Avoid cheap USB hubs; use powered hubs for high-draw devices; keep USB drivers updated'
  },
  {
    cat: 'hardware', catLabel: 'Hardware',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Laptop Battery Not Charging',
    sub: 'Battery / charging circuit issue',
    symptoms: ['Plugged in but battery % not increasing','"Plugged in, not charging" in battery icon','Battery drains while plugged in under load'],
    diag: ['Check charger LED / try different charger','Inspect charging port for damage/debris','Check battery health: powercfg /batteryreport','Test with battery removed (AC only) if removable'],
    resolution: 'Try different charger → clean charging port → run battery report → recalibrate battery → replace battery',
    resDetail: 'Run: powercfg /batteryreport → open battery-report.html. Design capacity vs Full Charge Capacity shows degradation. < 60% of original = replacement time.',
    time: '15–60 min',
    tools: ['powercfg /batteryreport', 'Compressed air', 'Manufacturer diagnostics (Dell SupportAssist, HP Support)'],
    escalate: 'Battery replacement via hardware repair; check if under warranty',
    prevention: 'Avoid full discharge cycles; store at 40-80% charge; replace every 3-4 years proactively'
  },
  {
    cat: 'hardware', catLabel: 'Hardware',
    sev: 'critical', sevLabel: 'CRITICAL',
    problem: 'Server / Workstation POST Failure (Beep Codes)',
    sub: 'Hardware self-test failure',
    symptoms: ['System beeps on startup but doesn\'t boot','Specific beep pattern (e.g., 3 beeps)','No display during POST'],
    diag: ['Look up beep code for that manufacturer (AMI/Phoenix/Award BIOS)','Count and time the beeps precisely','Common: 1 beep = POST pass, 3 beeps = RAM, 6 beeps = keyboard, 8 beeps = GPU','Inspect indicated component'],
    resolution: 'Reseat RAM (most common) → reseat GPU → test with one RAM stick → replace faulty component',
    resDetail: 'Remove all RAM → boot (different beep = POST running). Add one stick at a time. Test each slot. GPU: reseat or test with integrated graphics. Keyboard: try different keyboard.',
    time: '30–180 min',
    tools: ['Manufacturer BIOS beep code guide', 'Spare RAM/GPU', 'Antistatic equipment'],
    escalate: 'Replace failed component; engage hardware vendor if under warranty for diagnosis',
    prevention: 'Regular hardware inspection; spare components available; reseat all RAM/cards annually in dusty environments'
  },

  // ─── MORE SECURITY ──────────────────────────────────────────────────────────
  {
    cat: 'security', catLabel: 'Security',
    sev: 'high', sevLabel: 'HIGH',
    problem: 'BitLocker Recovery Key Required at Boot',
    sub: 'Disk encryption recovery prompt',
    symptoms: ['Blue BitLocker recovery screen at startup','"Enter the recovery key for this drive"','Happened after BIOS update or hardware change'],
    diag: ['Find recovery key in Azure AD, AD, or Microsoft Account','Check if TPM PCR values changed (BIOS update triggers this)','Verify if boot order changed or Secure Boot state changed','Check BitLocker status: manage-bde -status'],
    resolution: 'Enter recovery key from Azure AD/AD → suspend BitLocker before future BIOS changes → re-enable after',
    resDetail: 'Find key: Azure AD → Devices → [device] → Recovery Keys. AD: ADUC → Computer → BitLocker Recovery. M365 Account. Suspend before BIOS: Suspend-BitLocker -MountPoint "C:" -RebootCount 1.',
    time: '15–45 min',
    tools: ['Azure AD / Entra portal', 'ADUC', 'manage-bde', 'Microsoft Account'],
    escalate: 'If recovery key is lost and device cannot be recovered — data loss; reinforce key backup procedures',
    prevention: 'Escrow recovery keys to Azure AD (via Intune) or AD; suspend BitLocker before hardware changes; document key backup procedure'
  },
  {
    cat: 'security', catLabel: 'Security',
    sev: 'high', sevLabel: 'HIGH',
    problem: 'User Reports Receiving CEO / BEC Fraud Email',
    sub: 'Business email compromise attempt',
    symptoms: ['Email from "CEO" requesting urgent wire transfer','Spoofed executive email address','Pressure to act quickly without verification'],
    diag: ['Check real sender email in headers (vs display name)','Verify DMARC/DKIM/SPF on sending domain','Look up sender IP geolocation','Check if similar emails sent to other staff'],
    resolution: 'Do NOT action request → warn other potential targets → block sender → escalate to management and finance → report to authorities',
    resDetail: 'Check Message Headers: Received-From IP and Reply-To address. Report to FBI IC3 (US) or Action Fraud (UK). Alert finance immediately. Brief all staff.',
    time: '15–60 min',
    tools: ['Message Header Analyzer', 'MXToolbox', 'VirusTotal IP lookup', 'IC3.gov'],
    escalate: 'Immediate escalation to CISO, CFO, and legal if any financial transfer was made',
    prevention: 'BEC training; enforce email display-name policies; require 2-person authorization for wire transfers; DMARC enforcement'
  },
  {
    cat: 'security', catLabel: 'Security',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Rogue / Unauthorized Device on Network',
    sub: 'Unknown device detected',
    symptoms: ['Unknown MAC address in DHCP leases','ARP scan shows unfamiliar devices','Network monitoring alert for new device'],
    diag: ['Identify device: arp -a → look up MAC OUI prefix','Scan device ports: nmap -sV [IP]','Cross-reference with asset inventory','Check switch port the device is connected to'],
    resolution: 'Identify device owner → if unauthorized: isolate via VLAN/switch port shutdown → investigate',
    resDetail: 'Look up MAC vendor: maclookup.app. Locate on network: show mac address-table | include [MAC] on switch. Shutdown port: interface fa0/X → shutdown. Enable 802.1X for prevention.',
    time: '15–60 min',
    tools: ['arp -a', 'nmap', 'Switch CLI', 'MAC vendor lookup', 'Wireshark'],
    escalate: 'Treat as security incident if device intent is unknown; preserve logs for forensics',
    prevention: '802.1X network access control; regular network scans; NAC solution; asset inventory management'
  },

  // ─── MORE SOFTWARE ──────────────────────────────────────────────────────────
  {
    cat: 'software', catLabel: 'Software',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'PDF Won\'t Print / Displays Incorrectly',
    sub: 'PDF rendering / print failure',
    symptoms: ['PDF prints blank pages','PDF formatting broken in browser','Adobe shows "There was an error"'],
    diag: ['Try printing from Adobe Reader vs browser','Try "Print as Image" option in Adobe','Check if printer driver is up to date','Test with a different PDF file'],
    resolution: 'Use Adobe Reader (not browser) → enable Print as Image → update printer driver → flatten PDF',
    resDetail: 'In Adobe: File → Print → Advanced → Print as Image. For corrupt PDF: open in browser → Save as PDF (re-renders). Update to latest Adobe Reader. Try PDF24 or Foxit as alternative.',
    time: '5–20 min',
    tools: ['Adobe Reader', 'PDF24', 'Foxit Reader', 'Printer driver update'],
    escalate: 'For org-wide print issues, check if a recent Adobe update changed settings',
    prevention: 'Standardize on Adobe Reader; manage updates centrally; test PDFs before distributing'
  },
  {
    cat: 'software', catLabel: 'Software',
    sev: 'low', sevLabel: 'LOW',
    problem: 'Fonts Displaying Incorrectly / Missing',
    sub: 'Font rendering failure',
    symptoms: ['Boxes or symbols instead of text','Custom font not showing in documents','Font displays fine on one PC but not another'],
    diag: ['Check if font is installed: Settings → Personalization → Fonts','Verify font is not corrupted (try reinstalling)','Check if font requires licensing','Test in multiple applications'],
    resolution: 'Install missing font → reinstall corrupted font → embed fonts in documents for portability',
    resDetail: 'Install font: double-click .ttf/.otf → Install. For all users: copy to C:\\Windows\\Fonts. Embed in Word: Options → Save → Embed fonts. PDFs should embed fonts to avoid this.',
    time: '5–15 min',
    tools: ['Font settings', 'Font management tool', 'Word font embedding'],
    escalate: 'For licensed fonts, involve procurement for org-wide deployment',
    prevention: 'Deploy fonts via GPO; embed fonts in documents before sharing; document required fonts list'
  },
  {
    cat: 'software', catLabel: 'Software',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'VBA Macros Blocked / Disabled',
    sub: 'Office macro security policy',
    symptoms: ['Excel/Word macro won\'t run','"Macros have been disabled" security warning','Macro runs on some PCs but not others'],
    diag: ['Check Trust Center: File → Options → Trust Center → Macro Settings','Check if file is in a Trusted Location','Look for GPO enforcing macro restrictions','Check if file origin (internet) is blocking macro (Mark of the Web)'],
    resolution: 'Add file to Trusted Location → unblock file (right-click → Properties → Unblock) → adjust macro settings per policy',
    resDetail: 'Microsoft now blocks macros in files downloaded from internet by default. Unblock: file Properties → Unblock checkbox. Trusted location: Trust Center → Trusted Locations → Add new location.',
    time: '5–20 min',
    tools: ['Office Trust Center', 'File Properties', 'Group Policy (for org-wide)'],
    escalate: 'For org-wide macro requirements, evaluate migration to Power Automate or approved add-ins',
    prevention: 'Sign macros with code signing certificate; use approved trusted locations; document macro usage'
  },

  // ─── MORE PERFORMANCE ────────────────────────────────────────────────────────
  {
    cat: 'perf', catLabel: 'Performance',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: '100% Disk Usage in Task Manager',
    sub: 'Disk I/O saturation',
    symptoms: ['Task Manager shows Disk at 100%','System extremely slow but CPU/RAM are fine','Mostly on systems with HDDs + Windows 10/11'],
    diag: ['Task Manager → Performance → Disk → see which process uses most I/O','Check: services.msc → SysMain (Superfetch) and Windows Search services','Test disabling BITS (Background Intelligent Transfer Service)','Check for pending Windows Updates downloading'],
    resolution: 'Disable SysMain → disable Windows Search temporarily → let Windows Update complete → or upgrade to SSD',
    resDetail: 'Disable SysMain: sc stop sysmain && sc config sysmain start= disabled. Re-enable after SSD upgrade. Check for malware; Malwarebytes scan as disk I/O can be malware symptom.',
    time: '20–60 min',
    tools: ['Task Manager', 'Resource Monitor', 'services.msc', 'Malwarebytes'],
    escalate: 'Hardware upgrade (SSD) if persistent on HDD with no malware found',
    prevention: 'SSD for OS drives in all new builds; avoid installing too many Windows features on HDDs'
  },
  {
    cat: 'perf', catLabel: 'Performance',
    sev: 'low', sevLabel: 'LOW',
    problem: 'Browser Using Too Much RAM',
    sub: 'Web browser memory leak',
    symptoms: ['Browser using 2GB+ RAM','System slows down after hours of browsing','Browser tab crashes frequently'],
    diag: ['Check Task Manager for browser process memory','Use browser\'s built-in task manager (Shift+Esc in Chrome)','Count open tabs and loaded extensions','Test in private mode without extensions'],
    resolution: 'Limit open tabs → disable unused extensions → enable Memory Saver (Chrome) → clear browser cache → restart browser',
    resDetail: 'Chrome: Settings → Performance → Memory Saver ON. Identifies inactive tabs and frees memory. Audit extensions: remove unused. Check for extension-based adware.',
    time: '5–15 min',
    tools: ['Browser Task Manager (Shift+Esc)', 'Chrome Memory Saver', 'Extension manager'],
    escalate: 'If specific extension causes consistent leak, report to vendor and uninstall',
    prevention: 'Limit installed extensions via enterprise policy; promote tab management habits; use lightweight browsers for low-RAM machines'
  },

  // ─── MORE ACCOUNT ────────────────────────────────────────────────────────────
  {
    cat: 'account', catLabel: 'Account',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'SSO / Single Sign-On Not Working',
    sub: 'Federated auth failure',
    symptoms: ['Prompted for credentials on apps that should auto-sign in','SSO redirects to error page','Works in some browsers but not others'],
    diag: ['Check if user\'s Azure AD / ADFS token is valid','Test in InPrivate/Incognito (cookie issue?)','Verify browser is in Intranet Zone for ADFS (IE/Edge)','Check ADFS/AAD logs for federation errors'],
    resolution: 'Clear cookies → add ADFS URL to Trusted Sites/Intranet Zone → re-register device in AAD → check ADFS federation',
    resDetail: 'For ADFS: add sts.domain.com to IE Trusted Sites. For Azure AD SSO: device must be AAD joined or hybrid joined. Clear SSO token: dsregcmd /forcerecovery.',
    time: '15–45 min',
    tools: ['dsregcmd /status', 'Browser cookie manager', 'ADFS Event Viewer', 'Azure AD Sign-in logs'],
    escalate: 'ADFS down or misconfigured → escalate to Identity/ADFS admin',
    prevention: 'Move from ADFS to Azure AD direct federation (simpler); monitor ADFS availability; implement HA ADFS farm'
  },
  {
    cat: 'account', catLabel: 'Account',
    sev: 'low', sevLabel: 'LOW',
    problem: 'User Not Receiving IT Notifications / Emails',
    sub: 'Distribution group / email flow issue',
    symptoms: ['User misses team announcements','Not on correct distribution list','IT alerts not reaching user'],
    diag: ['Check if user is member of required distribution groups in AD/M365','Verify user\'s email address is correct in directory','Check if user has created a block or folder rule for IT emails','Test by sending direct email'],
    resolution: 'Add to correct distribution group → update email address in directory → remove block rule → test delivery',
    resDetail: 'In M365 Admin: Groups → Distribution Lists → [group] → Members. Check for Inbox rules (client-side) and Mail Flow rules (server-side) that might be filtering messages.',
    time: '5–20 min',
    tools: ['M365 Admin Center', 'Exchange Admin Center', 'Outlook Rules manager'],
    escalate: 'If org-wide announcement is missed, review distribution group membership governance',
    prevention: 'Automate distribution group membership via AD group-based policy; offboarding checklist should include group review'
  },

  // ─── MORE EMAIL ──────────────────────────────────────────────────────────────
  {
    cat: 'email', catLabel: 'Email',
    sev: 'high', sevLabel: 'HIGH',
    problem: 'Email Stuck in Outbox',
    sub: 'Message send failure',
    symptoms: ['Email stays in Outbox for hours','"Send/Receive" errors in Outlook','Large attachment seems to be cause'],
    diag: ['Check Outlook connectivity: File → Account Settings → Test','Look for large attachment that may have timed out','Try sending in Outlook Web App (OWA) — if works, client issue','Check SMTP send limits in Exchange/M365'],
    resolution: 'Delete stuck email → re-create without large attachment → check Outlook profile → test via OWA',
    resDetail: 'If email is stuck: go Offline mode first (Send/Receive → Work Offline) → delete from Outbox → go back Online. If attachment too large: use OneDrive link instead.',
    time: '5–20 min',
    tools: ['Outlook Outbox', 'Work Offline mode', 'OWA', 'Exchange send limits'],
    escalate: 'If Outlook consistently fails to send while OWA works, rebuild Outlook profile',
    prevention: 'Train users on size limits; configure Outlook to warn before sending large files'
  },
  {
    cat: 'email', catLabel: 'Email',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Auto-Reply / Out of Office Not Working',
    sub: 'OOF configuration failure',
    symptoms: ['Senders not receiving OOF reply','OOF shows "on" but not sending','External senders not getting OOF'],
    diag: ['Check OOF settings in Outlook: File → Automatic Replies','Verify OOF is configured for both internal and external','Check Exchange transport rules blocking OOF','Confirm OOF is not set for past date range'],
    resolution: 'Re-configure OOF with correct date range → check external OOF setting → verify Exchange transport rules allow OOF',
    resDetail: 'External OOF must be enabled in Exchange Admin: Organization → Mail Flow → Remote Domains → Default → Allow external OOF. OOF sends once per sender per SMTP session.',
    time: '10–20 min',
    tools: ['Outlook Automatic Replies', 'Exchange Admin Center', 'OWA settings'],
    escalate: 'If org-wide OOF issue, check Exchange transport rules and remote domain settings',
    prevention: 'Document OOF configuration requirements; test external OOF periodically'
  },

  // ─── MORE STORAGE ────────────────────────────────────────────────────────────
  {
    cat: 'storage', catLabel: 'Storage',
    sev: 'high', sevLabel: 'HIGH',
    problem: 'RAID Array Degraded / Disk Failure',
    sub: 'RAID member disk failure',
    symptoms: ['RAID controller alert (email or dashboard)','One drive removed from RAID set','Server performance degraded but still running'],
    diag: ['Check RAID controller status (iDRAC, iLO, RAID utility)','Identify which physical drive has failed','Verify RAID level — determine rebuild impact','Check remaining drives\' SMART data'],
    resolution: 'Identify and replace failed drive → initiate RAID rebuild → monitor rebuild completion → verify array integrity',
    resDetail: 'RAID 5/6: can survive 1/2 drive failure. Replace drive → array rebuilds automatically (may take hours). During rebuild, array is vulnerable — another failure = data loss. Check all other drives\' SMART. Backup FIRST.',
    time: '2–48 hours (rebuild)',
    tools: ['Server management console (iDRAC/iLO)', 'RAID utility', 'CrystalDiskInfo', 'Vendor HDD replacement'],
    escalate: 'If RAID 5 with second drive showing SMART errors — EMERGENCY — backup immediately before replacing',
    prevention: 'Monitor SMART data on all drives; replace drives proactively on SMART warnings; maintain spare drives on-site; use RAID 6 not RAID 5'
  },
  {
    cat: 'storage', catLabel: 'Storage',
    sev: 'medium', sevLabel: 'MEDIUM',
    problem: 'Files Accidentally Deleted',
    sub: 'Data recovery needed',
    symptoms: ['User deleted important file','Not in Recycle Bin','Shift+Delete was used bypassing Recycle Bin'],
    diag: ['Check Recycle Bin first','Check if Previous Versions are available (right-click folder → Properties → Previous Versions)','Check SharePoint/OneDrive recycle bin if cloud stored','Check if file server has shadow copies enabled'],
    resolution: 'Restore from Previous Versions → restore from backup → use file recovery tool (Recuva) as last resort',
    resDetail: 'Right-click parent folder → Properties → Previous Versions → restore specific version. OneDrive: web → Recycle Bin → Restore. File server: vssadmin list shadows. Last resort: Recuva (do NOT write new data to disk first).',
    time: '15–60 min',
    tools: ['Previous Versions (VSS)', 'Recuva', 'OneDrive Recycle Bin', 'Backup restore console'],
    escalate: 'If no backup and no VSS, professional data recovery service (expensive but possible)',
    prevention: '3-2-1 backup; enable VSS on file servers; use OneDrive/SharePoint for user files (built-in version history); educate users not to use Shift+Delete'
  },
];


const tbody = document.getElementById('table-body');
const totalCount = issues.length;
document.getElementById('total-count').textContent = totalCount;
document.getElementById('total-count-2').textContent = totalCount;

function renderRows() {
  tbody.innerHTML = '';
  issues.forEach((issue, i) => {
    const mainRow = document.createElement('tr');
    mainRow.dataset.cat = issue.cat;
    mainRow.dataset.search = [issue.problem, issue.sub, issue.symptoms.join(' '), issue.diag.join(' '), issue.resolution].join(' ').toLowerCase();
    mainRow.style.animationDelay = (i * 0.012) + 's';

    const sympTags = issue.symptoms.map(s => `<span class="symptom-tag">${s}</span>`).join('');
    const diagItems = issue.diag.map((d, n) => `<li data-n="${n+1}">${d}</li>`).join('');

    mainRow.innerHTML = `
      <td style="text-align:center">
        <button class="expand-btn" data-idx="${i}" title="Expand for full detail">+</button>
      </td>
      <td class="col-cat"><span class="cat-badge cat-${issue.cat}">${issue.catLabel}</span></td>
      <td class="col-sev">
        <span class="sev-badge sev-${issue.sev.toLowerCase()}">
          <span class="sev-dot"></span>${issue.sevLabel}
        </span>
      </td>
      <td class="col-prob">
        <div class="problem-text">${issue.problem}</div>
        <div class="problem-sub">${issue.sub}</div>
      </td>
      <td class="col-symptoms">${sympTags}</td>
      <td class="col-diag">
        <div class="diag-steps"><ol>${diagItems}</ol></div>
      </td>
      <td class="col-resolution">
        <div class="res-quick">${issue.resolution}</div>
      </td>
      <td class="col-time"><span class="time-badge">⏱ ${issue.time}</span></td>
    `;

    const detailRow = document.createElement('tr');
    detailRow.className = 'detail-row';
    detailRow.dataset.cat = issue.cat;
    detailRow.dataset.search = mainRow.dataset.search;
    detailRow.innerHTML = `
      <td colspan="8" class="detail-cell">
        <div class="detail-grid">
          <div class="detail-card">
            <div class="detail-card-title">⚡ INSTANT FIX</div>
            <div class="detail-card-body">${issue.resolution}</div>
          </div>
          <div class="detail-card">
            <div class="detail-card-title">🔍 FULL RESOLUTION</div>
            <div class="detail-card-body">${issue.resDetail}</div>
          </div>
          <div class="detail-card">
            <div class="detail-card-title">🛠 TOOLS NEEDED</div>
            <div class="detail-card-body">
              <ul>${issue.tools.map(t => `<li><code>${t}</code></li>`).join('')}</ul>
            </div>
          </div>
          <div class="detail-card">
            <div class="detail-card-title">📈 ESCALATION PATH</div>
            <div class="detail-card-body">${issue.escalate}</div>
          </div>
          <div class="detail-card">
            <div class="detail-card-title">🛡 PREVENTION</div>
            <div class="detail-card-body">${issue.prevention}</div>
          </div>
          <div class="detail-card">
            <div class="detail-card-title">⏱ TIME ESTIMATE</div>
            <div class="detail-card-body">Expected resolution: <strong style="color:var(--accent)">${issue.time}</strong></div>
          </div>
        </div>
      </td>
    `;

    tbody.appendChild(mainRow);
    tbody.appendChild(detailRow);
  });

  // Expand buttons
  tbody.querySelectorAll('.expand-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const idx = btn.dataset.idx;
      const detailRow = btn.closest('tr').nextElementSibling;
      const isOpen = detailRow.classList.contains('open');
      // Close all others
      tbody.querySelectorAll('.detail-row.open').forEach(r => r.classList.remove('open'));
      tbody.querySelectorAll('.expand-btn').forEach(b => b.textContent = '+');
      if (!isOpen) {
        detailRow.classList.add('open');
        btn.textContent = '−';
      }
    });
  });

  // Click row to expand
  tbody.querySelectorAll('tbody tr:not(.detail-row)').forEach(row => {
    row.addEventListener('click', (e) => {
      if (e.target.closest('.expand-btn')) return;
      const btn = row.querySelector('.expand-btn');
      if (btn) btn.click();
    });
    row.style.cursor = 'pointer';
  });
}

renderRows();

// ─── Filter & Search ────────────────────────────────────────────────────
let activeFilter = 'all';
let searchTerm = '';

function applyFilters() {
  let visible = 0;
  const rows = tbody.querySelectorAll('tr:not(.detail-row)');
  const detailRows = tbody.querySelectorAll('.detail-row');

  rows.forEach((row, i) => {
    const catMatch = activeFilter === 'all' || row.dataset.cat === activeFilter;
    const searchMatch = !searchTerm || row.dataset.search.includes(searchTerm);
    const show = catMatch && searchMatch;
    row.classList.toggle('hidden', !show);
    detailRows[i].classList.toggle('hidden', !show);
    if (!show) detailRows[i].classList.remove('open');
    if (show) visible++;
  });

  document.getElementById('visible-count').textContent = visible;
  document.getElementById('empty-state').classList.toggle('visible', visible === 0);
}

document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeFilter = btn.dataset.filter;
    applyFilters();
  });
});

document.getElementById('search-input').addEventListener('input', (e) => {
  searchTerm = e.target.value.toLowerCase().trim();
  applyFilters();
});