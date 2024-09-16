#!/bin/bash

# Create the HTML file and add the initial Bootstrap HTML structure with MUI-style cards using Bootstrap classes
output_file="soc_audit_report.html"

# Bootstrap and basic HTML structure
echo "<!DOCTYPE html>" > $output_file
echo "<html lang=\"en\">" >> $output_file
echo "<head>" >> $output_file
echo "<meta charset=\"UTF-8\">" >> $output_file
echo "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">" >> $output_file
echo "<link href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css\" rel=\"stylesheet\">" >> $output_file
echo "<title>SOC Audit Report</title>" >> $output_file
echo "<style>.card {margin-bottom: 20px;}</style>" >> $output_file  # Simple card styling
echo "</head>" >> $output_file
echo "<body class=\"container mt-4\">" >> $output_file
echo "<h1 class=\"text-center\">SOC Audit Report</h1>" >> $output_file

# Function to run a command, display it in the console, and append it to the HTML file
run_command() {
  title=$1
  description=$2
  command=$3

  # Run the command and capture the output
  output=$(eval "$command")

  # Display the output in the console
  echo "===================================="
  echo "$title"
  echo "$description"
  echo "------------------------------------"
  echo "$output"

  # Append to the HTML file with MUI-style card structure
  echo "<div class=\"card\">" >> $output_file
  echo "  <div class=\"card-header bg-primary text-white\">" >> $output_file
  echo "    <h4>$title</h4>" >> $output_file
  echo "  </div>" >> $output_file
  echo "  <div class=\"card-body\">" >> $output_file
  echo "    <p class=\"card-text\">$description</p>" >> $output_file
  echo "    <pre class=\"bg-light p-3\">$output</pre>" >> $output_file
  echo "  </div>" >> $output_file
  echo "</div>" >> $output_file
}

# ==========================
# Call Functions
# ==========================

# Note: [LuksDrivePath] is the path to your LUKS device, an example would be /dev/mapper/luks-c138a6fd-a844-4cc7-8dc2-932aaddd67ab
# Disk Encryption Status
run_command "Disk Encryption Status" \
"This checks if disk encryption is enabled and the encryption status of the specified LUKS partition." \
"lsblk -f | grep crypt && cryptsetup status [LuksDrivePath]"

# Note: [BlockPartitionPath] is the path to your drive partition that contains the encrypted luks device,
# an example would be /dev/nvme0n1p3
# LUKS Encryption Details
run_command "LUKS Encryption Details" \
"This checks the encryption algorithm and details used by the specified LUKS partition." \
"cryptsetup luksDump [BlockPartitionPath]"

# Secure Boot Status
run_command "Secure Boot Status" \
"This checks if Secure Boot is enabled. Secure Boot ensures only trusted software runs during the boot process." \
"mokutil --sb-state"

# Antivirus Status (ClamAV)
run_command "Antivirus Status (ClamAV)" \
"This checks if ClamAV (antivirus software) is running. ClamAV scans for malware and viruses." \
"systemctl status clamd@scan | grep Active && ps aux | grep [c]lamd"

# ClamAV Virus Database Last Update
run_command "ClamAV Virus Database Last Update" \
"This checks when the ClamAV virus database was last updated. Keeping virus definitions up-to-date is critical for detection." \
"if [ -f /var/log/clamav/freshclam.log ]; then grep 'ClamAV update process started ' /var/log/clamav/freshclam.log | tail -n 1; else echo 'freshclam log not found, database update information unavailable.'; fi"

# Firewall Status (firewalld)
run_command "Firewall Status" \
"This checks if the firewalld service is active. Firewalld controls network traffic and enforces security rules." \
"systemctl status firewalld | grep Active"

# Rootkit Hunter Scan (rkhunter)
run_command "Rootkit Hunter Scan (rkhunter)" \
"This runs Rootkit Hunter (rkhunter) to scan the system for potential rootkits or other vulnerabilities." \
"rkhunter --check --sk"

# SELinux Status
run_command "SELinux Status" \
"This checks if SELinux (Security-Enhanced Linux) is enabled. SELinux provides mandatory access control (MAC) security policies." \
"sestatus"

# Password Expiration Policy for User (kburns)
run_command "Password Expiration Policy for kburns" \
"This checks the password expiration and aging policy for the user 'kburns'. It shows when passwords will expire and other related settings." \
"chage -l kburns"

# Password Complexity Policy
run_command "Password Complexity Policy" \
"This checks the password complexity policy, such as minimum password length and required character types." \
"grep -E 'minlen|maxrepeat|minclass|retry' /etc/security/pwquality.conf"

# Suricata Status (Network IDS)
run_command "Suricata Status" \
"This checks if Suricata, a network intrusion detection system (IDS), is running. Suricata monitors network traffic for suspicious activity." \
"systemctl status suricata | grep Active"

# AIDE File Integrity Check
run_command "AIDE File Integrity Check" \
"This runs AIDE (Advanced Intrusion Detection Environment) to check for any changes to critical system files." \
"aide --check"

# AIDE Last Database Update
run_command "AIDE Last Database Update" \
"This checks when the AIDE database (used to compare file integrity) was last updated." \
"stat /var/lib/aide/aide.db.gz"

# SSH Configuration Check
run_command "SSH Configuration Check" \
"This checks for important SSH server configuration settings, such as whether root login is allowed and whether password authentication is enabled." \
"grep -E '^PermitRootLogin|^PasswordAuthentication|^PubkeyAuthentication|^PermitEmptyPasswords' /etc/ssh/sshd_config"

# Auditd Status
run_command "Auditd Status" \
"This checks if the auditd service is running. Auditd is the Linux auditing system that logs security-relevant information." \
"systemctl status auditd | grep Active"

# Fail2Ban Status
run_command "Fail2Ban Status" \
"This checks if Fail2Ban is running. Fail2Ban helps protect the system from brute-force attacks by monitoring log files and banning offending IP addresses." \
"systemctl status fail2ban | grep Active && fail2ban-client status"

# Open Ports and Services
run_command "Open Ports and Services" \
"This lists all open ports and services listening on the system. It provides information on network services that could be potential attack vectors." \
"ss -tuln"

# Time Synchronization Status (Chrony)
run_command "Time Synchronization Status" \
"This checks if Chrony, the time synchronization service, is active." \
"systemctl status chronyd | grep Active"

# Unattended Security Updates (DNF-Automatic)
run_command "Unattended Security Updates" \
"This checks if the automatic update service is running to ensure that security patches and updates are applied automatically." \
"systemctl status dnf-automatic-install.timer | grep Active"

# Firmware Security Status (fwupdmgr)
run_command "Firmware Security Status (fwupdmgr)" \
"This checks the firmware security status using the fwupdmgr tool, which ensures that the system firmware is up-to-date and secure." \
"fwupdmgr security"

# Close the HTML file
echo "</body></html>" >> $output_file

# Show where the report is saved
echo "Audit report saved to $output_file"
