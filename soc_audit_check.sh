#!/bin/bash

# Output file locations
output_file="soc_audit_report.html"

# Function to run a command and append its output to the HTML file
run_command() {
  title=$1
  description=$2
  command=$3
  optional_note=${4:-}  # Fourth argument is optional; default is empty if not provided

  # Run the command and conditionally apply ansi2html
  if [[ "$optional_note" == "no_ansi" ]]; then
    output=$(eval "$command")  # No ansi2html, plain output
  else
    output=$(eval "$command" | ansi2html)  # Apply ansi2html
  fi

  # Append the title, description, and output to the HTML file
  echo "<div class='card' style='margin-bottom:25px'>" >> $output_file
  echo "  <div class='card-header bg-primary text-white'>" >> $output_file
  echo "<h4>$title</h4>" >> $output_file
  echo "</div>" >> $output_file
  echo "<div class='card-body'>" >> $output_file

  # Check if the description is not empty
  if [[ -n "$description" ]]; then
    echo "<p>$description</p><hr>" >> $output_file
  fi

  echo "<style> pre { padding: 0; margin: 0; } </style>" >> $output_file
  echo "<div class='bg-light p-1' style='text-align:left'}>$output</div>" >> $output_file
  echo "</div>" >> $output_file
  echo "</div>" >> $output_file
}

# Get today's date
today_date=$(date +"%B %d, %Y")

# Start the HTML report
echo "<!DOCTYPE html>" > $output_file
echo "<html lang='en'>" >> $output_file
echo "<head>" >> $output_file
echo "<meta charset='UTF-8'>" >> $output_file
echo "<meta name='viewport' content='width=device-width, initial-scale=1.0'>" >> $output_file
echo "<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css' rel='stylesheet'>" >> $output_file
echo "<title>Audit Report - $today_date</title>" >> $output_file
echo "</head>" >> $output_file
echo "<body class='container mt-4'>" >> $output_file
echo "<h1 class='text-center'>Audit Report - $today_date</h1><hr><br/>" >> $output_file

# Add an introductory section below the title
echo "<div class='mb-4'>" >> $output_file
echo "  <p><strong>What is this report?</strong></p>" >> $output_file
echo "  <p>This report provides an overview of the security and operational status of the system. It includes checks on disk encryption, service status, network security, and various configurations that are critical for maintaining system integrity and ensuring compliance with security best practices.</p>" >> $output_file
echo "  <p><strong>What does it do?</strong></p>" >> $output_file
echo "  <p>The report performs system checks such as disk encryption verification, malware detection, secure boot status, firewall activity, and open ports. Additionally, it checks for the presence of security services like SELinux, AIDE (file integrity monitoring), and more.</p>" >> $output_file
echo "  <p><strong>Why is this important?</strong></p>" >> $output_file
echo "  <p>Regular auditing and monitoring of system settings and services help identify potential vulnerabilities or misconfigurations that could lead to security incidents. This report is an essential tool for maintaining system security and staying compliant with organizational or industry-specific security requirements.</p>" >> $output_file
echo "</div>" >> $output_file

# Commands to run
run_command "Disk Encryption Status" \
"This checks if disk encryption is enabled and the encryption status of the specified LUKS partition." \
"lsblk -f | grep crypt && cryptsetup status /dev/mapper/luks-c138a6fd-a844-4cc7-8dc2-962aad0d77ab"

run_command "LUKS Encryption Details" \
"This checks the encryption algorithm and key size used by the specified LUKS partition." \
"cryptsetup luksDump /dev/nvme0n1p3 | grep -E 'Cipher|Key Size'"

run_command "Secure Boot Status" \
"Secure Boot ensures only trusted software runs during the boot process." \
"mokutil --sb-state"

run_command "Antivirus Status (ClamAV)" \
"<strong>ClamAV</strong> is an open-source antivirus engine designed to detect malware, viruses, and other malicious threats on a system. It is commonly used in email scanning, web scanning, and file scanning applications. ClamAV can be deployed on various platforms, including Linux, macOS, and Windows. It supports multiple file formats and uses both signature-based and heuristic detection methods to identify threats."  \
"systemctl status clamd@scan | grep Active | sed 's/^[[:space:]]*//' && ps aux | grep [c]lamd"

run_command "ClamAV Virus Database Last Update" \
"The <strong>ClamAV database</strong> contains a collection of malware signatures that are used by the ClamAV antivirus engine to detect viruses, malware, trojans, and other malicious threats. This database is essential for ClamAV to effectively identify known malware through signature-based detection methods." \
"if [ -f /var/log/clamav/freshclam.log ]; then grep 'ClamAV update process started ' /var/log/clamav/freshclam.log | tail -n 1; else echo 'freshclam log not found, database update information unavailable.'; fi"

run_command "Firewall Status" \
"A <strong>firewall</strong> is a network security system that monitors and controls incoming and outgoing network traffic based on predetermined security rules. It acts as a barrier between a trusted internal network and untrusted external networks, such as the internet, to prevent unauthorized access and protect the system from potential threats. Firewalls can be implemented as hardware, software, or a combination of both, and they are designed to enforce security policies by filtering network traffic." \
"systemctl status firewalld | grep Active | sed 's/^[[:space:]]*//'"

# Check if LMD (maldet) is installed
run_command "Linux Malware Detect (LMD) Installation Check" \
"<strong>LMD (Linux Malware Detect)</strong>, also known as <b>Maldet</b>, is a malware scanner specifically designed for Linux-based systems. It is primarily focused on detecting malware that targets shared hosting environments, but it can be used on any Linux server. LMD scans for malicious files based on signature matching, heuristic detection, and monitoring of file system changes." \
"if command -v maldet &> /dev/null; then echo 'maldet is installed'; else echo 'maldet is NOT installed'; fi"

# Check the last modification timestamp of maldet logs
run_command "Last LMD (maldet) Run" \
"This checks when LMD (maldet) was last run by checking the modification time of the most recent log." \
"if [ -d /usr/local/maldetect/logs ]; then last_log=\$(ls -t /usr/local/maldetect/logs/event_log* 2>/dev/null | head -n 1); if [ -n \"\$last_log\" ]; then echo 'Last maldet scan log: '\$last_log; stat -c '%y' \"\$last_log\"; else echo 'No maldet scan logs found.'; fi; else echo 'No maldet logs directory found.'; fi"

run_command "SELinux Status" \
"<strong>SELinux (Security-Enhanced Linux)</strong> is a security architecture integrated into the Linux kernel that provides a mechanism for enforcing access control policies. It uses Mandatory Access Control (MAC), which means it restricts what processes and users can do, even if they have root privileges. SELinux helps protect systems by limiting the potential damage from security vulnerabilities, misconfigurations, or compromised processes." \
"sestatus"

run_command "Users with valid login shells" \
"The <strong>\"users with valid login shells\"</strong> check is essential for ensuring that only authorized users have access to an interactive shell on the system. A valid login shell allows a user to execute commands, access files, and interact with the system. Misconfigured user accounts with valid login shells could provide unauthorized individuals with unintended access to system resources, posing a significant security risk." \
"grep -E '/bin/bash|/bin/sh|/bin/zsh' /etc/passwd | cut -d: -f1"

valid_users=$(grep -E '/bin/bash|/bin/sh|/bin/zsh' /etc/passwd | cut -d: -f1)

# Start collecting the output for all users
output=""
for user in $valid_users; do
  # Add the output of the chage command to the output variable
  output+="Password Expiration Policy For $user
$(chage -l $user)"
done

# Use the run_command function to output all collected information in one card
run_command "Password Expiration Policies for Valid Users" \
"This checks the password expiration and aging policies for all users with valid login shells." \
"echo \"$output\"" \

run_command "Root Account Status" \
"<strong>Disabling the root account</strong> is an important security measure that reduces the risk of unauthorized or malicious access to a system's most privileged user. The root account has unrestricted access to all commands, files, and processes on a Linux system, making it a prime target for attackers. By disabling direct access to the root account, particularly for remote logins, the system relies on regular user accounts with more limited privileges, requiring users to escalate privileges through safer methods like <i style='background-color:#f7f7f7'>sudo</i>." \
"if [ \$(grep '^root:' /etc/passwd | cut -d: -f7) = '/sbin/nologin' ] || [ \$(grep '^root:' /etc/passwd | cut -d: -f7) = '/bin/false' ]; then echo 'Root account is disabled'; else echo 'Root account is enabled'; fi"

run_command "Password Complexity Policy" \
"<strong>Password Complexity</strong> refers to the set of rules and requirements that enforce the creation of strong, secure passwords to protect user accounts and system access. These rules often include minimum length, the inclusion of a mix of uppercase and lowercase letters, numbers, special characters, and restrictions on reusing old passwords or using easily guessable patterns." \
"grep -E 'difok|minlen|dcredit|ucredit|lcredit|ocredit|maxrepeat|maxclassrepeat|minclass|retry|dictcheck|usercheck|usersubstr|enforcing|enforce_for_root' /etc/security/pwquality.conf"

# HTML Description of Password Complexity Options
echo "<div class='card mt-4'>" >> $output_file
echo "<div class='card-header bg-primary text-white'>" >> $output_file
echo "<h4>Password Complexity Options Description</h4>" >> $output_file
echo "</div>" >> $output_file
echo "<div class='card-body'>" >> $output_file
echo "<table class='table table-bordered'>" >> $output_file
echo "<thead><tr><th>Option</th><th>Description</th></tr></thead>" >> $output_file
echo "<tbody>" >> $output_file

# Password option descriptions with reasons and explanation for negative values
echo "<tr><td><code>minlen</code></td><td>Minimum length of the password.</td><td>A longer password is harder to crack. Minimum length ensures password complexity. A value of 12 or more is recommended for security.</td></tr>" >> $output_file
echo "<tr><td><code>difok</code></td><td>Number of characters that must differ from the old password.</td><td>Ensures that users cannot easily reuse parts of their previous password, improving security.</td></tr>" >> $output_file
echo "<tr><td><code>dcredit</code></td><td>Minimum number of digits required in the password.</td><td>If set to a negative number (e.g., <code>dcredit=-1</code>), it enforces that at least one digit is required. This ensures stronger password entropy by adding numeric characters.</td></tr>" >> $output_file
echo "<tr><td><code>ucredit</code></td><td>Minimum number of uppercase letters required.</td><td>If set to a negative number (e.g., <code>ucredit=-1</code>), at least one uppercase letter must be present. This forces diversity in character classes, making passwords harder to guess.</td></tr>" >> $output_file
echo "<tr><td><code>lcredit</code></td><td>Minimum number of lowercase letters required.</td><td>If set to a negative number (e.g., <code>lcredit=-1</code>), it ensures at least one lowercase letter. Like <code>ucredit</code>, this adds complexity to the password.</td></tr>" >> $output_file
echo "<tr><td><code>ocredit</code></td><td>Minimum number of special characters required.</td><td>If set to a negative number (e.g., <code>ocredit=-1</code>), at least one special character (e.g., <code>@</code>, <code>!</code>) is required, increasing password strength by adding non-alphanumeric characters.</td></tr>" >> $output_file
echo "<tr><td><code>minclass</code></td><td>Minimum number of different character classes (uppercase, lowercase, digits, special characters) required.</td><td>Forces diversity in password construction. For example, setting <code>minclass=3</code> requires that the password uses at least three different types of characters, improving its resilience to brute-force attacks.</td></tr>" >> $output_file
echo "<tr><td><code>maxrepeat</code></td><td>Maximum number of consecutive identical characters allowed.</td><td>Limits repetition of the same character (e.g., <code>aaa</code>). Prevents users from creating weak passwords with repetitive characters.</td></tr>" >> $output_file
echo "<tr><td><code>maxclassrepeat</code></td><td>Maximum number of consecutive characters from the same class allowed (e.g., <code>AAA</code>).</td><td>Limits repetition of characters from the same class (e.g., consecutive uppercase letters). This prevents patterns like <code>AAA</code> or <code>111</code>, which are easier to guess.</td></tr>" >> $output_file
echo "<tr><td><code>retry</code></td><td>Number of allowed retry attempts for setting the password.</td><td>Gives the user multiple attempts (e.g., <code>retry=3</code>) to meet the password complexity rules without immediate rejection.</td></tr>" >> $output_file
echo "<tr><td><code>gecoscheck</code></td><td>Check if the password contains parts of the user's GECOS string (e.g., full name).</td><td>Prevents users from including personal information (such as their full name) in the password, making it harder to guess.</td></tr>" >> $output_file
echo "<tr><td><code>dictcheck</code></td><td>Check password against a dictionary of common passwords.</td><td>Ensures that the password isn't a commonly used or dictionary word, reducing the risk of password guessing attacks.</td></tr>" >> $output_file
echo "<tr><td><code>usercheck</code></td><td>Check if password contains the username or parts of it.</td><td>Prevents users from creating a password that contains their username or portions of it, which would be easy for attackers to guess.</td></tr>" >> $output_file
echo "<tr><td><code>usersubstr</code></td><td>Minimum length of substrings of the username to check against the password.</td><td>Specifies how many characters of the username must match in the password for it to be rejected. Helps enforce user-specific password policies.</td></tr>" >> $output_file
echo "<tr><td><code>enforcing</code></td><td>Enforce all password checks and reject passwords that fail any check.</td><td>Ensures that the password complexity rules are strictly enforced and passwords that don’t meet the requirements are rejected.</td></tr>" >> $output_file
echo "<tr><td><code>enforce_for_root</code></td><td>Enforce password complexity rules for the root user.</td><td>Ensures that even the root user is subject to the password complexity policies, enhancing overall system security.</td></tr>" >> $output_file

echo "</tbody></table>" >> $output_file
echo "</div></div>" >> $output_file

run_command "Suricata Status" \
"<strong>Suricata</strong> is an open-source network threat detection engine capable of performing real-time intrusion detection (IDS), intrusion prevention (IPS), and network security monitoring. It inspects network traffic, looking for malicious activities by analyzing network packets and application layer protocols. Suricata can operate in various modes and integrates with existing security infrastructures to provide detailed network visibility and security alerts." \
"systemctl status suricata | grep Active | sed 's/^[[:space:]]*//'"

run_command "AIDE (Advanced Intrusion Detection Environment) Status and Last Run" \
"This checks if AIDE (Advanced Intrusion Detection Environment) is installed, running, and the last time the AIDE database was updated. <strong>AIDE (Advanced Intrusion Detection Environment)</strong> is a security tool used to monitor the integrity of files and directories on a system. It works by creating a database of file attributes, such as checksums and permissions, and then compares the current state of the system with the recorded database to detect any unauthorized or unexpected changes. This helps in identifying potential security breaches or tampering." \
"if command -v aide &> /dev/null; then echo 'AIDE is installed'; stat /var/log/aide/aide.log 2>/dev/null | grep 'Modify' || echo 'No AIDE database found'; else echo 'AIDE is NOT installed'; fi"

run_command "Auditd Status" \
"<strong>Auditd</strong> is the userspace component of the Linux Auditing System that is responsible for logging and recording security-relevant events on the system. It helps track system activities and provides detailed information about processes, file access, and other critical events to assist in monitoring and ensuring system security." \
"systemctl status auditd | grep Active | sed 's/^[[:space:]]*//'"

run_command "Fail2Ban Status" \
"<strong>Fail2Ban</strong> is a security tool that monitors system logs for signs of repeated failed login attempts and other suspicious activity. When it detects such behavior, Fail2Ban can automatically take action, such as temporarily blocking the offending IP addresses, to prevent further unauthorized access attempts." \
"systemctl status fail2ban | grep Active | sed 's/^[[:space:]]*//' && fail2ban-client status"

# Check for open ports and services that are available to be connected to remotely
run_command "Open Ports and Services (Remotely Accessible)" \
"Listing open ports and services is a fundamental step in an audit as it helps identify potential entry points for attackers. Open ports indicate services that are accessible over the network, and any unnecessary or misconfigured services can present security risks. By reviewing which ports are open and what services are running, auditors can assess whether there are any vulnerabilities, unneeded services, or misconfigurations that could be exploited. Identifying and securing open ports is crucial for reducing the attack surface and ensuring that only authorized services are available to the network, which is key to maintaining a secure system during an audit." \
"ss -tuln | grep -vE '127\\.0\\.0\\.[0-9]+|::1|\\*'"

run_command "Time Synchronization Status (Chrony)" \
"<strong>Chrony</strong> is a versatile and robust time synchronization daemon that ensures the system’s clock is accurately synchronized with external time servers. Accurate system time is critical for a variety of reasons, particularly for logging, auditing, and security protocols. In an audit, having correct timestamps is essential for tracking system events, correlating activities, and ensuring that logs reflect the true sequence of events. If system time is incorrect, it can lead to discrepancies in audit trails, making it harder to detect and investigate security incidents." \
"systemctl status chronyd | grep Active | sed 's/^[[:space:]]*//'"

run_command "Unattended Security Updates (DNF-Automatic)" \
"<strong>Unattended security updates</strong> are crucial for maintaining the security and integrity of a system. They ensure that critical vulnerabilities are patched automatically, without requiring manual intervention. This is especially important for mitigating the risks posed by zero-day vulnerabilities and minimizing the attack surface. By automatically applying security updates, systems are kept up-to-date with the latest fixes, reducing the likelihood of exploitation and helping to maintain compliance with security policies and standards during an audit." \
"systemctl status dnf-automatic-install.timer | grep Active | sed 's/^[[:space:]]*//'"

run_command "Firmware Security Status (fwupdmgr)" \
"<strong>fwupdmgr</strong> is a command-line tool used for managing and updating firmware on Linux systems. It interacts with the Linux Vendor Firmware Service (LVFS) to check for and apply firmware updates for various hardware components. The security option in <i style='background-color:#f7f7f7'>fwupdmgr</i> provides information about the security status of the installed firmware, helping users ensure that their devices are running firmware with the latest security patches and are protected from known vulnerabilities." \
"fwupdmgr security"

# Close the HTML file
echo "</body></html>" >> $output_file

# Print completion message
echo "Audit report saved to $output_file (HTML format)"
