#!/bin/bash

# Function to log messages
log() {
  echo "$1"
  echo "$1" >> "/opt/scripts/scan_results.txt"
}

start_time="$(date +%s)"
docroots="$(grep -oP 'DocumentRoot \K\S+' /etc/httpd/conf.d/*.conf | sort -u)"
hostname="$(hostname)"
webuser="unknown"

if [[ "$(head -n1 /etc/issue)" == *"CentOS"* || "$(head -n1 /etc/issue)" == *"\S"* ]]; then
  webuser="apache"
elif [[ "$(head -n1 /etc/issue)" == *"Ubuntu"* ]]; then
  webuser="www-data"
fi

# Clean up from the last run
log "Step 1 of 9"
log "Cleaning up from the last run"
if [ ! -d "/opt/scripts/" ]; then
  mkdir -p "/opt/scripts/"
fi

if [ -f "/opt/scripts/scan_results.txt" ]; then
  rm -f "/opt/scripts/scan_results.txt"
fi
log "Clean up complete"
log ""

# Maldet scan
log "Step 2 of 9"
log "Scanning with maldet. This could take a while."
maldet -u
freshclam
maldet -a /
log "Maldet scan complete"
log ""

# Maldet results from the last scan
log "Step 3 of 9"
log "Getting Maldet results from the last scan and adding to /opt/scripts/scan_results.txt"
log "During a routine scan of your server, $hostname, we detected one or more suspicious files indicating the presence of malware on your server. Most often these are a result of an out-of-date or unpatched CMS, or unpatched plugins or themes."
log "Due to security concerns, we ask that your team address this issue as soon as possible. In the event that we don't hear back that you have addressed the problematic files within the next 24 hours, we must quarantine them."
log "If we do quarantine the files, there is a possibility that the functionality of your site(s) will be affected."
log "Please note that it is not sufficient to simply restore from a recent backup, as it is likely that the recent backup would have these files as well."
log "" >> "/opt/scripts/scan_results.txt"

maldethits="$(maldet -l | grep '\-\-report' | tail -n1 | awk '{print $NF}')"
find /usr/local/maldetect/sess/ -name "session.hits.$maldethits" -exec cat {} \; | grep -Ev 'rfxn.ndb|rfxn.hdb|rfxn.yara|hex.dat|md5.dat|/home/bmesh_admin' >> "/opt/scripts/scan_results.txt"
log "Maldet Results Complete"
log ""

# Docroot enumeration
log "Step 4 of 9"
log "Enumerating docroots"
log "Docroots found in /etc/httpd/conf.d/*.conf:"
log "$docroots"
log "Docroot enumeration complete"
log ""

log "Step 5 of 9"
log "Scanning for outstanding Drupal/WordPress updates. This can take a while, please be patient."
log "Here is a list of outstanding CMS updates we were able to identify. If a module/theme/plugin is listed as having an update available, you will need to apply these. Please note that this applies even if the provided module/theme/plugin is not in use. If you need any assistance with applying updates or would like to receive an email listing outstanding CMS updates on a regular basis, just let us know." >> "/opt/scripts/scan_results.txt"

for docroot in $docroots; do
  log ""
  cd "$docroot"
  log "======================================"
  log "$(pwd)"
  log "======================================"
  wp core version --allow-root 2>/dev/null
  wp plugin list --allow-root 2>/dev/null | grep -i 'available'
  wp theme list --allow-root 2>/dev/null | grep -i 'available'
  drush up --security-only -n 2>/dev/null | grep -i 'SECURITY UPDATE available'
done >> "/opt/scripts/scan_results.txt"
log "CMS updates scanning complete"
log ""

# Additional malware hunting and related checks

log "Additionally, we found the following suspicious files that may not have been detected by our malware scanning software. Please note that this secondary list is likely to contain false-positives but should still be investigated:" >> "/opt/scripts/scan_results.txt"
log ""

# PHP files in /uploads/ or /files/
log "Step 6 of 9"
log "Searching for PHP files within /var/www/*/htdocs/wp-content/uploads/ and /var/www/*/htdocs/sites/default/files/."
log "PHP files within /var/www/*/htdocs/wp-content/uploads/ and /var/www/*/htdocs/sites/default/files/." >> "/opt/scripts/scan_results.txt"
log "These can be malicious and should be reviewed manually and removed if they are indeed non-legit files:" >> "/opt/scripts/scan_results.txt"
log ""

find /var/www/*/htdocs/wp-content/uploads/ /var/www/*/htdocs/sites/default/files/ -name "*.php" -printf '%TY-%Tm-%Td %TT %p\n' | sort -r | grep -vi 'cache\|twig' >> "/opt/scripts/scan_results.txt"
log "PHP file scan complete"
log ""

# Binaries within /var/www/, /var/tmp/, /var/lib/dav/, /tmp/, and /dev/shm/
log "Step 7 of 9"
log "Searching for Binary files within /dev/shm, /var/tmp, /var/lib/dav, and /var/www/. This can take a while, please be patient."
log "Binary files found within /dev/shm/, /var/tmp, /var/lib/dav, /tmp, and /var/www/." >> "/opt/scripts/scan_results.txt"
log "These can be malicious and should be reviewed manually and removed if they are indeed non-legit files:" >> "/opt/scripts/scan_results.txt"
log ""

find /dev/shm/ /var/tmp/ /var/lib/dav/ /tmp/ /var/www/ -type f -exec file -i '{}' \; | grep 'x-executable; charset=binary' | awk -F ':' '{print $1}' | while read -r file; do
  find "$file" -printf '%TY-%Tm-%Td %TT %p\n' | sort -r
done >> "/opt/scripts/scan_results.txt"
log "Binary file scan complete"
log ""

# Files owned apache:apache or www-data:www-data within /var/www/, /var/tmp/, /var/lib/dav/, /tmp/, /dev/shm/
# Note: this portion will need filtering added as a pipe to 'grep -v' or blacklisting added to the find command. Until then, expect this to be verbose
log "Step 8 of 9"
log "Scanning for files owned $webuser:$webuser within /tmp, /var/tmp, /var/www, and /dev/shm/."
log "Files owned $webuser:$webuser within /tmp, /var/tmp, /var/lib/dav, /var/www, and /dev/shm:" >> "/opt/scripts/scan_results.txt"
log "These can be malicious and should be reviewed manually and removed if they are indeed non-legit files:" >> "/opt/scripts/scan_results.txt"
log "A large number of files here could indicate the need for a recursive permissions reset on the docroot." >> "/opt/scripts/scan_results.txt"
log ""

find /tmp/ /var/tmp/ /dev/shm/ /var/lib/dav/ /var/www/ -type f -user "$webuser" -group "$webuser" -printf '%TY-%Tm-%Td %TT %p\n' | sort -r | grep -vi 'css$\|js$\|js.gz$\|css.gz$\|png$\|jpg$\|jpeg$\|pdf$\|gif$\|gz.info$\|doc$\|docx$\|cache\|twig\|gluster\|proc' >> "/opt/scripts/scan_results.txt"
log "File scan complete"
log ""

# Directories owned apache:apache or www-data:www-data within /var/www/, /var/tmp/, /tmp/, /dev/shm/
# Note: this portion will need filtering added as a pipe to 'grep -v' or blacklisting added to the find command. Until then, expect this to be verbose
log "Step 9 of 9"
log "Scanning for directories owned $webuser:$webuser within /tmp, /var/tmp, /var/www, and /dev/shm/."
log "Directories owned $webuser:$webuser within /tmp, /var/tmp, /var/lib/dav, /var/www, and /dev/shm:" >> "/opt/scripts/scan_results.txt"
log "These can be malicious and should be reviewed manually and removed if they are indeed non-legit directories." >> "/opt/scripts/scan_results.txt"
log "A large number of directories here could indicate the need for a recursive permissions reset on the docroot." >> "/opt/scripts/scan_results.txt"
log ""

find /tmp/ /var/tmp/ /dev/shm/ /var/www/ -type d -user "$webuser" -group "$webuser" -printf '%TY-%Tm-%Td %TT %p\n' | sort -r >> "/opt/scripts/scan_results.txt"
log "Directory scan complete"
log ""


#chkrootkit install

wget -O /home/contegixadmin/chkrootkit.tar.gz ftp://ftp.chkrootkit.org/pub/seg/pac/chkrootkit.tar.gz
tar -xzvpf /home/contegixadmin/chkrootkit.tar.gz

#chkrootkit check

log "Additionally, here are results from chkrootkit:"

/home/contegixadmin/chkrootkit-0.58b/chkrootkit | grep -v "nothing found\|not found\|not infected\|not tested\|no suspect" >> "/opt/scripts/scan_results.txt"

finish_time="$(date +%s)"

# Send Results Via Mail - commented out for testing
# mail -s "CMS updates for $hostname" user@hostname.tld < "/opt/scripts/updates.txt"

log "Time duration: $((finish_time - start_time)) secs."
log "Time duration: $((finish_time - start_time)) secs." >> "/opt/scripts/scan_results.txt"
