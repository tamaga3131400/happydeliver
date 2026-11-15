#!/bin/sh
# Rotates the container logs once a day and deletes rotated logs after 10 days.
while :; do
    stamp=$(date +%Y%m%d)
    for log in /var/log/happydeliver/*.log /var/log/messages; do
        [ -s "$log" ] || continue
        cat "$log" >> "$log.$stamp" && : > "$log"
    done
    # Rotated files keep at most one day of entries, so +8 bounds the age at 10 days.
    find /var/log/happydeliver -maxdepth 1 -type f -name '*.log.*' -mtime +8 -exec rm -f {} +
    find /var/log -maxdepth 1 -type f -name 'messages.*' -mtime +8 -exec rm -f {} +
    sleep 86400
done
