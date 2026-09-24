#!/bin/sh
# Résout *.lab.test vers l'IP du Core (trouvée par DNS Docker) : évite CORE_IP et extra_hosts.
ip=$(getent hosts "${CORE_HOST:-goproxify-core}" | awk '{print $1; exit}')
[ -n "$ip" ] || { echo "goproxify-core introuvable sur goproxify_net (stack principale démarrée ?)" >&2; exit 1; }
grep -v '\.lab\.test' /etc/hosts > /tmp/hosts.new
for h in lab-fast lab-waf-block lab-waf-detect lab-ratelimit lab-chaos lab-juice; do echo "$ip $h.lab.test" >> /tmp/hosts.new; done
cat /tmp/hosts.new > /etc/hosts
