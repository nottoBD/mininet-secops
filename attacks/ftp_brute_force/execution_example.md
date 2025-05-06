ftp sudo nano /etc/vsftpd.conf

anonymous_enable=NO
local_enable=YES
write_enable=YES


sudo systemctl restart vsftpd

protection : 
source protections/ftp_brute_force/run_ftp_brute_force_protection.py
