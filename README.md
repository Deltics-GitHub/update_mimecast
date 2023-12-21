[DEPRECATED] Please use the new Mimecast API 2.0 version https://github.com/Deltics-GitHub/Zorgmail-Mimecast-Sync
# update_mimecast

This is a script used for updating the Mimecast profile group with the latest Zorgmail domainbook.

Create a directory /opt/update_mimecast_zorgdomains and place the files update_mimecast_zorgdomains.py and the the dummy.conf in this directory.

Change the information in the dummy.conf file and fill in your access_key, secret_key, app_id and app_key.
Also add your domains to the exclude list, so internal mail will not be routed through Zorgmail.

Create a crontab with the information provided in the cron.txt file. (The user should have permissions to execute the script).
