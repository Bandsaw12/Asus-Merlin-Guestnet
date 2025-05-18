# Asus-Merlin-Guestnet
Guest Network Script

This is a script that started out life as a few lines of code that allowed me to add a LAN port to the guest network.  The script was inspired by github user JackYaz.

I was working on a production version to share until git user janico82 (https://github.com/janico82/sbnMerlin) published his own fine work.  Sense janico82 published his work, I now just play around with this script to help me keep my own programming skills up.  I still use it on my RT-AX86U-Pro running 3004.388.8_4 firmware.

I use an RT-AC86U running 3004.386.14_2 firmware, without entware as my development router.

The script uses a configuration file that is created when the script is first run (./guest-net.sh start).  The configuration file can be found in the same directory that this script resides.  Once created, edit the configuration file to setup the script parameters.

Before running the script, the guest network must be setup from the Asus GUI of the router.  The script works with only one guest network.

There is some manual work involved to have the script work on boot and continue to work after various Asus events happen.  I was going to automate these extra actions, but probably will not now that Janico82 has published his script.

First, you must set up some dnsmasq parameters so that DHCP can hand out addresses to your guest network.  I have added an example of a dnsmasq.conf.add script in the repository.  Simply edit the dnsmasq.conf.add file using the same bridge name and IP address matching your setup.

Secondly, you need to setup various user scripts.  I have added examples for the firewall-start, services-start, nat-start, and services-event-end script that is needed to get this script working properly.  All of the example user scripts assume the script is located in /jffs/addons/guest directory.  Again, I’m not planning on automating any of these user scripts now that Janico82’s script is up and running.

You can run your own custom scripts (to add additional firewall rules, as an example) by putting your scripts in a directory called “scripts” located in the same directory as the gust-net.sh script.  The only cavet is your additional scripts must named as *.sh and must have the execute permission added.

Just a note about how naming your guest network bridge may affect how DNS works.  If the router’s global redirection parameter in DNS Director is set to “Router”, then a couple of iptable PREROUTING rules are added using a pattern match of “br+” that redirects any DNS requests to the router (or as setup in DNS Director). Therefore if you name your guest bridge “br604”, as an example, then DNS requests will be caught by the router’s DNS Director.  If, however, you use a bridge name such as “brgst”, then the iptables PREROUTING rules will not match and the DNS servers you defined in your dnsmasq setup should be used instead of the routers.






