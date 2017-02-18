#!/usr/bin/env python
import sys, os, pip

if os.geteuid() != 0:
		print "You are not privileged enough."
		sys.exit(1)

try:
	import apt
except Exception:
	print "[-] 'python-apt' package does not exist, installing"
	os.system('apt-get install -y python-apt')
	print "[-] Retrying to import apt module"
	import apt

apt_packages = ["python-scapy"]
pip_packages = ["pbkdf2"]

def install_scapy_com():
	print "[+] Preparing to install community version of scapy"
	clone_command 			= "hg clone https://bitbucket.org/secdev/scapy-com"
	installation_command 	= "python scapy-com/setup.py install"
	cleanup_command 		= "rm -rf scapy-com"

	print "[+] Cloning scapy-com official repository"
	os.system(clone_command)

	print "[+] Running scapy-com setup installation"
	os.system(installation_command)

	print "[+] Cleaning up the cloned folder after installation"
	os.system(cleanup_command)

print "[+] Updating apt... (This may take a while)"
cache = apt.cache.Cache()
cache.update()  # apt-get update
cache.open()    # use the updated list

for pkg in apt_packages:
	try:
		print "[+] Preparing to install '{}'".format(pkg)
		apt_pkg = cache[pkg]

		if apt_pkg.is_installed:
			print "[-] '{}' already installed, skipping...".format(pkg)
		else:
			apt_pkg.mark_install()
			cache.commit()
			print "[+] Installation of package '{}' was successful.".format(pkg)

	except Exception as e:
		print e
		print "[-] Installation of package '{}' failed.".format(pkg)

for pkg in pip_packages:
	print "[+] Preparing to install '{}' via python-pip".format(pkg)
	pip.main(["install", pkg])

install_scapy_com()