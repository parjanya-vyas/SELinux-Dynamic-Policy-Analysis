
* Setting up RWFM rules engine.

Make sure you have following package installed on your system.
    python3
    sqlite3
    python-virtualenv
    python3-pip
    libcurl4-gnutls-dev
    librtmp-dev
    pycurl

Follow the steps mentioned at https://github.com/TresysTechnology/setools/wiki/SETools-4-on-Ubuntu-16.10 to install setools python package:
    $ sudo apt install gcc bison flex swig mock libbz2-dev
    $ sudo apt install libsepol1 libsepol1-dev gcc sepol-utils
    $ sudo apt install libselinux1 libselinux1-dev python-selinux selinux-utils python-dev
    $ sudo apt install python-enum34 python-pyqt5 python-setools python-pip python-mock python-tox
    $ sudo pip install networkx

Build and Install:
    $ cd setools
    $ python setup.py build
    $ sudo python setup.py install

* Installing runtime monitor.

  Run following commands from the machine you want to protect.

    $ git clone https://github.com/parjanya-vyas/SELinux-Dynamic-Policy-Analysis/
  
* Installing webapp.
    $ cd webapp
    $ ./start_server.sh

* Installing client
    $ cd client
    $ sudo ./install.sh
  
  Configure rwfmd.cfg to use user Rules engine and run install script -

  Once installation is done, run secure shell as  
 
    $ /opt/secos/bin/secure_shell

  Enable rwfm as follows - 

    $ /opt/secos/bin/rwfm enable

  You can see the rwfmd daemon log @  /var/log/rwfmd.log

Run your test program.

If you get "port in use" error while executing rwfmd.py or webapp - just type in the following command:
For error in rwfmd.py: sudo fuser -k 5000/tcp
For error in django webapp: sudo fuser -k 8000/tcp
