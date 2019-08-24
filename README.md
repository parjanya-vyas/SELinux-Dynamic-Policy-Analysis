
* Setting up RWFM rules engine.

Make sure you have following package installed on your system.
    python3
    sqlite3
    python-virtualenv
    python3-pip
    libcurl4-gnutls-dev
    librtmp-dev
    pycurl

Run following commands to get your app running.

  git clone https://bitbucket.org/atawre/secureos/
  cd secureos
  pip install -r reqs.txt
  cd webapp
  rm -f db.sqlite3
  rm -fr rwfm/migrations/
  python manage.py makemigrations rwfm
  python manage.py migrate
  python manage.py runserver 0.0.0.0:8000


* Installing client.

  Run following commands from the machine you want to protect.

  # git clone https://bitbucket.org/atawre/secureos/
  # cd secureos/client/
  
  Configure rwfmd.cfg to use user Rules engine and run install script -

  # bash install.sh

  Once installation is done, run secure shell as  
 
  # /opt/secos/bin/secure_shell

  Enable rwfm as follows - 

  # rwfm enable

  You can see the rwfmd daemon log @  /var/log/rwfmd.log

Run your test program.

If you get "port in use" error while executing rwfmd.py or webapp - just type in the following command:
For error in rwfmd.py: sudo fuser -k 5000/tcp
For error in django webapp: sudo fuser -k 8000/tcp
