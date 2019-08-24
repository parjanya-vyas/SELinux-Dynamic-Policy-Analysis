rm -f db.sqlite3
rm -fr rwfm/migrations/
python manage.py makemigrations rwfm
python manage.py migrate
python manage.py runserver 0.0.0.0:8000
