# servod
servod the leightweight webserver with cgi extensions for php and sqlite
php-cgi has sqlite support built in so it should all work great on different platforms.

g++ -std=c++20 -lssl -lcrypto -lpthread -o servod servod.cpp -I/Users/macbook2015/Desktop/brew/include -L/Users/macbook2015/Desktop/brew/lib
mkdir -p www
echo "<?php echo 'Hello from PHP!'; ?>" > www/index.php
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
./servod