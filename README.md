# servod
servod the leightweight webserver with cgi extensions for php and sqlite
php-cgi has sqlite support built in so it should all work great on different platforms.

the decentralized folder is a version of the webserver that serves zip files as websites to store offline like i2p

g++ -std=c++20 -lssl -lcrypto -lpthread -o servod servod.cpp -I/Users/macbook2015/Desktop/brew/include -L/Users/macbook2015/Desktop/brew/lib <br>
mkdir -p www <br>
echo "<?php echo 'Hello from PHP!'; ?>" > www/index.php <br>
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes <br>
./servod <br>
