FROM ubuntu:20.04

ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
RUN apt-get update && apt-get install -y \
    apache2 \
    php

RUN mkdir -p /app
COPY preload.php /app
COPY src/index.php /var/www/html/index.php
COPY php.ini /etc/php/7.4/apache2/php.ini

RUN rm -rf /var/www/html/*.html
RUN chmod 555 /app/preload.php
RUN chmod 555 /var/www/html/index.php
RUN echo "aliyunctf{`head /dev/urandom | tr -dc A-Za-z0-9 | head -c 15`}" > /flag
RUN chmod 444 /flag
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf

CMD ["/usr/sbin/apache2ctl", "-D", "FOREGROUND"]