FROM micropython/unix:v1.18

RUN /usr/local/bin/micropython-dev -m upip install uasyncio
RUN /usr/local/bin/micropython-dev -m upip install unittest

WORKDIR /code

COPY ./micropython_captive_dns_server/* .

CMD ["/usr/local/bin/micropython-dev", "server.py"]
