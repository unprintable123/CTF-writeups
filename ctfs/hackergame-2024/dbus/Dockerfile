# Uncomment "RUN echo"s, then do this locally for testing:
# docker build -t local/dbus .
# cat <YOUR_PAYLOAD> | base64 --wrap=0 | docker run --rm --tmpfs /dev/shm:exec -i local/dbus
FROM ustclug/debian:bookworm-slim

# Fine, we give gdbus and dbus-send for you, to make your life easier... maybe?
RUN apt update && apt install --no-install-recommends -y build-essential libglib2.0-dev \
    dbus-daemon dbus-system-bus-common python3 libglib2.0-bin dbus-bin

ADD src /src
WORKDIR /src
RUN make && make install && mkdir -p /run/dbus && \
    sed -i 's|/run/dbus/system_bus_socket|/dev/shm/system_bus_socket|' /usr/share/dbus-1/system.conf && \
    sed -i 's|/run/dbus/pid|/dev/shm/dbus-pid|' /usr/share/dbus-1/system.conf && \
    mkdir -p /usr/share/dbus-1/system-services/ && mkdir -p /usr/share/dbus-1/system.d/ && \
    mv cn.edu.ustc.lug.hack.FlagService.service /usr/share/dbus-1/system-services/ && \
    mv cn.edu.ustc.lug.hack.FlagService.conf /usr/share/dbus-1/system.d/

# Note that you cannot just "cat /flag1" directly on server :)
# RUN echo "Submit your program to get real flag1 on server!" > /flag1 && \
#     echo "Submit your program to get real flag2 on server!" > /flag2 && \
#     echo "Submit your program to get real flag3 on server!" > /flag3

CMD ["python3", "-u", "/src/server.py"]
