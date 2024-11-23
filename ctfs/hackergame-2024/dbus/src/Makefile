all: flagserver getflag3

flagserver: flagserver.c
	gcc flagserver.c `pkg-config --cflags --libs gio-2.0` -o flagserver

getflag3: getflag3.c
	gcc getflag3.c `pkg-config --cflags --libs gio-2.0` -o getflag3

install: all
	install -d /usr/bin/
	install -d /usr/share/dbus-1/system-services/
	install -d /usr/share/dbus-1/system.d/
	install -m 755 flagserver /usr/bin/flagserver
	install -m 444 cn.edu.ustc.lug.hack.FlagService.service /usr/share/dbus-1/system-services/
	install -m 444 cn.edu.ustc.lug.hack.FlagService.conf /usr/share/dbus-1/system.d/

	install -m 755 getflag3 /usr/bin/getflag3

clean:
	rm -rf flagserver getflag3
