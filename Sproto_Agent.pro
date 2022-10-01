QT += network
CONFIG += c++11
CONFIG += console

INCLUDEPATH += "C:/Users/1234Y/Desktop/npcap 1.12/Include"
INCLUDEPATH += "C:/Program Files (x86)/Windows Kits/10/Include/10.0.19041.0/um"
LIBS += "-LC:/Users/1234Y/Desktop/npcap 1.12\Lib\x64" -lwpcap -lws2_32

SOURCES += \
        main.cpp


HEADERS += \
    AgentClient.h \
    HeadersFiles.h
