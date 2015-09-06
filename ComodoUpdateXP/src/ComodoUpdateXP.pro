TEMPLATE = app

CONFIG -= app_bundle
CONFIG -= qt

QMAKE_LFLAGS += -static

LIBS += -lpsapi

SOURCES += main.cpp
