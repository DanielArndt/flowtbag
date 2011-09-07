include $(GOROOT)/src/Make.inc

TARG=flowtbag2
GOFILES=\
	src/flowtbag.go\
	src/flow.go\
	src/tcpState.go\

include $(GOROOT)/src/Make.cmd
