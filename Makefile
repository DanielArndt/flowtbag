include $(GOROOT)/src/Make.inc

TARG=flowtbag
GOFILES=\
	src/flowtbag.go\
	src/flow.go\
	src/tcpState.go\
	src/features.go\
	src/misc.go\

include $(GOROOT)/src/Make.cmd
