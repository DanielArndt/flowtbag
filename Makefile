include $(GOROOT)/src/Make.inc

TARG=flowtbag
GOFILES=\
	src/flowtbag.go\
	src/flow.go\
	src/tcpState.go\
	src/feature.go\

include $(GOROOT)/src/Make.cmd
