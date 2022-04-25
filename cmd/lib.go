package main

import "C"
import (
	"os"
	"rpc/internal/amt"
	"strings"
)

//export checkAccess
func checkAccess() {
	amt := amt.NewAMTCommand()
	result, err := amt.Initialize()
	if !result || err != nil {
		println("Unable to launch application. Please ensure that Intel ME is present, the MEI driver is installed and that this application is run with administrator or root privileges.")
		os.Exit(1)
	}
}

//export rpcExec
func rpcExec(Input *C.char, Output **C.char) {
	checkAccess()

	//create argurment array from input string
	args := strings.Fields(C.GoString(Input))
	args = append([]string{"rpc"}, args...)
	runRPC(args)
	*Output = C.CString("test output")
}
