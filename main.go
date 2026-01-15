package main

import (
	"sim_reader/cmd"
	_ "sim_reader/sim/card_drivers"
)

func main() {
	cmd.Execute()
}
