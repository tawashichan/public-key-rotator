package main

import (
	"fmt"
	"publicKeyRotator"
	"time"
)

func main() {
	rotator, _ := publicKeyRotator.InitPublicKeyRotator("")
	rotator.Rotate(time.Second + 3)

	for {
		time.Sleep(time.Millisecond * 100)
		key := rotator.ReadPublicKeyMap()
		fmt.Printf("%v\n", key)
	}

}
