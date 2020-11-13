package main

import (
	"fmt"
	"math/rand"
	"publicKeyRotator"
	"time"
)

func main(){
	rotator,_ := publicKeyRotator.InitPublicKeyRotator("")
	rotator.Rotate(time.Second + 3)

	rand.Seed(time.Now().UnixNano())
	for {
		time.Sleep(time.Millisecond * 100)
		key := rotator.ReadPublicKeyMap()
		fmt.Printf("%v\n",key)
	}

}