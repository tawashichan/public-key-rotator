package publicKeyRotator

import (
	"crypto/rsa"
	"fmt"
	"math/rand"
	"sync"
	"time"
)

type KeyId string

type RSAPublicKey struct {
	KeyId KeyId
	Key rsa.PublicKey
}

type RSAPublicKeyMap map[KeyId]RSAPublicKey

type PublicKeyRotator struct {
	rotationStarted bool
	endpoint string
	keyMutex *sync.RWMutex
	rsaPublicKeyMap RSAPublicKeyMap
}

func InitPublicKeyRotator(endpoint string) (PublicKeyRotator,error) {
	var rwMutex = sync.RWMutex{}
	initialKeyMap,err := getRSAPublicKeyMapFromEndpoint(endpoint)
	if err != nil {
		return PublicKeyRotator{},err
	}
	return PublicKeyRotator{
		keyMutex: &rwMutex,
		endpoint: endpoint,
		rsaPublicKeyMap: initialKeyMap,
	},nil
}

func (rotator *PublicKeyRotator) Rotate(rotationSpan time.Duration) {
	if rotator.rotationStarted {
		return
	}
	rotator.rotationStarted = true
	go func(){
		for {
			time.Sleep(rotationSpan)
			key,err := getRSAPublicKeyMapFromEndpoint(rotator.endpoint)
			if err != nil {
				// 親プロセスごと停止
				panic("error in rotator: getting public key failed")
			}
			rotator.keyMutex.Lock()
			rotator.rsaPublicKeyMap = key
			rotator.keyMutex.Unlock()
		}
	}()
}

func (rotator PublicKeyRotator) ReadPublicKeyMap() RSAPublicKeyMap {
	rotator.keyMutex.RLock()
	defer rotator.keyMutex.RUnlock()
	return rotator.rsaPublicKeyMap
}

func getRSAPublicKeyMapFromEndpoint(endpoint string) (RSAPublicKeyMap,error) {
	id := KeyId(fmt.Sprintf("%v",rand.Int()))
	return RSAPublicKeyMap{
		id: RSAPublicKey{},
	},nil
}