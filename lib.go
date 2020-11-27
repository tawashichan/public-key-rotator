package publicKeyRotator

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"
)

type KeyId string

type RSAPublicKey struct {
	KeyId KeyId
	Key   rsa.PublicKey
}

type RSAPublicKeyMap map[KeyId]RSAPublicKey

type PublicKeyRotator struct {
	rotationStarted bool
	endpoint        string
	keyMutex        *sync.RWMutex
	rsaPublicKeyMap RSAPublicKeyMap
	httpClient      *http.Client
}

type RSAJSONWebKey struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

type RSAJWKs []RSAJSONWebKey

type RSAJWKResponse struct {
	JWKs []RSAJSONWebKey `json:"jwks"`
}

func InitPublicKeyRotator(endpoint string) (PublicKeyRotator, error) {
	var rwMutex = sync.RWMutex{}
	client := &http.Client{}
	initialKeyMap, err := getRSAPublicKeyMapFromEndpoint(client, endpoint)
	if err != nil {
		return PublicKeyRotator{}, err
	}
	return PublicKeyRotator{
		keyMutex:        &rwMutex,
		endpoint:        endpoint,
		rsaPublicKeyMap: initialKeyMap,
		httpClient:      client,
	}, nil
}

func (rotator *PublicKeyRotator) Rotate(rotationSpan time.Duration) {
	if rotator.rotationStarted {
		return
	}
	rotator.rotationStarted = true
	go func() {
		for {
			time.Sleep(rotationSpan)
			key, err := getRSAPublicKeyMapFromEndpoint(rotator.httpClient, rotator.endpoint)
			if err != nil {
				log.Printf(`{"type": "jwk endpoint","message": "endpoint is not active"}`)
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

func getRSAPublicKeyMapFromEndpoint(client *http.Client, endpoint string) (RSAPublicKeyMap, error) {
	response, err := client.Get(endpoint)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	var jwkResponse RSAJWKResponse
	if err := json.Unmarshal(body, &jwkResponse); err != nil {
		return nil, err
	}
	return getRSAPublicKeyMapFromJWKs(jwkResponse.JWKs)
}

func getRSAPublicKeyFromJWK(jwk RSAJSONWebKey) (RSAPublicKey, error) {
	decodedN, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return RSAPublicKey{}, err
	}
	var keyN big.Int
	keyN.SetBytes(decodedN)

	keyE, err := decodeStringToUint64(jwk.E)
	if err != nil {
		return RSAPublicKey{}, err
	}

	return RSAPublicKey{
		KeyId: KeyId(jwk.Kid),
		Key: rsa.PublicKey{
			N: &keyN,
			E: int(keyE),
		},
	}, nil
}

func getRSAPublicKeyMapFromJWKs(jwks RSAJWKs) (RSAPublicKeyMap, error) {
	keyMap := make(RSAPublicKeyMap)
	for _, jwk := range jwks {
		key, err := getRSAPublicKeyFromJWK(jwk)
		if err != nil {
			return nil, err
		}
		keyMap[key.KeyId] = key
	}
	return keyMap, nil
}

func decodeStringToUint64(str string) (uint64, error) {
	bytes, err := decodeStringToBytes(str)
	if err != nil {
		return 0, err
	}

	data := make([]byte, 8)
	for i, v := range bytes {
		data[8-len(bytes)+i] = v
	}

	return binary.BigEndian.Uint64(data), nil
}

func decodeStringToBytes(str string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(str)
}
