package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"
)

func CreateChallenge(a *ecdsa.PrivateKey) ([]byte, *ecdsa.PrivateKey, *ecdsa.PrivateKey, *big.Int){
	curve := elliptic.P256()
	v, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil{
		log.Panic(err)
	}

	//gets public keys from private keyes
	V := v.PublicKey.X.Bytes()
	A := a.PublicKey.X.Bytes()


	//gets curve order
	parameters := curve.Params()
	n:= parameters.N

	generatorPointX := parameters.Gx
	generatorPointXBytes := generatorPointX.Bytes()

	challengeBytes := append(generatorPointXBytes, V...)
	challengeBytes = append(challengeBytes, A...)

	challenge := sha256.Sum256(challengeBytes)
	c := challenge[:]
	return c, a, v, n
}

func CreateProof(a *ecdsa.PrivateKey) (*big.Int, ecdsa.PublicKey, *big.Int){
	c, a, v, n := CreateChallenge(a)

	//gets public keys
	V := v.PublicKey.X

	cN := new(big.Int)
	cN.SetBytes(c)

	r := new(big.Int)
	r.Mul(a.D ,cN)
	r.Sub(v.D,r)
	r.Mod(r, n)





	return r, a.PublicKey, V

}

func VerifyProof(r *big.Int, A ecdsa.PublicKey, V *big.Int ) (bool){
	curve := elliptic.P256()
	if !curve.IsOnCurve(A.X, A.Y){
		return false
	}


	GxrX,GxrY := curve.ScalarBaseMult(r.Bytes())
	challengeBytes := append(curve.Params().Gx.Bytes(), V.Bytes()...)
	challengeBytes = append(challengeBytes,A.X.Bytes()...)
	challenge := sha256.Sum256(challengeBytes)
	c := challenge[:]

	AxcX, AxcY := curve.ScalarMult(A.X, A.Y, c)

	finalX := new(big.Int)

	finalX, _= curve.Add(GxrX,GxrY, AxcX,AxcY)
	fmt.Print(finalX, "\n" )
	fmt.Print(V, "\n")

	return finalX.Cmp(V) == 0


}

func main() {
	curve := elliptic.P256()

	a, err := ecdsa.GenerateKey(curve,rand.Reader)
	if err != nil{
		log.Panic(err)
	}
	r, A, V := CreateProof(a)

	fmt.Print(VerifyProof(r,A,V))



}