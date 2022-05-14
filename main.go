package main

import (
	"flag"
	"fmt"
	"log"
	"strconv"

	"github.com/bloxapp/ssv/utils/threshold"
	"github.com/herumi/bls-eth-go-binary/bls"
	"go.uber.org/zap"
)

func main() {
	var privKey string
	var keysCountString, sharesThresholdString string
	var message string
	flag.StringVar(&privKey, "privKey", "", "Private key to be split")
	flag.StringVar(&sharesThresholdString, "threshold", "3", "Number of key shares threshold")
	flag.StringVar(&keysCountString, "total", "5", "Total number of key shares")
	flag.StringVar(&message, "message", "messagetobesigned", "Message to be signed")

	flag.Parse()

	if bls.Init(bls.BLS12_381) != nil {
		log.Fatalf("Init")
	}
	if bls.SetETHmode(0) != nil {
		log.Fatalf("SetMapToMode")
	}

	// First validator private key hex
	keysCount, err := strconv.ParseUint(keysCountString, 10, 64)
	if err != nil {
		log.Fatalf("Invalid keys count")
	}
	sharesThreshold, err := strconv.ParseUint(sharesThresholdString, 10, 64)
	if err != nil {
		log.Fatalf("Invalid threshold")
	}

	baseKey := &bls.SecretKey{}
	if err := baseKey.SetHexString(privKey); err != nil {
		log.Fatal("failed to set hex private key", zap.Error(err))
	}

	privKeys, err := threshold.Create(baseKey.Serialize(), sharesThreshold, keysCount)
	if err != nil {
		log.Fatal("failed to turn a private key into a threshold key", zap.Error(err))
	}

	log.Println("Master Public key", baseKey.GetPublicKey().SerializeToHexStr())

	for i, pk := range privKeys {
		fmt.Println("Public key", i, pk.GetPublicKey().SerializeToHexStr())
		fmt.Println("Private key", i, pk.SerializeToHexStr())
	}

	// partial sigs

	allPartialSignatures := make(map[uint64][]byte)
	for i, s := range privKeys {
		partialSig := s.SignByte([]byte(message))
		allPartialSignatures[i] = partialSig.Serialize()
	}

	thresholdPartialSignatures := make(map[uint64][]byte)
	for i, s := range privKeys {
		partialSig := s.SignByte([]byte(message))
		if i < sharesThreshold {
			thresholdPartialSignatures[i] = partialSig.Serialize()
		}
	}

	signatureReconstructed, _ := threshold.ReconstructSignatures(allPartialSignatures)
	signatureReconstructedThreshold, _ := threshold.ReconstructSignatures(thresholdPartialSignatures)

	log.Print("Signature verification  Sig:", signatureReconstructed.VerifyByte(baseKey.GetPublicKey(), []byte(message)), "\n", signatureReconstructed.SerializeToHexStr())
	log.Print("Signature verification Sig1:", signatureReconstructedThreshold.VerifyByte(baseKey.GetPublicKey(), []byte(message)), "\n", signatureReconstructedThreshold.SerializeToHexStr())

}
