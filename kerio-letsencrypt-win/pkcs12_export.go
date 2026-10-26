package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"unicode/utf16"
)

// Pure-Go RFC 7292 + PKCS#5 v2.1 (PBES2 PBKDF2-HMAC-SHA256 + AES-256-CBC) PKCS#12 (.pfx) builder.
// Compatible with Windows Certificate Store (Win10/11 & Server 2019/2022/2025), IIS, Kerio, and OpenSSL 3.x.

var (
	oidDataContentType          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidEncryptedDataContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidPKCS8ShroudedKeyBag      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidCertBag                  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidX509Certificate          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	oidFriendlyName             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}
	oidLocalKeyID               = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}
	oidPBES2                    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACWithSHA256           = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES256CBC                = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidSHA256                   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
)

type pfxStructure struct {
	Version  int
	AuthSafe contentInfoASN1
	MacData  macDataASN1
}

type contentInfoASN1 struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type macDataASN1 struct {
	Mac        digestInfoASN1
	MacSalt    []byte
	Iterations int
}

type digestInfoASN1 struct {
	Algorithm algorithmIdentifierASN1
	Digest    []byte
}

type algorithmIdentifierASN1 struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type pbes2ParamsASN1 struct {
	KeyDerivationFunc algorithmIdentifierASN1
	EncryptionScheme  algorithmIdentifierASN1
}

type pbkdf2ParamsASN1 struct {
	Salt           []byte
	IterationCount int
	Prf            algorithmIdentifierASN1
}

type encryptedPrivateKeyInfoASN1 struct {
	EncryptionAlgorithm algorithmIdentifierASN1
	EncryptedData       []byte
}

type encryptedDataASN1 struct {
	Version              int
	EncryptedContentInfo encryptedContentInfoASN1
}

type encryptedContentInfoASN1 struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm algorithmIdentifierASN1
	EncryptedContent           []byte `asn1:"implicit,optional,tag:0"`
}

type safeBagASN1 struct {
	Id         asn1.ObjectIdentifier
	Value      asn1.RawValue     `asn1:"explicit,tag:0"`
	Attributes []pkcs12Attribute `asn1:"set,optional"`
}

type pkcs12Attribute struct {
	Id     asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

type certBagASN1 struct {
	Id   asn1.ObjectIdentifier
	Data []byte `asn1:"explicit,tag:0"`
}

// BuildPFX creates a standard PKCS#12 (.pfx) archive containing the private key, leaf certificate, and CA chain.
func BuildPFX(privKey crypto.Signer, leafCertDER []byte, chainCertDERs [][]byte, password string, friendlyName string) ([]byte, error) {
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка сериализации PKCS#8 ключа для PFX: %w", err)
	}

	keyIDHash := sha256.Sum256(leafCertDER)
	localKeyID := keyIDHash[:20]

	attrs, err := makeBagAttributes(friendlyName, localKeyID)
	if err != nil {
		return nil, err
	}

	// 1. Encrypt private key into PKCS8ShroudedKeyBag using PBES2 (PBKDF2-SHA256 + AES-256-CBC)
	encAlg, encKeyBytes, err := pbes2Encrypt(pkcs8Bytes, password, 2048)
	if err != nil {
		return nil, err
	}
	shroudedBytes, err := asn1.Marshal(encryptedPrivateKeyInfoASN1{
		EncryptionAlgorithm: encAlg,
		EncryptedData:       encKeyBytes,
	})
	if err != nil {
		return nil, err
	}
	keySafeBag := safeBagASN1{
		Id:         oidPKCS8ShroudedKeyBag,
		Value:      asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: shroudedBytes},
		Attributes: attrs,
	}
	keySafeContentsBytes, err := asn1.Marshal([]safeBagASN1{keySafeBag})
	if err != nil {
		return nil, err
	}
	keyContentInfo, err := makeDataContentInfo(keySafeContentsBytes)
	if err != nil {
		return nil, err
	}

	// 2. Build Certificate SafeBags (leaf + intermediates) and encrypt into EncryptedData ContentInfo
	var certBags []safeBagASN1
	leafBagBytes, err := makeCertBagValue(leafCertDER)
	if err != nil {
		return nil, err
	}
	certBags = append(certBags, safeBagASN1{
		Id:         oidCertBag,
		Value:      asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: leafBagBytes},
		Attributes: attrs,
	})
	for _, caDER := range chainCertDERs {
		caBagBytes, err := makeCertBagValue(caDER)
		if err != nil {
			return nil, err
		}
		certBags = append(certBags, safeBagASN1{
			Id:    oidCertBag,
			Value: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: caBagBytes},
		})
	}
	certSafeContentsBytes, err := asn1.Marshal(certBags)
	if err != nil {
		return nil, err
	}
	certEncAlg, certEncBytes, err := pbes2Encrypt(certSafeContentsBytes, password, 2048)
	if err != nil {
		return nil, err
	}
	encDataBytes, err := asn1.Marshal(encryptedDataASN1{
		Version: 0,
		EncryptedContentInfo: encryptedContentInfoASN1{
			ContentType:                oidDataContentType,
			ContentEncryptionAlgorithm: certEncAlg,
			EncryptedContent:           certEncBytes,
		},
	})
	if err != nil {
		return nil, err
	}
	certContentInfo := contentInfoASN1{
		ContentType: oidEncryptedDataContentType,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: encDataBytes},
	}

	// 3. AuthenticatedSafe = SEQUENCE OF ContentInfo
	authSafeBytes, err := asn1.Marshal([]contentInfoASN1{certContentInfo, keyContentInfo})
	if err != nil {
		return nil, err
	}
	authSafeCI, err := makeDataContentInfo(authSafeBytes)
	if err != nil {
		return nil, err
	}

	// 4. Compute RFC 7292 PKCS#12 MAC (SHA-256)
	macSalt := make([]byte, 16)
	if _, err := rand.Read(macSalt); err != nil {
		return nil, err
	}
	const macIter = 2048
	macKey := pkcs12KDFSha256(encodeBMPPassword(password), macSalt, 3, macIter, 32)
	h := hmac.New(sha256.New, macKey)
	h.Write(authSafeBytes)
	macDigest := h.Sum(nil)

	pfx := pfxStructure{
		Version:  3,
		AuthSafe: authSafeCI,
		MacData: macDataASN1{
			Mac: digestInfoASN1{
				Algorithm: algorithmIdentifierASN1{
					Algorithm:  oidSHA256,
					Parameters: asn1.NullRawValue,
				},
				Digest: macDigest,
			},
			MacSalt:    macSalt,
			Iterations: macIter,
		},
	}
	return asn1.Marshal(pfx)
}

func makeDataContentInfo(data []byte) (contentInfoASN1, error) {
	octet, err := asn1.Marshal(data)
	if err != nil {
		return contentInfoASN1{}, err
	}
	return contentInfoASN1{
		ContentType: oidDataContentType,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: octet},
	}, nil
}

func makeCertBagValue(certDER []byte) ([]byte, error) {
	octet, err := asn1.Marshal(certDER)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(certBagASN1{
		Id:   oidX509Certificate,
		Data: octet,
	})
}

func makeBagAttributes(friendlyName string, localKeyID []byte) ([]pkcs12Attribute, error) {
	var attrs []pkcs12Attribute
	if len(localKeyID) > 0 {
		idBytes, err := asn1.Marshal(localKeyID)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, pkcs12Attribute{
			Id:     oidLocalKeyID,
			Values: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: idBytes},
		})
	}
	if friendlyName != "" {
		u16 := utf16.Encode([]rune(friendlyName))
		bmp := make([]byte, len(u16)*2)
		for i, v := range u16 {
			bmp[i*2] = byte(v >> 8)
			bmp[i*2+1] = byte(v)
		}
		bmpVal, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: 30, IsCompound: false, Bytes: bmp})
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, pkcs12Attribute{
			Id:     oidFriendlyName,
			Values: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: bmpVal},
		})
	}
	return attrs, nil
}

func pbes2Encrypt(plaintext []byte, password string, iterations int) (algorithmIdentifierASN1, []byte, error) {
	salt := make([]byte, 16)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(salt); err != nil {
		return algorithmIdentifierASN1{}, nil, err
	}
	if _, err := rand.Read(iv); err != nil {
		return algorithmIdentifierASN1{}, nil, err
	}

	key := pbkdf2SHA256([]byte(password), salt, iterations, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return algorithmIdentifierASN1{}, nil, err
	}

	padLen := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	padded := make([]byte, len(plaintext)+padLen)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	kdfParamsBytes, err := asn1.Marshal(pbkdf2ParamsASN1{
		Salt:           salt,
		IterationCount: iterations,
		Prf: algorithmIdentifierASN1{
			Algorithm:  oidHMACWithSHA256,
			Parameters: asn1.NullRawValue,
		},
	})
	if err != nil {
		return algorithmIdentifierASN1{}, nil, err
	}

	ivBytes, err := asn1.Marshal(iv)
	if err != nil {
		return algorithmIdentifierASN1{}, nil, err
	}

	pbes2Bytes, err := asn1.Marshal(pbes2ParamsASN1{
		KeyDerivationFunc: algorithmIdentifierASN1{
			Algorithm:  oidPBKDF2,
			Parameters: asn1.RawValue{FullBytes: kdfParamsBytes},
		},
		EncryptionScheme: algorithmIdentifierASN1{
			Algorithm:  oidAES256CBC,
			Parameters: asn1.RawValue{FullBytes: ivBytes},
		},
	})
	if err != nil {
		return algorithmIdentifierASN1{}, nil, err
	}

	return algorithmIdentifierASN1{
		Algorithm:  oidPBES2,
		Parameters: asn1.RawValue{FullBytes: pbes2Bytes},
	}, ciphertext, nil
}

func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var dk []byte
	buf := make([]byte, 4)
	u := make([]byte, hashLen)
	t := make([]byte, hashLen)

	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf)
		u = prf.Sum(u[:0])
		copy(t, u)
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for x := range u {
				t[x] ^= u[x]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

func encodeBMPPassword(password string) []byte {
	if password == "" {
		return []byte{0, 0}
	}
	u16 := utf16.Encode([]rune(password))
	out := make([]byte, (len(u16)+1)*2)
	for i, v := range u16 {
		out[i*2] = byte(v >> 8)
		out[i*2+1] = byte(v)
	}
	return out
}

// RFC 7292 Appendix B.2 PKCS#12 KDF using SHA-256 (v = 64 bytes, u = 32 bytes).
func pkcs12KDFSha256(passwordBMP []byte, salt []byte, id byte, iter int, size int) []byte {
	const v = 64
	const u = 32

	D := make([]byte, v)
	for i := range D {
		D[i] = id
	}
	S := make([]byte, v*((len(salt)+v-1)/v))
	if len(salt) > 0 {
		for i := range S {
			S[i] = salt[i%len(salt)]
		}
	}
	P := make([]byte, v*((len(passwordBMP)+v-1)/v))
	if len(passwordBMP) > 0 {
		for i := range P {
			P[i] = passwordBMP[i%len(passwordBMP)]
		}
	}
	I := append(S, P...)
	c := (size + u - 1) / u
	var out []byte
	B := make([]byte, v)

	for i := 1; i <= c; i++ {
		h := sha256.New()
		h.Write(D)
		h.Write(I)
		A := h.Sum(nil)
		for j := 1; j < iter; j++ {
			sum := sha256.Sum256(A)
			A = sum[:]
		}
		out = append(out, A...)
		if i == c {
			break
		}
		for k := range B {
			B[k] = A[k%len(A)]
		}
		for j := 0; j < len(I); j += v {
			// I_j = (I_j + B + 1) mod 2^512
			carry := uint16(1)
			for k := v - 1; k >= 0; k-- {
				s := uint16(I[j+k]) + uint16(B[k]) + carry
				I[j+k] = byte(s)
				carry = s >> 8
			}
		}
	}
	return out[:size]
}
