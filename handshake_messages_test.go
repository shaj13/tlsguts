// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tlsguts

import (
	"bytes"
	"crypto/tls"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"testing/quick"
	"time"
)

// TODO: move me to an standalone interface.
type handshakeMessage interface {
	Marshal() []byte
	Unmarshal([]byte) bool
}

// TLS 1.3 PSK Key Exchange Modes. See RFC 8446, Section 4.2.9.
const (
	pskModePlain uint8 = 0
	pskModeDHE   uint8 = 1
)

var supportedSignatureAlgorithms = []tls.SignatureScheme{
	tls.PSSWithSHA256,
	tls.ECDSAWithP256AndSHA256,
	tls.Ed25519,
	tls.PSSWithSHA384,
	tls.PSSWithSHA512,
	tls.PKCS1WithSHA256,
	tls.PKCS1WithSHA384,
	tls.PKCS1WithSHA512,
	tls.ECDSAWithP384AndSHA384,
	tls.ECDSAWithP521AndSHA512,
	tls.PKCS1WithSHA1,
	tls.ECDSAWithSHA1,
}

var tests = []interface{}{
	&ClientHello{},
	&ServerHello{},
	&Finished{},

	&Certificate{},
	&CertificateRequest{},
	&CertificateVerify{
		HasSignatureAlgorithm: true,
	},
	&CertificateStatus{},
	&ClientKeyExchange{},
	&NewSessionTicket{},
	&SessionState{},
	&SessionStateTLS13{},
	&EncryptedExtensions{},
	&EndOfEarlyData{},
	&KeyUpdate{},
	&NewSessionTicketTLS13{},
	&CertificateRequestTLS13{},
	&CertificateTLS13{},
}

func TestMarshalUnmarshal(t *testing.T) {
	rand := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i, iface := range tests {
		ty := reflect.ValueOf(iface).Type()

		n := 100
		if testing.Short() {
			n = 5
		}
		for j := 0; j < n; j++ {
			v, ok := quick.Value(ty, rand)
			if !ok {
				t.Errorf("#%d: failed to create value", i)
				break
			}

			m1 := v.Interface().(handshakeMessage)
			marshaled := m1.Marshal()
			m2 := iface.(handshakeMessage)
			if !m2.Unmarshal(marshaled) {
				t.Errorf("#%d failed to unmarshal %#v %x", i, m1, marshaled)
				break
			}
			m2.Marshal() // to fill any marshal cache in the message

			if !reflect.DeepEqual(m1, m2) {
				t.Errorf("#%d got:%#v want:%#v %x", i, m2, m1, marshaled)
				break
			}

			if i >= 3 {
				// The first three message types (ClientHello,
				// ServerHello and Finished) are allowed to
				// have parsable prefixes because the extension
				// data is optional and the length of the
				// Finished varies across versions.
				for j := 0; j < len(marshaled); j++ {
					if m2.Unmarshal(marshaled[0:j]) {
						t.Errorf("#%d unmarshaled a prefix of length %d of %#v", i, j, m1)
						break
					}
				}
			}
		}
	}
}

func TestFuzz(t *testing.T) {
	rand := rand.New(rand.NewSource(0))
	for _, iface := range tests {
		m := iface.(handshakeMessage)

		for j := 0; j < 1000; j++ {
			len := rand.Intn(100)
			bytes := randomBytes(len, rand)
			// This just looks for crashes due to bounds errors etc.
			m.Unmarshal(bytes)
		}
	}
}

func randomBytes(n int, rand *rand.Rand) []byte {
	r := make([]byte, n)
	if _, err := rand.Read(r); err != nil {
		panic("rand.Read failed: " + err.Error())
	}
	return r
}

func randomString(n int, rand *rand.Rand) string {
	b := randomBytes(n, rand)
	return string(b)
}

func (*ClientHello) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &ClientHello{}
	m.Version = uint16(rand.Intn(65536))
	m.Random = randomBytes(32, rand)
	m.SessionId = randomBytes(rand.Intn(32), rand)
	m.CipherSuites = make([]uint16, rand.Intn(63)+1)
	for i := 0; i < len(m.CipherSuites); i++ {
		cs := uint16(rand.Int31())
		if cs == scsvRenegotiation {
			cs += 1
		}
		m.CipherSuites[i] = cs
	}
	m.CompressionMethods = randomBytes(rand.Intn(63)+1, rand)
	if rand.Intn(10) > 5 {
		m.ServerName = randomString(rand.Intn(255), rand)
		for strings.HasSuffix(m.ServerName, ".") {
			m.ServerName = m.ServerName[:len(m.ServerName)-1]
		}
	}
	m.OCSPStapling = rand.Intn(10) > 5
	m.SupportedPoints = randomBytes(rand.Intn(5)+1, rand)
	m.SupportedCurves = make([]tls.CurveID, rand.Intn(5)+1)
	for i := range m.SupportedCurves {
		m.SupportedCurves[i] = tls.CurveID(rand.Intn(30000) + 1)
	}
	if rand.Intn(10) > 5 {
		m.TicketSupported = true
		if rand.Intn(10) > 5 {
			m.SessionTicket = randomBytes(rand.Intn(300), rand)
		} else {
			m.SessionTicket = make([]byte, 0)
		}
	}
	if rand.Intn(10) > 5 {
		m.SupportedSignatureAlgorithms = supportedSignatureAlgorithms
	}
	if rand.Intn(10) > 5 {
		m.SupportedSignatureAlgorithmsCert = supportedSignatureAlgorithms
	}
	for i := 0; i < rand.Intn(5); i++ {
		m.ALPNProtocols = append(m.ALPNProtocols, randomString(rand.Intn(20)+1, rand))
	}
	if rand.Intn(10) > 5 {
		m.SCTS = true
	}
	if rand.Intn(10) > 5 {
		m.SecureRenegotiationSupported = true
		m.SecureRenegotiation = randomBytes(rand.Intn(50)+1, rand)
	}
	for i := 0; i < rand.Intn(5); i++ {
		m.SupportedVersions = append(m.SupportedVersions, uint16(rand.Intn(0xffff)+1))
	}
	if rand.Intn(10) > 5 {
		m.Cookie = randomBytes(rand.Intn(500)+1, rand)
	}
	for i := 0; i < rand.Intn(5); i++ {
		var ks KeyShare
		ks.Group = tls.CurveID(rand.Intn(30000) + 1)
		ks.Data = randomBytes(rand.Intn(200)+1, rand)
		m.KeyShares = append(m.KeyShares, ks)
	}
	switch rand.Intn(3) {
	case 1:
		m.PSKModes = []uint8{pskModeDHE}
	case 2:
		m.PSKModes = []uint8{pskModeDHE, pskModePlain}
	}
	for i := 0; i < rand.Intn(5); i++ {
		var psk PSKIdentity
		psk.ObfuscatedTicketAge = uint32(rand.Intn(500000))
		psk.Label = randomBytes(rand.Intn(500)+1, rand)
		m.PSKIdentities = append(m.PSKIdentities, psk)
		m.PSKBinders = append(m.PSKBinders, randomBytes(rand.Intn(50)+32, rand))
	}
	if rand.Intn(10) > 5 {
		m.EarlyData = true
	}

	return reflect.ValueOf(m)
}

func (*ServerHello) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &ServerHello{}
	m.Version = uint16(rand.Intn(65536))
	m.Random = randomBytes(32, rand)
	m.SessionId = randomBytes(rand.Intn(32), rand)
	m.CipherSuite = uint16(rand.Int31())
	m.CompressionMethod = uint8(rand.Intn(256))
	m.SupportedPoints = randomBytes(rand.Intn(5)+1, rand)

	if rand.Intn(10) > 5 {
		m.OCSPStapling = true
	}
	if rand.Intn(10) > 5 {
		m.TicketSupported = true
	}
	if rand.Intn(10) > 5 {
		m.ALPNProtocol = randomString(rand.Intn(32)+1, rand)
	}

	for i := 0; i < rand.Intn(4); i++ {
		m.SCTS = append(m.SCTS, randomBytes(rand.Intn(500)+1, rand))
	}

	if rand.Intn(10) > 5 {
		m.SecureRenegotiationSupported = true
		m.SecureRenegotiation = randomBytes(rand.Intn(50)+1, rand)
	}
	if rand.Intn(10) > 5 {
		m.SupportedVersion = uint16(rand.Intn(0xffff) + 1)
	}
	if rand.Intn(10) > 5 {
		m.Cookie = randomBytes(rand.Intn(500)+1, rand)
	}
	if rand.Intn(10) > 5 {
		for i := 0; i < rand.Intn(5); i++ {
			m.ServerShare.Group = tls.CurveID(rand.Intn(30000) + 1)
			m.ServerShare.Data = randomBytes(rand.Intn(200)+1, rand)
		}
	} else if rand.Intn(10) > 5 {
		m.SelectedGroup = tls.CurveID(rand.Intn(30000) + 1)
	}
	if rand.Intn(10) > 5 {
		m.SelectedIdentityPresent = true
		m.SelectedIdentity = uint16(rand.Intn(0xffff))
	}

	return reflect.ValueOf(m)
}

func (*EncryptedExtensions) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &EncryptedExtensions{}

	if rand.Intn(10) > 5 {
		m.ALPNProtocol = randomString(rand.Intn(32)+1, rand)
	}

	return reflect.ValueOf(m)
}

func (*Certificate) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &Certificate{}
	numCerts := rand.Intn(20)
	m.Certificates = make([][]byte, numCerts)
	for i := 0; i < numCerts; i++ {
		m.Certificates[i] = randomBytes(rand.Intn(10)+1, rand)
	}
	return reflect.ValueOf(m)
}

func (*CertificateRequest) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &CertificateRequest{}
	m.CertificateTypes = randomBytes(rand.Intn(5)+1, rand)
	for i := 0; i < rand.Intn(100); i++ {
		m.CertificateAuthorities = append(m.CertificateAuthorities, randomBytes(rand.Intn(15)+1, rand))
	}
	return reflect.ValueOf(m)
}

func (*CertificateVerify) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &CertificateVerify{}
	m.HasSignatureAlgorithm = true
	m.SignatureAlgorithm = tls.SignatureScheme(rand.Intn(30000))
	m.Signature = randomBytes(rand.Intn(15)+1, rand)
	return reflect.ValueOf(m)
}

func (*CertificateStatus) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &CertificateStatus{}
	m.response = randomBytes(rand.Intn(10)+1, rand)
	return reflect.ValueOf(m)
}

func (*ClientKeyExchange) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &ClientKeyExchange{}
	m.CipherText = randomBytes(rand.Intn(1000)+1, rand)
	return reflect.ValueOf(m)
}

func (*Finished) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &Finished{}
	m.VerifyData = randomBytes(12, rand)
	return reflect.ValueOf(m)
}

func (*NewSessionTicket) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &NewSessionTicket{}
	m.Ticket = randomBytes(rand.Intn(4), rand)
	return reflect.ValueOf(m)
}

func (*SessionState) Generate(rand *rand.Rand, size int) reflect.Value {
	s := &SessionState{}
	s.Version = uint16(rand.Intn(10000))
	s.CipherSuite = uint16(rand.Intn(10000))
	s.MasterSecret = randomBytes(rand.Intn(100)+1, rand)
	s.CreatedAt = uint64(rand.Int63())
	for i := 0; i < rand.Intn(20); i++ {
		s.Certificates = append(s.Certificates, randomBytes(rand.Intn(500)+1, rand))
	}
	return reflect.ValueOf(s)
}

func (*SessionStateTLS13) Generate(rand *rand.Rand, size int) reflect.Value {
	s := &SessionStateTLS13{}
	s.CipherSuite = uint16(rand.Intn(10000))
	s.ResumptionSecret = randomBytes(rand.Intn(100)+1, rand)
	s.CreatedAt = uint64(rand.Int63())
	for i := 0; i < rand.Intn(2)+1; i++ {
		s.Certificate.Certificate = append(
			s.Certificate.Certificate, randomBytes(rand.Intn(500)+1, rand))
	}
	if rand.Intn(10) > 5 {
		s.Certificate.OCSPStaple = randomBytes(rand.Intn(100)+1, rand)
	}
	if rand.Intn(10) > 5 {
		for i := 0; i < rand.Intn(2)+1; i++ {
			s.Certificate.SignedCertificateTimestamps = append(
				s.Certificate.SignedCertificateTimestamps, randomBytes(rand.Intn(500)+1, rand))
		}
	}
	return reflect.ValueOf(s)
}

func (*EndOfEarlyData) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &EndOfEarlyData{}
	return reflect.ValueOf(m)
}

func (*KeyUpdate) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &KeyUpdate{}
	m.UpdateRequested = rand.Intn(10) > 5
	return reflect.ValueOf(m)
}

func (*NewSessionTicketTLS13) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &NewSessionTicketTLS13{}
	m.Lifetime = uint32(rand.Intn(500000))
	m.AgeAdd = uint32(rand.Intn(500000))
	m.Nonce = randomBytes(rand.Intn(100), rand)
	m.Label = randomBytes(rand.Intn(1000), rand)
	if rand.Intn(10) > 5 {
		m.MaxEarlyData = uint32(rand.Intn(500000))
	}
	return reflect.ValueOf(m)
}

func (*CertificateRequestTLS13) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &CertificateRequestTLS13{}
	if rand.Intn(10) > 5 {
		m.OCSPStapling = true
	}
	if rand.Intn(10) > 5 {
		m.SCTS = true
	}
	if rand.Intn(10) > 5 {
		m.SupportedSignatureAlgorithms = supportedSignatureAlgorithms
	}
	if rand.Intn(10) > 5 {
		m.SupportedSignatureAlgorithmsCert = supportedSignatureAlgorithms
	}
	if rand.Intn(10) > 5 {
		m.CertificateAuthorities = make([][]byte, 3)
		for i := 0; i < 3; i++ {
			m.CertificateAuthorities[i] = randomBytes(rand.Intn(10)+1, rand)
		}
	}
	return reflect.ValueOf(m)
}

func (*CertificateTLS13) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &CertificateTLS13{}
	for i := 0; i < rand.Intn(2)+1; i++ {
		m.Certificate.Certificate = append(
			m.Certificate.Certificate, randomBytes(rand.Intn(500)+1, rand))
	}
	if rand.Intn(10) > 5 {
		m.OSCPStapling = true
		m.Certificate.OCSPStaple = randomBytes(rand.Intn(100)+1, rand)
	}
	if rand.Intn(10) > 5 {
		m.SCTS = true
		for i := 0; i < rand.Intn(2)+1; i++ {
			m.Certificate.SignedCertificateTimestamps = append(
				m.Certificate.SignedCertificateTimestamps, randomBytes(rand.Intn(500)+1, rand))
		}
	}
	return reflect.ValueOf(m)
}

func TestRejectEmptySCTList(t *testing.T) {
	// RFC 6962, Section 3.3.1 specifies that empty SCT lists are invalid.

	var random [32]byte
	sct := []byte{0x42, 0x42, 0x42, 0x42}
	serverHello := ServerHello{
		Version: tls.VersionTLS12,
		Random:  random[:],
		SCTS:    [][]byte{sct},
	}
	serverHelloBytes := serverHello.Marshal()

	var serverHelloCopy ServerHello
	if !serverHelloCopy.Unmarshal(serverHelloBytes) {
		t.Fatal("Failed to unmarshal initial message")
	}

	// Change serverHelloBytes so that the SCT list is empty
	i := bytes.Index(serverHelloBytes, sct)
	if i < 0 {
		t.Fatal("Cannot find SCT in ServerHello")
	}

	var serverHelloEmptySCT []byte
	serverHelloEmptySCT = append(serverHelloEmptySCT, serverHelloBytes[:i-6]...)
	// Append the extension length and SCT list length for an empty list.
	serverHelloEmptySCT = append(serverHelloEmptySCT, []byte{0, 2, 0, 0}...)
	serverHelloEmptySCT = append(serverHelloEmptySCT, serverHelloBytes[i+4:]...)

	// Update the handshake message length.
	serverHelloEmptySCT[1] = byte((len(serverHelloEmptySCT) - 4) >> 16)
	serverHelloEmptySCT[2] = byte((len(serverHelloEmptySCT) - 4) >> 8)
	serverHelloEmptySCT[3] = byte(len(serverHelloEmptySCT) - 4)

	// Update the extensions length
	serverHelloEmptySCT[42] = byte((len(serverHelloEmptySCT) - 44) >> 8)
	serverHelloEmptySCT[43] = byte((len(serverHelloEmptySCT) - 44))

	if serverHelloCopy.Unmarshal(serverHelloEmptySCT) {
		t.Fatal("Unmarshaled ServerHello with empty SCT list")
	}
}

func TestRejectEmptySCT(t *testing.T) {
	// Not only must the SCT list be non-empty, but the SCT elements must
	// not be zero length.

	var random [32]byte
	serverHello := ServerHello{
		Version: tls.VersionTLS12,
		Random:  random[:],
		SCTS:    [][]byte{nil},
	}
	serverHelloBytes := serverHello.Marshal()

	var serverHelloCopy ServerHello
	if serverHelloCopy.Unmarshal(serverHelloBytes) {
		t.Fatal("Unmarshaled ServerHello with zero-length SCT")
	}
}
