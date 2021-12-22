package tlsguts

import (
	"crypto/tls"
	"fmt"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

const (
	statusTypeOCSP uint8 = 1
)

// TLS signaling cipher suite values
const (
	scsvRenegotiation uint16 = 0x00ff
)

// TLS handshake message types.
const (
	typeHelloRequest        uint8 = 0
	typeClientHello         uint8 = 1
	typeServerHello         uint8 = 2
	typeNewSessionTicket    uint8 = 4
	typeEndOfEarlyData      uint8 = 5
	typeEncryptedExtensions uint8 = 8
	typeCertificate         uint8 = 11
	typeServerKeyExchange   uint8 = 12
	typeCertificateRequest  uint8 = 13
	typeServerHelloDone     uint8 = 14
	typeCertificateVerify   uint8 = 15
	typeClientKeyExchange   uint8 = 16
	typeFinished            uint8 = 20
	typeCertificateStatus   uint8 = 22
	typeKeyUpdate           uint8 = 24
	typeNextProtocol        uint8 = 67  // Not IANA assigned
	typeMessageHash         uint8 = 254 // synthetic message
)

// TLS extension numbers
const (
	extensionServerName              uint16 = 0
	extensionStatusRequest           uint16 = 5
	extensionSupportedCurves         uint16 = 10 // supported_groups in TLS 1.3, see RFC 8446, Section 4.2.7
	extensionSupportedPoints         uint16 = 11
	extensionSignatureAlgorithms     uint16 = 13
	extensionALPN                    uint16 = 16
	extensionSCT                     uint16 = 18
	extensionSessionTicket           uint16 = 35
	extensionPreSharedKey            uint16 = 41
	extensionEarlyData               uint16 = 42
	extensionSupportedVersions       uint16 = 43
	extensionCookie                  uint16 = 44
	extensionPSKModes                uint16 = 45
	extensionCertificateAuthorities  uint16 = 47
	extensionSignatureAlgorithmsCert uint16 = 50
	extensionKeyShare                uint16 = 51
	extensionRenegotiationInfo       uint16 = 0xff01
)

// The marshalingFunction type is an adapter to allow the use of ordinary
// functions as cryptobyte.MarshalingValue.
type marshalingFunction func(b *cryptobyte.Builder) error

func (f marshalingFunction) Marshal(b *cryptobyte.Builder) error {
	return f(b)
}

// addBytesWithLength appends a sequence of bytes to the cryptobyte.Builder. If
// the length of the sequence is not the value specified, it produces an error.
func addBytesWithLength(b *cryptobyte.Builder, v []byte, n int) {
	b.AddValue(marshalingFunction(func(b *cryptobyte.Builder) error {
		if len(v) != n {
			return fmt.Errorf("invalid value length: expected %d, got %d", n, len(v))
		}
		b.AddBytes(v)
		return nil
	}))
}

// addUint64 appends a big-endian, 64-bit value to the cryptobyte.Builder.
func addUint64(b *cryptobyte.Builder, v uint64) {
	b.AddUint32(uint32(v >> 32))
	b.AddUint32(uint32(v))
}

// readUint64 decodes a big-endian, 64-bit value into out and advances over it.
// It reports whether the read was successful.
func readUint64(s *cryptobyte.String, out *uint64) bool {
	var hi, lo uint32
	if !s.ReadUint32(&hi) || !s.ReadUint32(&lo) {
		return false
	}
	*out = uint64(hi)<<32 | uint64(lo)
	return true
}

// readUint8LengthPrefixed acts like s.ReadUint8LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint8LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint8LengthPrefixed((*cryptobyte.String)(out))
}

// readUint16LengthPrefixed acts like s.ReadUint16LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint16LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint16LengthPrefixed((*cryptobyte.String)(out))
}

// readUint24LengthPrefixed acts like s.ReadUint24LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint24LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint24LengthPrefixed((*cryptobyte.String)(out))
}

type ClientHello struct {
	Raw                              []byte
	Version                          uint16
	Random                           []byte
	SessionId                        []byte
	CipherSuites                     []uint16
	CompressionMethods               []uint8
	ServerName                       string
	OCSPStapling                     bool
	SupportedCurves                  []tls.CurveID
	SupportedPoints                  []uint8
	TicketSupported                  bool
	SessionTicket                    []uint8
	SupportedSignatureAlgorithms     []tls.SignatureScheme
	SupportedSignatureAlgorithmsCert []tls.SignatureScheme
	SecureRenegotiationSupported     bool
	SecureRenegotiation              []byte
	ALPNProtocols                    []string
	SCTS                             bool
	SupportedVersions                []uint16
	Cookie                           []byte
	KeyShares                        []keyShare
	EarlyData                        bool
	PSKModes                         []uint8
	PSKIdentities                    []pskIdentity
	PSKBinders                       [][]byte
}

func (m *ClientHello) Marshal() []byte {
	if m.Raw != nil {
		return m.Raw
	}

	var b cryptobyte.Builder
	b.AddUint8(typeClientHello)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(m.Version)
		addBytesWithLength(b, m.Random, 32)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.SessionId)
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, suite := range m.CipherSuites {
				b.AddUint16(suite)
			}
		})
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.CompressionMethods)
		})

		// If extensions aren't present, omit them.
		var extensionsPresent bool
		bWithoutExtensions := *b

		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			if len(m.ServerName) > 0 {
				// RFC 6066, Section 3
				b.AddUint16(extensionServerName)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint8(0) // name_type = host_name
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddBytes([]byte(m.ServerName))
						})
					})
				})
			}
			if m.OCSPStapling {
				// RFC 4366, Section 3.6
				b.AddUint16(extensionStatusRequest)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint8(1)  // status_type = ocsp
					b.AddUint16(0) // empty responder_id_list
					b.AddUint16(0) // empty request_extensions
				})
			}
			if len(m.SupportedCurves) > 0 {
				// RFC 4492, sections 5.1.1 and RFC 8446, Section 4.2.7
				b.AddUint16(extensionSupportedCurves)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						for _, curve := range m.SupportedCurves {
							b.AddUint16(uint16(curve))
						}
					})
				})
			}
			if len(m.SupportedPoints) > 0 {
				// RFC 4492, Section 5.1.2
				b.AddUint16(extensionSupportedPoints)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes(m.SupportedPoints)
					})
				})
			}
			if m.TicketSupported {
				// RFC 5077, Section 3.2
				b.AddUint16(extensionSessionTicket)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(m.SessionTicket)
				})
			}
			if len(m.SupportedSignatureAlgorithms) > 0 {
				// RFC 5246, Section 7.4.1.4.1
				b.AddUint16(extensionSignatureAlgorithms)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						for _, sigAlgo := range m.SupportedSignatureAlgorithms {
							b.AddUint16(uint16(sigAlgo))
						}
					})
				})
			}
			if len(m.SupportedSignatureAlgorithmsCert) > 0 {
				// RFC 8446, Section 4.2.3
				b.AddUint16(extensionSignatureAlgorithmsCert)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						for _, sigAlgo := range m.SupportedSignatureAlgorithmsCert {
							b.AddUint16(uint16(sigAlgo))
						}
					})
				})
			}
			if m.SecureRenegotiationSupported {
				// RFC 5746, Section 3.2
				b.AddUint16(extensionRenegotiationInfo)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes(m.SecureRenegotiation)
					})
				})
			}
			if len(m.ALPNProtocols) > 0 {
				// RFC 7301, Section 3.1
				b.AddUint16(extensionALPN)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						for _, proto := range m.ALPNProtocols {
							b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
								b.AddBytes([]byte(proto))
							})
						}
					})
				})
			}
			if m.SCTS {
				// RFC 6962, Section 3.3.1
				b.AddUint16(extensionSCT)
				b.AddUint16(0) // empty extension_data
			}
			if len(m.SupportedVersions) > 0 {
				// RFC 8446, Section 4.2.1
				b.AddUint16(extensionSupportedVersions)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
						for _, vers := range m.SupportedVersions {
							b.AddUint16(vers)
						}
					})
				})
			}
			if len(m.Cookie) > 0 {
				// RFC 8446, Section 4.2.2
				b.AddUint16(extensionCookie)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes(m.Cookie)
					})
				})
			}
			if len(m.KeyShares) > 0 {
				// RFC 8446, Section 4.2.8
				b.AddUint16(extensionKeyShare)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						for _, ks := range m.KeyShares {
							b.AddUint16(uint16(ks.group))
							b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
								b.AddBytes(ks.data)
							})
						}
					})
				})
			}
			if m.EarlyData {
				// RFC 8446, Section 4.2.10
				b.AddUint16(extensionEarlyData)
				b.AddUint16(0) // empty extension_data
			}
			if len(m.PSKModes) > 0 {
				// RFC 8446, Section 4.2.9
				b.AddUint16(extensionPSKModes)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes(m.PSKModes)
					})
				})
			}
			if len(m.PSKIdentities) > 0 { // pre_shared_key must be the last extension
				// RFC 8446, Section 4.2.11
				b.AddUint16(extensionPreSharedKey)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						for _, psk := range m.PSKIdentities {
							b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
								b.AddBytes(psk.label)
							})
							b.AddUint32(psk.obfuscatedTicketAge)
						}
					})
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						for _, binder := range m.PSKBinders {
							b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
								b.AddBytes(binder)
							})
						}
					})
				})
			}

			extensionsPresent = len(b.BytesOrPanic()) > 2
		})

		if !extensionsPresent {
			*b = bWithoutExtensions
		}
	})

	m.Raw = b.BytesOrPanic()
	return m.Raw
}

// marshalWithoutBinders returns the ClientHello through the
// PreSharedKeyExtension.identities field, according to RFC 8446, Section
// 4.2.11.2. Note that m.pskBinders must be set to slices of the correct length.
func (m *ClientHello) marshalWithoutBinders() []byte {
	bindersLen := 2 // uint16 length prefix
	for _, binder := range m.PSKBinders {
		bindersLen += 1 // uint8 length prefix
		bindersLen += len(binder)
	}

	fullMessage := m.Marshal()
	return fullMessage[:len(fullMessage)-bindersLen]
}

// updateBinders updates the m.pskBinders field, if necessary updating the
// cached marshaled representation. The supplied binders must have the same
// length as the current m.pskBinders.
func (m *ClientHello) updateBinders(pskBinders [][]byte) {
	if len(pskBinders) != len(m.PSKBinders) {
		panic("tls: internal error: pskBinders length mismatch")
	}
	for i := range m.PSKBinders {
		if len(pskBinders[i]) != len(m.PSKBinders[i]) {
			panic("tls: internal error: pskBinders length mismatch")
		}
	}
	m.PSKBinders = pskBinders
	if m.Raw != nil {
		lenWithoutBinders := len(m.marshalWithoutBinders())
		b := cryptobyte.NewFixedBuilder(m.Raw[:lenWithoutBinders])
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, binder := range m.PSKBinders {
				b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(binder)
				})
			}
		})
		if out, err := b.Bytes(); err != nil || len(out) != len(m.Raw) {
			panic("tls: internal error: failed to update binders")
		}
	}
}

func (m *ClientHello) Unmarshal(data []byte) bool {
	*m = ClientHello{Raw: data}
	s := cryptobyte.String(data)

	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&m.Version) || !s.ReadBytes(&m.Random, 32) ||
		!readUint8LengthPrefixed(&s, &m.SessionId) {
		return false
	}

	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return false
	}
	m.CipherSuites = []uint16{}
	m.SecureRenegotiationSupported = false
	for !cipherSuites.Empty() {
		var suite uint16
		if !cipherSuites.ReadUint16(&suite) {
			return false
		}
		if suite == scsvRenegotiation {
			m.SecureRenegotiationSupported = true
		}
		m.CipherSuites = append(m.CipherSuites, suite)
	}

	if !readUint8LengthPrefixed(&s, &m.CompressionMethods) {
		return false
	}

	if s.Empty() {
		// ClientHello is optionally followed by extension data
		return true
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}

	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		switch extension {
		case extensionServerName:
			// RFC 6066, Section 3
			var nameList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&nameList) || nameList.Empty() {
				return false
			}
			for !nameList.Empty() {
				var nameType uint8
				var serverName cryptobyte.String
				if !nameList.ReadUint8(&nameType) ||
					!nameList.ReadUint16LengthPrefixed(&serverName) ||
					serverName.Empty() {
					return false
				}
				if nameType != 0 {
					continue
				}
				if len(m.ServerName) != 0 {
					// Multiple names of the same name_type are prohibited.
					return false
				}
				m.ServerName = string(serverName)
				// An SNI value may not include a trailing dot.
				if strings.HasSuffix(m.ServerName, ".") {
					return false
				}
			}
		case extensionStatusRequest:
			// RFC 4366, Section 3.6
			var statusType uint8
			var ignored cryptobyte.String
			if !extData.ReadUint8(&statusType) ||
				!extData.ReadUint16LengthPrefixed(&ignored) ||
				!extData.ReadUint16LengthPrefixed(&ignored) {
				return false
			}
			m.OCSPStapling = statusType == statusTypeOCSP
		case extensionSupportedCurves:
			// RFC 4492, sections 5.1.1 and RFC 8446, Section 4.2.7
			var curves cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&curves) || curves.Empty() {
				return false
			}
			for !curves.Empty() {
				var curve uint16
				if !curves.ReadUint16(&curve) {
					return false
				}
				m.SupportedCurves = append(m.SupportedCurves, tls.CurveID(curve))
			}
		case extensionSupportedPoints:
			// RFC 4492, Section 5.1.2
			if !readUint8LengthPrefixed(&extData, &m.SupportedPoints) ||
				len(m.SupportedPoints) == 0 {
				return false
			}
		case extensionSessionTicket:
			// RFC 5077, Section 3.2
			m.TicketSupported = true
			extData.ReadBytes(&m.SessionTicket, len(extData))
		case extensionSignatureAlgorithms:
			// RFC 5246, Section 7.4.1.4.1
			var sigAndAlgs cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
				return false
			}
			for !sigAndAlgs.Empty() {
				var sigAndAlg uint16
				if !sigAndAlgs.ReadUint16(&sigAndAlg) {
					return false
				}
				m.SupportedSignatureAlgorithms = append(
					m.SupportedSignatureAlgorithms, tls.SignatureScheme(sigAndAlg))
			}
		case extensionSignatureAlgorithmsCert:
			// RFC 8446, Section 4.2.3
			var sigAndAlgs cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
				return false
			}
			for !sigAndAlgs.Empty() {
				var sigAndAlg uint16
				if !sigAndAlgs.ReadUint16(&sigAndAlg) {
					return false
				}
				m.SupportedSignatureAlgorithmsCert = append(
					m.SupportedSignatureAlgorithmsCert, tls.SignatureScheme(sigAndAlg))
			}
		case extensionRenegotiationInfo:
			// RFC 5746, Section 3.2
			if !readUint8LengthPrefixed(&extData, &m.SecureRenegotiation) {
				return false
			}
			m.SecureRenegotiationSupported = true
		case extensionALPN:
			// RFC 7301, Section 3.1
			var protoList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
				return false
			}
			for !protoList.Empty() {
				var proto cryptobyte.String
				if !protoList.ReadUint8LengthPrefixed(&proto) || proto.Empty() {
					return false
				}
				m.ALPNProtocols = append(m.ALPNProtocols, string(proto))
			}
		case extensionSCT:
			// RFC 6962, Section 3.3.1
			m.SCTS = true
		case extensionSupportedVersions:
			// RFC 8446, Section 4.2.1
			var versList cryptobyte.String
			if !extData.ReadUint8LengthPrefixed(&versList) || versList.Empty() {
				return false
			}
			for !versList.Empty() {
				var vers uint16
				if !versList.ReadUint16(&vers) {
					return false
				}
				m.SupportedVersions = append(m.SupportedVersions, vers)
			}
		case extensionCookie:
			// RFC 8446, Section 4.2.2
			if !readUint16LengthPrefixed(&extData, &m.Cookie) ||
				len(m.Cookie) == 0 {
				return false
			}
		case extensionKeyShare:
			// RFC 8446, Section 4.2.8
			var clientShares cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&clientShares) {
				return false
			}
			for !clientShares.Empty() {
				var ks keyShare
				if !clientShares.ReadUint16((*uint16)(&ks.group)) ||
					!readUint16LengthPrefixed(&clientShares, &ks.data) ||
					len(ks.data) == 0 {
					return false
				}
				m.KeyShares = append(m.KeyShares, ks)
			}
		case extensionEarlyData:
			// RFC 8446, Section 4.2.10
			m.EarlyData = true
		case extensionPSKModes:
			// RFC 8446, Section 4.2.9
			if !readUint8LengthPrefixed(&extData, &m.PSKModes) {
				return false
			}
		case extensionPreSharedKey:
			// RFC 8446, Section 4.2.11
			if !extensions.Empty() {
				return false // pre_shared_key must be the last extension
			}
			var identities cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&identities) || identities.Empty() {
				return false
			}
			for !identities.Empty() {
				var psk pskIdentity
				if !readUint16LengthPrefixed(&identities, &psk.label) ||
					!identities.ReadUint32(&psk.obfuscatedTicketAge) ||
					len(psk.label) == 0 {
					return false
				}
				m.PSKIdentities = append(m.PSKIdentities, psk)
			}
			var binders cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&binders) || binders.Empty() {
				return false
			}
			for !binders.Empty() {
				var binder []byte
				if !readUint8LengthPrefixed(&binders, &binder) ||
					len(binder) == 0 {
					return false
				}
				m.PSKBinders = append(m.PSKBinders, binder)
			}
		default:
			// Ignore unknown extensions.
			continue
		}

		if !extData.Empty() {
			return false
		}
	}

	return true
}

type ServerHello struct {
	Raw                          []byte
	Version                      uint16
	Random                       []byte
	SessionId                    []byte
	CipherSuite                  uint16
	CompressionMethod            uint8
	OCSPStapling                 bool
	TicketSupported              bool
	SecureRenegotiationSupported bool
	SecureRenegotiation          []byte
	ALPNProtocol                 string
	SCTS                         [][]byte
	SupportedVersion             uint16
	ServerShare                  keyShare
	SelectedIdentityPresent      bool
	SelectedIdentity             uint16
	SupportedPoints              []uint8

	// HelloRetryRequest extensions
	Cookie        []byte
	SelectedGroup tls.CurveID
}

func (m *ServerHello) Marshal() []byte {
	if m.Raw != nil {
		return m.Raw
	}

	var b cryptobyte.Builder
	b.AddUint8(typeServerHello)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(m.Version)
		addBytesWithLength(b, m.Random, 32)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.SessionId)
		})
		b.AddUint16(m.CipherSuite)
		b.AddUint8(m.CompressionMethod)

		// If extensions aren't present, omit them.
		var extensionsPresent bool
		bWithoutExtensions := *b

		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			if m.OCSPStapling {
				b.AddUint16(extensionStatusRequest)
				b.AddUint16(0) // empty extension_data
			}
			if m.TicketSupported {
				b.AddUint16(extensionSessionTicket)
				b.AddUint16(0) // empty extension_data
			}
			if m.SecureRenegotiationSupported {
				b.AddUint16(extensionRenegotiationInfo)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes(m.SecureRenegotiation)
					})
				})
			}
			if len(m.ALPNProtocol) > 0 {
				b.AddUint16(extensionALPN)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddBytes([]byte(m.ALPNProtocol))
						})
					})
				})
			}
			if len(m.SCTS) > 0 {
				b.AddUint16(extensionSCT)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						for _, sct := range m.SCTS {
							b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
								b.AddBytes(sct)
							})
						}
					})
				})
			}
			if m.SupportedVersion != 0 {
				b.AddUint16(extensionSupportedVersions)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16(m.SupportedVersion)
				})
			}
			if m.ServerShare.group != 0 {
				b.AddUint16(extensionKeyShare)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16(uint16(m.ServerShare.group))
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes(m.ServerShare.data)
					})
				})
			}
			if m.SelectedIdentityPresent {
				b.AddUint16(extensionPreSharedKey)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16(m.SelectedIdentity)
				})
			}

			if len(m.Cookie) > 0 {
				b.AddUint16(extensionCookie)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes(m.Cookie)
					})
				})
			}
			if m.SelectedGroup != 0 {
				b.AddUint16(extensionKeyShare)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16(uint16(m.SelectedGroup))
				})
			}
			if len(m.SupportedPoints) > 0 {
				b.AddUint16(extensionSupportedPoints)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes(m.SupportedPoints)
					})
				})
			}

			extensionsPresent = len(b.BytesOrPanic()) > 2
		})

		if !extensionsPresent {
			*b = bWithoutExtensions
		}
	})

	m.Raw = b.BytesOrPanic()
	return m.Raw
}

func (m *ServerHello) Unmarshal(data []byte) bool {
	*m = ServerHello{Raw: data}
	s := cryptobyte.String(data)

	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&m.Version) || !s.ReadBytes(&m.Random, 32) ||
		!readUint8LengthPrefixed(&s, &m.SessionId) ||
		!s.ReadUint16(&m.CipherSuite) ||
		!s.ReadUint8(&m.CompressionMethod) {
		return false
	}

	if s.Empty() {
		// ServerHello is optionally followed by extension data
		return true
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}

	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		switch extension {
		case extensionStatusRequest:
			m.OCSPStapling = true
		case extensionSessionTicket:
			m.TicketSupported = true
		case extensionRenegotiationInfo:
			if !readUint8LengthPrefixed(&extData, &m.SecureRenegotiation) {
				return false
			}
			m.SecureRenegotiationSupported = true
		case extensionALPN:
			var protoList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
				return false
			}
			var proto cryptobyte.String
			if !protoList.ReadUint8LengthPrefixed(&proto) ||
				proto.Empty() || !protoList.Empty() {
				return false
			}
			m.ALPNProtocol = string(proto)
		case extensionSCT:
			var sctList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sctList) || sctList.Empty() {
				return false
			}
			for !sctList.Empty() {
				var sct []byte
				if !readUint16LengthPrefixed(&sctList, &sct) ||
					len(sct) == 0 {
					return false
				}
				m.SCTS = append(m.SCTS, sct)
			}
		case extensionSupportedVersions:
			if !extData.ReadUint16(&m.SupportedVersion) {
				return false
			}
		case extensionCookie:
			if !readUint16LengthPrefixed(&extData, &m.Cookie) ||
				len(m.Cookie) == 0 {
				return false
			}
		case extensionKeyShare:
			// This extension has different formats in SH and HRR, accept either
			// and let the handshake logic decide. See RFC 8446, Section 4.2.8.
			if len(extData) == 2 {
				if !extData.ReadUint16((*uint16)(&m.SelectedGroup)) {
					return false
				}
			} else {
				if !extData.ReadUint16((*uint16)(&m.ServerShare.group)) ||
					!readUint16LengthPrefixed(&extData, &m.ServerShare.data) {
					return false
				}
			}
		case extensionPreSharedKey:
			m.SelectedIdentityPresent = true
			if !extData.ReadUint16(&m.SelectedIdentity) {
				return false
			}
		case extensionSupportedPoints:
			// RFC 4492, Section 5.1.2
			if !readUint8LengthPrefixed(&extData, &m.SupportedPoints) ||
				len(m.SupportedPoints) == 0 {
				return false
			}
		default:
			// Ignore unknown extensions.
			continue
		}

		if !extData.Empty() {
			return false
		}
	}

	return true
}

type encryptedExtensionsMsg struct {
	raw          []byte
	alpnProtocol string
}

func (m *encryptedExtensionsMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	var b cryptobyte.Builder
	b.AddUint8(typeEncryptedExtensions)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			if len(m.alpnProtocol) > 0 {
				b.AddUint16(extensionALPN)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddBytes([]byte(m.alpnProtocol))
						})
					})
				})
			}
		})
	})

	m.raw = b.BytesOrPanic()
	return m.raw
}

func (m *encryptedExtensionsMsg) unmarshal(data []byte) bool {
	*m = encryptedExtensionsMsg{raw: data}
	s := cryptobyte.String(data)

	var extensions cryptobyte.String
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}

	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		switch extension {
		case extensionALPN:
			var protoList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
				return false
			}
			var proto cryptobyte.String
			if !protoList.ReadUint8LengthPrefixed(&proto) ||
				proto.Empty() || !protoList.Empty() {
				return false
			}
			m.alpnProtocol = string(proto)
		default:
			// Ignore unknown extensions.
			continue
		}

		if !extData.Empty() {
			return false
		}
	}

	return true
}

type endOfEarlyDataMsg struct{}

func (m *endOfEarlyDataMsg) marshal() []byte {
	x := make([]byte, 4)
	x[0] = typeEndOfEarlyData
	return x
}

func (m *endOfEarlyDataMsg) unmarshal(data []byte) bool {
	return len(data) == 4
}

type keyUpdateMsg struct {
	raw             []byte
	updateRequested bool
}

func (m *keyUpdateMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	var b cryptobyte.Builder
	b.AddUint8(typeKeyUpdate)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		if m.updateRequested {
			b.AddUint8(1)
		} else {
			b.AddUint8(0)
		}
	})

	m.raw = b.BytesOrPanic()
	return m.raw
}

func (m *keyUpdateMsg) unmarshal(data []byte) bool {
	m.raw = data
	s := cryptobyte.String(data)

	var updateRequested uint8
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint8(&updateRequested) || !s.Empty() {
		return false
	}
	switch updateRequested {
	case 0:
		m.updateRequested = false
	case 1:
		m.updateRequested = true
	default:
		return false
	}
	return true
}

type newSessionTicketMsgTLS13 struct {
	raw          []byte
	lifetime     uint32
	ageAdd       uint32
	nonce        []byte
	label        []byte
	maxEarlyData uint32
}

func (m *newSessionTicketMsgTLS13) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	var b cryptobyte.Builder
	b.AddUint8(typeNewSessionTicket)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint32(m.lifetime)
		b.AddUint32(m.ageAdd)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.nonce)
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.label)
		})

		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			if m.maxEarlyData > 0 {
				b.AddUint16(extensionEarlyData)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint32(m.maxEarlyData)
				})
			}
		})
	})

	m.raw = b.BytesOrPanic()
	return m.raw
}

func (m *newSessionTicketMsgTLS13) unmarshal(data []byte) bool {
	*m = newSessionTicketMsgTLS13{raw: data}
	s := cryptobyte.String(data)

	var extensions cryptobyte.String
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint32(&m.lifetime) ||
		!s.ReadUint32(&m.ageAdd) ||
		!readUint8LengthPrefixed(&s, &m.nonce) ||
		!readUint16LengthPrefixed(&s, &m.label) ||
		!s.ReadUint16LengthPrefixed(&extensions) ||
		!s.Empty() {
		return false
	}

	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		switch extension {
		case extensionEarlyData:
			if !extData.ReadUint32(&m.maxEarlyData) {
				return false
			}
		default:
			// Ignore unknown extensions.
			continue
		}

		if !extData.Empty() {
			return false
		}
	}

	return true
}

type certificateRequestMsgTLS13 struct {
	raw                              []byte
	ocspStapling                     bool
	scts                             bool
	supportedSignatureAlgorithms     []tls.SignatureScheme
	supportedSignatureAlgorithmsCert []tls.SignatureScheme
	certificateAuthorities           [][]byte
}

func (m *certificateRequestMsgTLS13) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	var b cryptobyte.Builder
	b.AddUint8(typeCertificateRequest)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		// certificate_request_context (SHALL be zero length unless used for
		// post-handshake authentication)
		b.AddUint8(0)

		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			if m.ocspStapling {
				b.AddUint16(extensionStatusRequest)
				b.AddUint16(0) // empty extension_data
			}
			if m.scts {
				// RFC 8446, Section 4.4.2.1 makes no mention of
				// signed_certificate_timestamp in CertificateRequest, but
				// "Extensions in the Certificate message from the client MUST
				// correspond to extensions in the CertificateRequest message
				// from the server." and it appears in the table in Section 4.2.
				b.AddUint16(extensionSCT)
				b.AddUint16(0) // empty extension_data
			}
			if len(m.supportedSignatureAlgorithms) > 0 {
				b.AddUint16(extensionSignatureAlgorithms)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						for _, sigAlgo := range m.supportedSignatureAlgorithms {
							b.AddUint16(uint16(sigAlgo))
						}
					})
				})
			}
			if len(m.supportedSignatureAlgorithmsCert) > 0 {
				b.AddUint16(extensionSignatureAlgorithmsCert)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						for _, sigAlgo := range m.supportedSignatureAlgorithmsCert {
							b.AddUint16(uint16(sigAlgo))
						}
					})
				})
			}
			if len(m.certificateAuthorities) > 0 {
				b.AddUint16(extensionCertificateAuthorities)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						for _, ca := range m.certificateAuthorities {
							b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
								b.AddBytes(ca)
							})
						}
					})
				})
			}
		})
	})

	m.raw = b.BytesOrPanic()
	return m.raw
}

func (m *certificateRequestMsgTLS13) unmarshal(data []byte) bool {
	*m = certificateRequestMsgTLS13{raw: data}
	s := cryptobyte.String(data)

	var context, extensions cryptobyte.String
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint8LengthPrefixed(&context) || !context.Empty() ||
		!s.ReadUint16LengthPrefixed(&extensions) ||
		!s.Empty() {
		return false
	}

	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		switch extension {
		case extensionStatusRequest:
			m.ocspStapling = true
		case extensionSCT:
			m.scts = true
		case extensionSignatureAlgorithms:
			var sigAndAlgs cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
				return false
			}
			for !sigAndAlgs.Empty() {
				var sigAndAlg uint16
				if !sigAndAlgs.ReadUint16(&sigAndAlg) {
					return false
				}
				m.supportedSignatureAlgorithms = append(
					m.supportedSignatureAlgorithms, tls.SignatureScheme(sigAndAlg))
			}
		case extensionSignatureAlgorithmsCert:
			var sigAndAlgs cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
				return false
			}
			for !sigAndAlgs.Empty() {
				var sigAndAlg uint16
				if !sigAndAlgs.ReadUint16(&sigAndAlg) {
					return false
				}
				m.supportedSignatureAlgorithmsCert = append(
					m.supportedSignatureAlgorithmsCert, tls.SignatureScheme(sigAndAlg))
			}
		case extensionCertificateAuthorities:
			var auths cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&auths) || auths.Empty() {
				return false
			}
			for !auths.Empty() {
				var ca []byte
				if !readUint16LengthPrefixed(&auths, &ca) || len(ca) == 0 {
					return false
				}
				m.certificateAuthorities = append(m.certificateAuthorities, ca)
			}
		default:
			// Ignore unknown extensions.
			continue
		}

		if !extData.Empty() {
			return false
		}
	}

	return true
}

type certificateMsg struct {
	raw          []byte
	certificates [][]byte
}

func (m *certificateMsg) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	var i int
	for _, slice := range m.certificates {
		i += len(slice)
	}

	length := 3 + 3*len(m.certificates) + i
	x = make([]byte, 4+length)
	x[0] = typeCertificate
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)

	certificateOctets := length - 3
	x[4] = uint8(certificateOctets >> 16)
	x[5] = uint8(certificateOctets >> 8)
	x[6] = uint8(certificateOctets)

	y := x[7:]
	for _, slice := range m.certificates {
		y[0] = uint8(len(slice) >> 16)
		y[1] = uint8(len(slice) >> 8)
		y[2] = uint8(len(slice))
		copy(y[3:], slice)
		y = y[3+len(slice):]
	}

	m.raw = x
	return
}

func (m *certificateMsg) unmarshal(data []byte) bool {
	if len(data) < 7 {
		return false
	}

	m.raw = data
	certsLen := uint32(data[4])<<16 | uint32(data[5])<<8 | uint32(data[6])
	if uint32(len(data)) != certsLen+7 {
		return false
	}

	numCerts := 0
	d := data[7:]
	for certsLen > 0 {
		if len(d) < 4 {
			return false
		}
		certLen := uint32(d[0])<<16 | uint32(d[1])<<8 | uint32(d[2])
		if uint32(len(d)) < 3+certLen {
			return false
		}
		d = d[3+certLen:]
		certsLen -= 3 + certLen
		numCerts++
	}

	m.certificates = make([][]byte, numCerts)
	d = data[7:]
	for i := 0; i < numCerts; i++ {
		certLen := uint32(d[0])<<16 | uint32(d[1])<<8 | uint32(d[2])
		m.certificates[i] = d[3 : 3+certLen]
		d = d[3+certLen:]
	}

	return true
}

type certificateMsgTLS13 struct {
	raw          []byte
	certificate  tls.Certificate
	ocspStapling bool
	scts         bool
}

func (m *certificateMsgTLS13) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	var b cryptobyte.Builder
	b.AddUint8(typeCertificate)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(0) // certificate_request_context

		certificate := m.certificate
		if !m.ocspStapling {
			certificate.OCSPStaple = nil
		}
		if !m.scts {
			certificate.SignedCertificateTimestamps = nil
		}
		marshalCertificate(b, certificate)
	})

	m.raw = b.BytesOrPanic()
	return m.raw
}

func marshalCertificate(b *cryptobyte.Builder, certificate tls.Certificate) {
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		for i, cert := range certificate.Certificate {
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(cert)
			})
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				if i > 0 {
					// This library only supports OCSP and SCT for leaf certificates.
					return
				}
				if certificate.OCSPStaple != nil {
					b.AddUint16(extensionStatusRequest)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint8(statusTypeOCSP)
						b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddBytes(certificate.OCSPStaple)
						})
					})
				}
				if certificate.SignedCertificateTimestamps != nil {
					b.AddUint16(extensionSCT)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
							for _, sct := range certificate.SignedCertificateTimestamps {
								b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
									b.AddBytes(sct)
								})
							}
						})
					})
				}
			})
		}
	})
}

func (m *certificateMsgTLS13) unmarshal(data []byte) bool {
	*m = certificateMsgTLS13{raw: data}
	s := cryptobyte.String(data)

	var context cryptobyte.String
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint8LengthPrefixed(&context) || !context.Empty() ||
		!unmarshalCertificate(&s, &m.certificate) ||
		!s.Empty() {
		return false
	}

	m.scts = m.certificate.SignedCertificateTimestamps != nil
	m.ocspStapling = m.certificate.OCSPStaple != nil

	return true
}

func unmarshalCertificate(s *cryptobyte.String, certificate *tls.Certificate) bool {
	var certList cryptobyte.String
	if !s.ReadUint24LengthPrefixed(&certList) {
		return false
	}
	for !certList.Empty() {
		var cert []byte
		var extensions cryptobyte.String
		if !readUint24LengthPrefixed(&certList, &cert) ||
			!certList.ReadUint16LengthPrefixed(&extensions) {
			return false
		}
		certificate.Certificate = append(certificate.Certificate, cert)
		for !extensions.Empty() {
			var extension uint16
			var extData cryptobyte.String
			if !extensions.ReadUint16(&extension) ||
				!extensions.ReadUint16LengthPrefixed(&extData) {
				return false
			}
			if len(certificate.Certificate) > 1 {
				// This library only supports OCSP and SCT for leaf certificates.
				continue
			}

			switch extension {
			case extensionStatusRequest:
				var statusType uint8
				if !extData.ReadUint8(&statusType) || statusType != statusTypeOCSP ||
					!readUint24LengthPrefixed(&extData, &certificate.OCSPStaple) ||
					len(certificate.OCSPStaple) == 0 {
					return false
				}
			case extensionSCT:
				var sctList cryptobyte.String
				if !extData.ReadUint16LengthPrefixed(&sctList) || sctList.Empty() {
					return false
				}
				for !sctList.Empty() {
					var sct []byte
					if !readUint16LengthPrefixed(&sctList, &sct) ||
						len(sct) == 0 {
						return false
					}
					certificate.SignedCertificateTimestamps = append(
						certificate.SignedCertificateTimestamps, sct)
				}
			default:
				// Ignore unknown extensions.
				continue
			}

			if !extData.Empty() {
				return false
			}
		}
	}
	return true
}

type serverKeyExchangeMsg struct {
	raw []byte
	key []byte
}

func (m *serverKeyExchangeMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}
	length := len(m.key)
	x := make([]byte, length+4)
	x[0] = typeServerKeyExchange
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	copy(x[4:], m.key)

	m.raw = x
	return x
}

func (m *serverKeyExchangeMsg) unmarshal(data []byte) bool {
	m.raw = data
	if len(data) < 4 {
		return false
	}
	m.key = data[4:]
	return true
}

type certificateStatusMsg struct {
	raw      []byte
	response []byte
}

func (m *certificateStatusMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	var b cryptobyte.Builder
	b.AddUint8(typeCertificateStatus)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(statusTypeOCSP)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.response)
		})
	})

	m.raw = b.BytesOrPanic()
	return m.raw
}

func (m *certificateStatusMsg) unmarshal(data []byte) bool {
	m.raw = data
	s := cryptobyte.String(data)

	var statusType uint8
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint8(&statusType) || statusType != statusTypeOCSP ||
		!readUint24LengthPrefixed(&s, &m.response) ||
		len(m.response) == 0 || !s.Empty() {
		return false
	}
	return true
}

type serverHelloDoneMsg struct{}

func (m *serverHelloDoneMsg) marshal() []byte {
	x := make([]byte, 4)
	x[0] = typeServerHelloDone
	return x
}

func (m *serverHelloDoneMsg) unmarshal(data []byte) bool {
	return len(data) == 4
}

type clientKeyExchangeMsg struct {
	raw        []byte
	ciphertext []byte
}

func (m *clientKeyExchangeMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}
	length := len(m.ciphertext)
	x := make([]byte, length+4)
	x[0] = typeClientKeyExchange
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	copy(x[4:], m.ciphertext)

	m.raw = x
	return x
}

func (m *clientKeyExchangeMsg) unmarshal(data []byte) bool {
	m.raw = data
	if len(data) < 4 {
		return false
	}
	l := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if l != len(data)-4 {
		return false
	}
	m.ciphertext = data[4:]
	return true
}

type finishedMsg struct {
	raw        []byte
	verifyData []byte
}

func (m *finishedMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	var b cryptobyte.Builder
	b.AddUint8(typeFinished)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(m.verifyData)
	})

	m.raw = b.BytesOrPanic()
	return m.raw
}

func (m *finishedMsg) unmarshal(data []byte) bool {
	m.raw = data
	s := cryptobyte.String(data)
	return s.Skip(1) &&
		readUint24LengthPrefixed(&s, &m.verifyData) &&
		s.Empty()
}

type certificateRequestMsg struct {
	raw []byte
	// hasSignatureAlgorithm indicates whether this message includes a list of
	// supported signature algorithms. This change was introduced with TLS 1.2.
	hasSignatureAlgorithm bool

	certificateTypes             []byte
	supportedSignatureAlgorithms []tls.SignatureScheme
	certificateAuthorities       [][]byte
}

func (m *certificateRequestMsg) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	// See RFC 4346, Section 7.4.4.
	length := 1 + len(m.certificateTypes) + 2
	casLength := 0
	for _, ca := range m.certificateAuthorities {
		casLength += 2 + len(ca)
	}
	length += casLength

	if m.hasSignatureAlgorithm {
		length += 2 + 2*len(m.supportedSignatureAlgorithms)
	}

	x = make([]byte, 4+length)
	x[0] = typeCertificateRequest
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)

	x[4] = uint8(len(m.certificateTypes))

	copy(x[5:], m.certificateTypes)
	y := x[5+len(m.certificateTypes):]

	if m.hasSignatureAlgorithm {
		n := len(m.supportedSignatureAlgorithms) * 2
		y[0] = uint8(n >> 8)
		y[1] = uint8(n)
		y = y[2:]
		for _, sigAlgo := range m.supportedSignatureAlgorithms {
			y[0] = uint8(sigAlgo >> 8)
			y[1] = uint8(sigAlgo)
			y = y[2:]
		}
	}

	y[0] = uint8(casLength >> 8)
	y[1] = uint8(casLength)
	y = y[2:]
	for _, ca := range m.certificateAuthorities {
		y[0] = uint8(len(ca) >> 8)
		y[1] = uint8(len(ca))
		y = y[2:]
		copy(y, ca)
		y = y[len(ca):]
	}

	m.raw = x
	return
}

func (m *certificateRequestMsg) unmarshal(data []byte) bool {
	m.raw = data

	if len(data) < 5 {
		return false
	}

	length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if uint32(len(data))-4 != length {
		return false
	}

	numCertTypes := int(data[4])
	data = data[5:]
	if numCertTypes == 0 || len(data) <= numCertTypes {
		return false
	}

	m.certificateTypes = make([]byte, numCertTypes)
	if copy(m.certificateTypes, data) != numCertTypes {
		return false
	}

	data = data[numCertTypes:]

	if m.hasSignatureAlgorithm {
		if len(data) < 2 {
			return false
		}
		sigAndHashLen := uint16(data[0])<<8 | uint16(data[1])
		data = data[2:]
		if sigAndHashLen&1 != 0 {
			return false
		}
		if len(data) < int(sigAndHashLen) {
			return false
		}
		numSigAlgos := sigAndHashLen / 2
		m.supportedSignatureAlgorithms = make([]tls.SignatureScheme, numSigAlgos)
		for i := range m.supportedSignatureAlgorithms {
			m.supportedSignatureAlgorithms[i] = tls.SignatureScheme(data[0])<<8 | tls.SignatureScheme(data[1])
			data = data[2:]
		}
	}

	if len(data) < 2 {
		return false
	}
	casLength := uint16(data[0])<<8 | uint16(data[1])
	data = data[2:]
	if len(data) < int(casLength) {
		return false
	}
	cas := make([]byte, casLength)
	copy(cas, data)
	data = data[casLength:]

	m.certificateAuthorities = nil
	for len(cas) > 0 {
		if len(cas) < 2 {
			return false
		}
		caLen := uint16(cas[0])<<8 | uint16(cas[1])
		cas = cas[2:]

		if len(cas) < int(caLen) {
			return false
		}

		m.certificateAuthorities = append(m.certificateAuthorities, cas[:caLen])
		cas = cas[caLen:]
	}

	return len(data) == 0
}

type certificateVerifyMsg struct {
	raw                   []byte
	hasSignatureAlgorithm bool // format change introduced in TLS 1.2
	signatureAlgorithm    tls.SignatureScheme
	signature             []byte
}

func (m *certificateVerifyMsg) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	var b cryptobyte.Builder
	b.AddUint8(typeCertificateVerify)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		if m.hasSignatureAlgorithm {
			b.AddUint16(uint16(m.signatureAlgorithm))
		}
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.signature)
		})
	})

	m.raw = b.BytesOrPanic()
	return m.raw
}

func (m *certificateVerifyMsg) unmarshal(data []byte) bool {
	m.raw = data
	s := cryptobyte.String(data)

	if !s.Skip(4) { // message type and uint24 length field
		return false
	}
	if m.hasSignatureAlgorithm {
		if !s.ReadUint16((*uint16)(&m.signatureAlgorithm)) {
			return false
		}
	}
	return readUint16LengthPrefixed(&s, &m.signature) && s.Empty()
}

type newSessionTicketMsg struct {
	raw    []byte
	ticket []byte
}

func (m *newSessionTicketMsg) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	// See RFC 5077, Section 3.3.
	ticketLen := len(m.ticket)
	length := 2 + 4 + ticketLen
	x = make([]byte, 4+length)
	x[0] = typeNewSessionTicket
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	x[8] = uint8(ticketLen >> 8)
	x[9] = uint8(ticketLen)
	copy(x[10:], m.ticket)

	m.raw = x

	return
}

func (m *newSessionTicketMsg) unmarshal(data []byte) bool {
	m.raw = data

	if len(data) < 10 {
		return false
	}

	length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if uint32(len(data))-4 != length {
		return false
	}

	ticketLen := int(data[8])<<8 + int(data[9])
	if len(data)-10 != ticketLen {
		return false
	}

	m.ticket = data[10:]

	return true
}

type helloRequestMsg struct {
}

func (*helloRequestMsg) marshal() []byte {
	return []byte{typeHelloRequest, 0, 0, 0}
}

func (*helloRequestMsg) unmarshal(data []byte) bool {
	return len(data) == 4
}

// TLS 1.3 Key Share. See RFC 8446, Section 4.2.8.
type keyShare struct {
	group tls.CurveID
	data  []byte
}

// TLS 1.3 PSK Identity. Can be a Session Ticket, or a reference to a saved
// session. See RFC 8446, Section 4.2.11.
type pskIdentity struct {
	label               []byte
	obfuscatedTicketAge uint32
}
