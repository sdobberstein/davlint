package client

import (
	"bytes"
	"encoding/xml"
	"fmt"
)

// WebDAV XML namespace URIs.
const (
	NSdav     = "DAV:"
	NScarddav = "urn:ietf:params:xml:ns:carddav"
)

// Multistatus is the top-level element of a 207 Multi-Status response (RFC 4918 §13.4.2).
type Multistatus struct {
	XMLName   xml.Name     `xml:"DAV: multistatus"`
	Responses []MSResponse `xml:"response"`
}

// MSResponse is a single resource entry in a Multistatus body.
type MSResponse struct {
	Href     string     `xml:"href"`
	PropStat []PropStat `xml:"propstat"`
	Status   string     `xml:"status"`
}

// PropStat groups properties that share an HTTP status (RFC 4918 §14.22).
type PropStat struct {
	Prop   RawProp `xml:"prop"`
	Status string  `xml:"status"`
}

// RawProp preserves the inner XML of a <prop> element for flexible inspection.
type RawProp struct {
	Inner []byte `xml:",innerxml"`
}

// ParseMultistatus unmarshals the body of a 207 Multi-Status response.
func ParseMultistatus(body []byte) (*Multistatus, error) {
	var ms Multistatus
	if err := xml.Unmarshal(body, &ms); err != nil {
		return nil, fmt.Errorf("unmarshal multistatus: %w", err)
	}
	return &ms, nil
}

// PropInnerXML checks whether a raw <prop> inner XML fragment contains an
// element with the given namespace and local name.
func PropInnerXML(inner []byte, ns, local string) bool {
	// Wrap with namespace declarations so the decoder resolves prefixes correctly.
	wrapped := append(
		[]byte(`<prop xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">`),
		inner...,
	)
	wrapped = append(wrapped, []byte("</prop>")...)

	dec := xml.NewDecoder(bytes.NewReader(wrapped))
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		if se, ok := tok.(xml.StartElement); ok {
			if se.Name.Space == ns && se.Name.Local == local {
				return true
			}
		}
	}
	return false
}

// PropfindAllprop returns a PROPFIND body requesting all live properties.
func PropfindAllprop() []byte {
	return []byte(xml.Header +
		`<D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>`)
}

// PropfindProps returns a PROPFIND body requesting the named properties.
// props is a slice of [namespace, localname] pairs.
func PropfindProps(props [][2]string) []byte {
	type innerProp struct {
		XMLName xml.Name
	}
	type propEl struct {
		XMLName xml.Name    `xml:"DAV: prop"`
		Props   []innerProp
	}
	type propFind struct {
		XMLName xml.Name `xml:"DAV: propfind"`
		Prop    propEl
	}

	pf := propFind{}
	for _, p := range props {
		pf.Prop.Props = append(pf.Prop.Props, innerProp{
			XMLName: xml.Name{Space: p[0], Local: p[1]},
		})
	}
	out, err := xml.Marshal(pf)
	if err != nil {
		// Marshal of a static well-formed struct never fails.
		panic(fmt.Sprintf("davlint: PropfindProps marshal: %v", err))
	}
	return append([]byte(xml.Header), out...)
}
