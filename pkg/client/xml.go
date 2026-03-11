package client

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"
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
	// SyncToken is present in DAV:sync-collection REPORT responses (RFC 6578 §3.2).
	SyncToken string `xml:"sync-token"`
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

// xmlEscape returns s with XML special characters escaped.
func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s)) //nolint:errcheck // strings.Builder.Write never fails
	return b.String()
}

// propElem returns the XML self-closing element for a single property in the
// DAV or CardDAV namespace. Used when building REPORT request bodies.
func propElem(ns, local string) string {
	switch ns {
	case NSdav:
		return fmt.Sprintf("<D:%s/>", local)
	case NScarddav:
		return fmt.Sprintf("<C:%s/>", local)
	default:
		return fmt.Sprintf("<ns0:%s xmlns:ns0=%q/>", local, ns)
	}
}

// ReportAddressbookQuery returns a CardDAV addressbook-query REPORT body (RFC 6352 §8.6).
// props is the list of [namespace, localname] pairs to request per matching resource.
// filter is an optional raw XML fragment for the C:filter element; nil means no filter
// (the server MUST return all address objects in the collection).
func ReportAddressbookQuery(props [][2]string, filter []byte) []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?>`)
	b.WriteString(`<C:addressbook-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">`)
	b.WriteString(`<D:prop>`)
	for _, p := range props {
		b.WriteString(propElem(p[0], p[1]))
	}
	b.WriteString(`</D:prop>`)
	if len(filter) > 0 {
		b.WriteString(`<C:filter>`)
		_, _ = b.Write(filter) //nolint:errcheck // strings.Builder.Write never fails
		b.WriteString(`</C:filter>`)
	}
	b.WriteString(`</C:addressbook-query>`)
	return []byte(b.String())
}

// ReportAddressbookQueryPropFilter returns a C:prop-filter XML fragment that
// applies a text-match to the named vCard property (RFC 6352 §8.6.4).
// The default collation (i;ascii-casemap) and match-type (contains) apply.
// Pass the result as the filter argument to ReportAddressbookQuery.
func ReportAddressbookQueryPropFilter(propName, textMatch string) []byte {
	return []byte(fmt.Sprintf(
		`<C:prop-filter name=%q><C:text-match>%s</C:text-match></C:prop-filter>`,
		propName, xmlEscape(textMatch),
	))
}

// ReportAddressbookQueryPropFilterCollation returns a C:prop-filter XML
// fragment with an explicit collation attribute on C:text-match (RFC 6352 §8.3,
// §8.6.4). Use this to test collation-specific query behaviour.
// Pass the result as the filter argument to ReportAddressbookQuery.
func ReportAddressbookQueryPropFilterCollation(propName, textMatch, collation string) []byte {
	return []byte(fmt.Sprintf(
		`<C:prop-filter name=%q><C:text-match collation=%q>%s</C:text-match></C:prop-filter>`,
		propName, collation, xmlEscape(textMatch),
	))
}

// ReportAddressbookQueryParamFilter returns a C:prop-filter XML fragment that
// restricts results by matching a specific parameter of a vCard property
// (RFC 6352 §8.6.4). paramMatch is matched against the parameter value using
// the default collation (i;ascii-casemap, contains).
// Pass the result as the filter argument to ReportAddressbookQuery.
func ReportAddressbookQueryParamFilter(propName, paramName, paramMatch string) []byte {
	return []byte(fmt.Sprintf(
		`<C:prop-filter name=%q><C:param-filter name=%q><C:text-match>%s</C:text-match></C:param-filter></C:prop-filter>`,
		propName, paramName, xmlEscape(paramMatch),
	))
}

// ReportAddressbookMultiget returns a CardDAV addressbook-multiget REPORT body (RFC 6352 §8.7).
// props is the list of [namespace, localname] pairs to request per resource;
// hrefs is the list of absolute-path resource URLs to retrieve.
func ReportAddressbookMultiget(props [][2]string, hrefs []string) []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?>`)
	b.WriteString(`<C:addressbook-multiget xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">`)
	b.WriteString(`<D:prop>`)
	for _, p := range props {
		b.WriteString(propElem(p[0], p[1]))
	}
	b.WriteString(`</D:prop>`)
	for _, href := range hrefs {
		fmt.Fprintf(&b, "<D:href>%s</D:href>", xmlEscape(href))
	}
	b.WriteString(`</C:addressbook-multiget>`)
	return []byte(b.String())
}

// ReportSyncCollection returns a DAV:sync-collection REPORT body (RFC 6578 §3.2).
// syncToken is the token from a previous response; pass "" for the initial sync.
// syncLevel is "1" (one-level) or "infinite"; CardDAV servers only require "1".
// props is the list of [namespace, localname] pairs to request per changed resource.
func ReportSyncCollection(syncToken, syncLevel string, props [][2]string) []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?>`)
	b.WriteString(`<D:sync-collection xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">`)
	fmt.Fprintf(&b, "<D:sync-token>%s</D:sync-token>", xmlEscape(syncToken))
	fmt.Fprintf(&b, "<D:sync-level>%s</D:sync-level>", xmlEscape(syncLevel))
	b.WriteString(`<D:prop>`)
	for _, p := range props {
		b.WriteString(propElem(p[0], p[1]))
	}
	b.WriteString(`</D:prop>`)
	b.WriteString(`</D:sync-collection>`)
	return []byte(b.String())
}

// ReportSyncCollectionWithLimit returns a DAV:sync-collection REPORT body that
// includes a DAV:limit/DAV:nresults element (RFC 6578 §3.7).
// nResults is the maximum number of member entries the client wants returned.
func ReportSyncCollectionWithLimit(syncToken, syncLevel string, nResults int, props [][2]string) []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?>`)
	b.WriteString(`<D:sync-collection xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">`)
	fmt.Fprintf(&b, "<D:sync-token>%s</D:sync-token>", xmlEscape(syncToken))
	fmt.Fprintf(&b, "<D:sync-level>%s</D:sync-level>", xmlEscape(syncLevel))
	fmt.Fprintf(&b, "<D:limit><D:nresults>%d</D:nresults></D:limit>", nResults)
	b.WriteString(`<D:prop>`)
	for _, p := range props {
		b.WriteString(propElem(p[0], p[1]))
	}
	b.WriteString(`</D:prop>`)
	b.WriteString(`</D:sync-collection>`)
	return []byte(b.String())
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
