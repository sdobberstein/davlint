// Package webdav provides shared WebDAV discovery helpers for davlint test suites.
// These helpers navigate the standard CardDAV discovery chain defined by
// RFC 6764 (well-known) and RFC 6352 (addressbook-home-set) without assuming
// any server-specific URL structure.
package webdav

import (
	"context"
	"fmt"

	"github.com/sdobberstein/davlint/pkg/assert"
	"github.com/sdobberstein/davlint/pkg/client"
)

// CurrentUserPrincipalURL issues a depth-0 PROPFIND on contextPath and returns
// the DAV:href value of the DAV:current-user-principal property.
func CurrentUserPrincipalURL(ctx context.Context, c *client.Client, contextPath string) (string, error) {
	body := client.PropfindProps([][2]string{
		{client.NSdav, "current-user-principal"},
	})
	resp, err := c.Propfind(ctx, contextPath, "0", body)
	if err != nil {
		return "", fmt.Errorf("current-user-principal lookup: %w", err)
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return "", fmt.Errorf("current-user-principal lookup: %w", err)
	}
	ms, err := client.ParseMultistatus(resp.Body)
	if err != nil {
		return "", fmt.Errorf("current-user-principal lookup: %w", err)
	}
	href, err := assert.PropHrefValue(ms, contextPath, client.NSdav, "current-user-principal")
	if err != nil {
		return "", fmt.Errorf("current-user-principal lookup: %w", err)
	}
	return href, nil
}

// AddressbookHomeSetURL issues a depth-0 PROPFIND on principalURL and returns
// the DAV:href value of the carddav:addressbook-home-set property.
func AddressbookHomeSetURL(ctx context.Context, c *client.Client, principalURL string) (string, error) {
	body := client.PropfindProps([][2]string{
		{client.NScarddav, "addressbook-home-set"},
	})
	resp, err := c.Propfind(ctx, principalURL, "0", body)
	if err != nil {
		return "", fmt.Errorf("addressbook-home-set lookup: %w", err)
	}
	if err := assert.StatusCode(resp, 207); err != nil {
		return "", fmt.Errorf("addressbook-home-set lookup: %w", err)
	}
	ms, err := client.ParseMultistatus(resp.Body)
	if err != nil {
		return "", fmt.Errorf("addressbook-home-set lookup: %w", err)
	}
	href, err := assert.PropHrefValue(ms, principalURL, client.NScarddav, "addressbook-home-set")
	if err != nil {
		return "", fmt.Errorf("addressbook-home-set lookup: %w", err)
	}
	return href, nil
}
