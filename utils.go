package epicserver

import (
	"crypto/rand"
	"encoding/hex"
	"net/url"
)

// String utils
func GenerateToken(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

type QueryParam map[string][]string

// Url utils
func BuildQueryParams(baseUrl string, queryParams QueryParam) string {
	base, _ := url.Parse(baseUrl)

	params := url.Values{}
	for idx, strArray := range queryParams {
		for _, str := range strArray {
			params.Add(idx, str)
		}
	}

	base.RawQuery = params.Encode()
	return base.String()
}
